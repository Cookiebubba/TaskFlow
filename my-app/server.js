const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const path = require("path");
const bcrypt = require("bcrypt");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);

const app = express();
const PORT = process.env.PORT || 3000;

// Use a secure secret from environment or fallback for local dev
const SESSION_SECRET = process.env.SESSION_SECRET || "fallback-dev-secret";

app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: new SQLiteStore({ db: "sessions.db", dir: "./" }),
  cookie: { maxAge: 1000 * 60 * 60 } // 1 hour default
}));

app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "login.html"));
});

// Initialize database
const db = new sqlite3.Database("database.db", (err) => {
  if (err) console.error("Database error:", err);
  else console.log("Connected to SQLite.");
});

// Auth endpoints
app.post("/api/register", (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: "Username and password required." });
  }

  bcrypt.hash(password, 10, (err, hash) => {
    if (err) {
      console.error("Hash error:", err.message);
      return res.status(500).json({ error: "Internal server error." });
    }

    db.run("INSERT INTO users (username, passwordHash, createdAt) VALUES (?, ?, ?)",
      [username, hash, Date.now()],
      function(err) {
        if (err) {
          console.error("Registration error:", err.message);
          if (err.message.includes("UNIQUE")) {
            return res.status(400).json({ error: "Username already exists." });
          }
          return res.status(500).json({ error: "Registration failed." });
        }

        req.session.user = { id: this.lastID, username };
        res.json({ message: "Registration successful", user: req.session.user });
      });
  });
});

app.post("/api/login", (req, res) => {
  const { username, password, stayLoggedIn } = req.body;
  if (!username || !password) return res.status(400).json({ error: "Username and password required." });

  db.get("SELECT * FROM users WHERE username = ?", [username], (err, user) => {
    if (!user) return res.status(400).json({ error: "Invalid credentials." });

    bcrypt.compare(password, user.passwordHash, (err, result) => {
      if (result) {
        req.session.user = { id: user.id, username: user.username };
        if (stayLoggedIn) {
          req.session.cookie.maxAge = 1000 * 60 * 60 * 24 * 30; // 30 days
        }
        res.json({ message: "Login successful", user: req.session.user });
      } else {
        res.status(400).json({ error: "Invalid credentials." });
      }
    });
  });
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => res.json({ message: "Logged out successfully." }));
});

app.get("/api/user", (req, res) => {
  if (req.session.user) res.json({ user: req.session.user });
  else res.status(401).json({ error: "Not authenticated." });
});

app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
