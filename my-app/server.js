const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const path = require("path");
const bcrypt = require("bcrypt");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);

const app = express();
const PORT = process.env.PORT || 3000;

const SESSION_SECRET = process.env.SESSION_SECRET || "fallback-dev-secret";

app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: new SQLiteStore({ db: "sessions.db", dir: "./" }),
  cookie: { maxAge: 1000 * 60 * 60 }
}));

app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "login.html"));
});

const db = new sqlite3.Database("database.db", (err) => {
  if (err) {
    console.error("Database error:", err);
  } else {
    console.log("Connected to SQLite.");
    db.serialize(() => {
      db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        passwordHash TEXT NOT NULL,
        createdAt INTEGER NOT NULL
      )`);

      db.run(`CREATE TABLE IF NOT EXISTS job_boards (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        owner_id INTEGER NOT NULL,
        createdAt INTEGER NOT NULL,
        FOREIGN KEY (owner_id) REFERENCES users(id)
      )`);

      db.run(`CREATE TABLE IF NOT EXISTS job_board_users (
        job_board_id INTEGER,
        user_id INTEGER,
        role TEXT NOT NULL DEFAULT 'Viewer',
        PRIMARY KEY (job_board_id, user_id),
        FOREIGN KEY (job_board_id) REFERENCES job_boards(id),
        FOREIGN KEY (user_id) REFERENCES users(id)
      )`);

      db.run(`CREATE TABLE IF NOT EXISTS tasks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        job_board_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        assigned_to INTEGER,
        status TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        due_date INTEGER,
        FOREIGN KEY (job_board_id) REFERENCES job_boards(id),
        FOREIGN KEY (assigned_to) REFERENCES users(id)
      )`);

      db.run(`CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        type TEXT NOT NULL,
        message TEXT NOT NULL,
        related_id INTEGER,
        created_at INTEGER NOT NULL,
        is_read INTEGER DEFAULT 0,
        FOREIGN KEY (user_id) REFERENCES users(id)
      )`);

      db.run(`CREATE TABLE IF NOT EXISTS task_phases (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        task_id INTEGER NOT NULL,
        phase_name TEXT NOT NULL,
        entered_at INTEGER NOT NULL,
        exited_at INTEGER,
        FOREIGN KEY (task_id) REFERENCES tasks(id)
      )`);

      console.log("All necessary tables created or verified.");
    });
  }
});

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
          req.session.cookie.maxAge = 1000 * 60 * 60 * 24 * 30;
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

app.get("/api/alerts", (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: "Unauthorized" });
  db.all("SELECT * FROM alerts WHERE user_id = ? AND is_read = 0", [req.session.user.id], (err, rows) => {
    if (err) {
      console.error("Failed to fetch alerts:", err.message);
      return res.status(500).json({ error: "Failed to fetch alerts." });
    }
    res.json(rows);
  });
});

app.get("/api/job-boards", (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: "Unauthorized" });
  db.all(`SELECT jb.id, jb.name FROM job_boards jb JOIN job_board_users jbu ON jb.id = jbu.job_board_id WHERE jbu.user_id = ?`, [req.session.user.id], (err, rows) => {
    if (err) {
      console.error("Failed to fetch job boards:", err.message);
      return res.status(500).json({ error: "Failed to fetch job boards." });
    }
    res.json(rows);
  });
});

app.get("/api/job-board/:id", (req, res) => {
  const boardId = req.params.id;
  db.get("SELECT * FROM job_boards WHERE id = ?", [boardId], (err, row) => {
    if (err) {
      console.error("Failed to fetch job board:", err.message);
      return res.status(500).json({ error: "Failed to fetch job board." });
    }
    res.json(row);
  });
});

app.get("/api/job-board/:id/users", (req, res) => {
  const boardId = req.params.id;
  db.all("SELECT u.id, u.username, jbu.role FROM users u JOIN job_board_users jbu ON u.id = jbu.user_id WHERE jbu.job_board_id = ?", [boardId], (err, rows) => {
    if (err) {
      console.error("Failed to fetch users for board:", err.message);
      return res.status(500).json({ error: "Failed to fetch users." });
    }
    res.json(rows);
  });
});

app.get("/api/job-board/:id/sub-boards", (req, res) => {
  const boardId = req.params.id;
  db.all("SELECT DISTINCT phase_name FROM task_phases WHERE task_id IN (SELECT id FROM tasks WHERE job_board_id = ?)", [boardId], (err, rows) => {
    if (err) {
      console.error("Failed to fetch sub-boards:", err.message);
      return res.status(500).json({ error: "Failed to fetch sub-boards." });
    }
    res.json(rows);
  });
});

app.get("/api/task/:id", (req, res) => {
  const taskId = req.params.id;
  db.get("SELECT * FROM tasks WHERE id = ?", [taskId], (err, task) => {
    if (err || !task) {
      return res.status(404).json({ error: "Task not found." });
    }
    db.all("SELECT * FROM task_phases WHERE task_id = ? ORDER BY entered_at ASC", [taskId], (err2, phases) => {
      if (err2) {
        console.error("Failed to fetch task phases:", err2.message);
        return res.status(500).json({ error: "Failed to fetch task phases." });
      }
      task.phases = phases;
      res.json(task);
    });
  });
});

app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
