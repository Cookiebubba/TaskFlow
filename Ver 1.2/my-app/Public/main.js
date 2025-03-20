document.addEventListener("DOMContentLoaded", () => {
  checkAuth();
  loadAlerts();
});

// Function to check if user is logged in
async function checkAuth() {
  try {
    const response = await fetch("/api/user");
    if (!response.ok) {
      window.location.href = "login.html";
      return;
    }
    const data = await response.json();
    document.getElementById("usernameDisplay").innerText = `👤 ${data.user.username}`;
  } catch (err) {
    console.error("Authentication error:", err);
    window.location.href = "login.html";
  }
}

// Function to fetch alerts from the server and update the alerts dropdown
async function loadAlerts() {
  try {
    const response = await fetch("/api/alerts");
    if (!response.ok) {
      console.error("Failed to fetch alerts.");
      return;
    }

    const alerts = await response.json();
    const alertsDropdown = document.getElementById("alertsDropdown");
    alertsDropdown.innerHTML = "";

    if (alerts.length === 0) {
      alertsDropdown.innerHTML = "<p class='no-alerts'>No new alerts</p>";
      return;
    }

    alerts.forEach(alert => {
      const alertItem = document.createElement("div");
      alertItem.classList.add("alert-item");
      alertItem.innerHTML = `
        <p>${alert.message}</p>
        ${alert.type === "job_board_invite" ? `<button onclick="acceptJobBoardInvite(${alert.related_id}, ${alert.id})">Accept</button>` : ""}
        ${alert.type === "task_due_soon" ? `<button onclick="viewTask(${alert.related_id})">View Task</button>` : ""}
        <button onclick="markAlertRead(${alert.id})">Dismiss</button>
      `;
      alertsDropdown.appendChild(alertItem);
    });
  } catch (err) {
    console.error("Error fetching alerts:", err);
  }
}

// Function to accept job board invite
async function acceptJobBoardInvite(boardId, alertId) {
  try {
    const response = await fetch(`/api/job-board/${boardId}/accept`, { method: "POST" });
    if (response.ok) {
      alert("Joined job board successfully!");
      markAlertRead(alertId);
      window.location.reload();
    } else {
      alert("Failed to accept invite.");
    }
  } catch (err) {
    console.error("Error accepting job board invite:", err);
  }
}

// Function to view task details
function viewTask(taskId) {
  window.location.href = `task-details.html?id=${taskId}`;
}

// Function to mark an alert as read
async function markAlertRead(alertId) {
  try {
    await fetch("/api/alerts/mark-read", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ alertId })
    });
    loadAlerts();
  } catch (err) {
    console.error("Error marking alert as read:", err);
  }
}

// Function to toggle the alerts dropdown visibility
document.getElementById("alertsBtn").addEventListener("click", () => {
  const dropdown = document.getElementById("alertsDropdown");
  dropdown.classList.toggle("show");
});

// Function to log out the user
async function logout() {
  try {
    const response = await fetch("/api/logout", { method: "POST" });
    if (response.ok) {
      window.location.href = "login.html";
    }
  } catch (err) {
    console.error("Logout error:", err);
  }
}
