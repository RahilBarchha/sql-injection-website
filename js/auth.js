// AICTE Cybersecurity Portal - Authentication Controller
// ⚠️  CEH MODULE 15 LAB: SQL INJECTION TRAINING VERSION ⚠️
// This build is intentionally vulnerable for hands-on CEH lab exercises.
// DO NOT use in production.

function recordAuditLog(logEntry) {
  const STORAGE_KEY = "aicte_dcim_audit_logs";
  let logs = [];
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (raw) logs = JSON.parse(raw);
  } catch (e) {
    logs = [];
  }
  if (!Array.isArray(logs)) logs = [];
  logs.unshift(logEntry);
  if (logs.length > 200) logs = logs.slice(0, 200);
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(logs));
  } catch (e) {
    console.error("Failed to save audit log to localStorage", e);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
//  CEH LAB: SQL INJECTION SUCCESS SCREEN
//  Replaces the whole page with a single confirmation message when an
//  injection bypasses the login. No dashboard / infrastructure data is shown.
// ─────────────────────────────────────────────────────────────────────────────
function showInjectionThankYou() {
  document.documentElement.innerHTML = `
    <head>
      <meta charset="UTF-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1.0" />
      <title>Thank you for visiting our website</title>
      <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
          min-height: 100vh;
          display: flex;
          align-items: center;
          justify-content: center;
          background: radial-gradient(1200px 600px at 50% -10%, #12203a 0%, #0a0f1c 55%, #060910 100%);
          color: #e8eefc;
          font-family: "Plus Jakarta Sans", system-ui, -apple-system, Segoe UI, sans-serif;
          text-align: center;
          padding: 24px;
        }
        .ty-message {
          font-size: clamp(1.6rem, 5vw, 3rem);
          font-weight: 700;
          letter-spacing: 0.5px;
          line-height: 1.3;
          background: linear-gradient(90deg, #6ee7ff, #8b9bff 55%, #c77dff);
          -webkit-background-clip: text;
          background-clip: text;
          color: transparent;
        }
      </style>
    </head>
    <body>
      <h1 class="ty-message">Thank you for visiting our website</h1>
    </body>`;
  try { document.title = "Thank you for visiting our website"; } catch (e) {}
}

// ─────────────────────────────────────────────────────────────────────────────
//  CEH LAB: SIMULATED SQL USER TABLE
//  In a real server this would be a database table.
//  Here we keep it in-memory so the injection demo works client-side.
// ─────────────────────────────────────────────────────────────────────────────
const SQL_USERS_TABLE = [
  { id: 1, username: "superadmin",  password: "Super@88", role: "Super Admin",      name: "System Super Admin" },
  { id: 2, username: "admin",       password: "Admin@88", role: "Admin",            name: "System Admin"       },
  { id: 3, username: "itoperator",  password: "ITOps@88", role: "IT Operator",      name: "IT Operations Lead" },
  { id: 4, username: "netengineer", password: "NetEng88", role: "Network Engineer", name: "Network Engineer"   },
  { id: 5, username: "auditor",     password: "Audit@88", role: "Auditor",          name: "Compliance Auditor" }
];

/**
 * ─────────────────────────────────────────────────────────────────────────────
 *  CEH LAB: VULNERABLE SQL LOGIN SIMULATION
 *
 *  A real vulnerable PHP/Node backend would run:
 *    SELECT * FROM users
 *    WHERE username = '<INPUT>' AND password = '<INPUT>'
 *
 *  Because inputs are NOT sanitised or parameterised, an attacker can inject
 *  SQL logic that changes the query's meaning.
 *
 *  This function simulates that behaviour entirely in JavaScript so you can
 *  practise SQL injection attacks without needing a backend server.
 * ─────────────────────────────────────────────────────────────────────────────
 */
function simulateVulnerableSQLLogin(rawUsername, rawPassword) {
  // ── Step 1: Build the query string EXACTLY as a vulnerable backend would ──
  const query = `SELECT * FROM users WHERE username='${rawUsername}' AND password='${rawPassword}'`;

  // Update the SQL console panel
  updateSQLConsole(query, rawUsername, rawPassword);

  // ── Step 2: Detect SQL injection patterns ────────────────────────────────
  //
  //  Pattern A — comment injection in username:
  //    admin'--   →  WHERE username='admin'--' AND password='...'
  //    The -- comments out the password check; auth is skipped.
  //
  //  Pattern B — OR injection in username:
  //    ' OR '1'='1'--  →  WHERE username='' OR '1'='1'--' AND password='...'
  //    Always evaluates to TRUE; first row is returned.
  //
  //  Pattern C — OR injection in password:
  //    anything' OR '1'='1  →  WHERE username='admin' AND password='anything' OR '1'='1'
  //    Last OR condition is always TRUE.

  // Check for SQL comment sequences that terminate the query early
  const commentInUsername = /['"`]\s*(--|#|\/\*)/i.test(rawUsername);

  // Check for OR-based tautologies in either field
  const orTautologyPattern = /'\s*or\s+(['"]?)1\1\s*=\s*\1?1\1?/i;
  const orStringPattern    = /'\s*or\s*'[^']*'\s*=\s*'[^']*'/i;
  const orAltPattern       = /'\s*or\s+[a-z_]+\s*=\s*[a-z_]+/i;  // ' OR a=a
  const doubleOrPattern    = /or\s+1\s*=\s*1/i;                   // OR 1=1 without quotes

  const isInjected =
    commentInUsername ||
    orTautologyPattern.test(rawUsername) ||
    orTautologyPattern.test(rawPassword) ||
    orStringPattern.test(rawUsername)    ||
    orStringPattern.test(rawPassword)    ||
    orAltPattern.test(rawUsername)       ||
    orAltPattern.test(rawPassword)       ||
    doubleOrPattern.test(rawUsername)    ||
    doubleOrPattern.test(rawPassword);

  if (isInjected) {
    // ── Injection successful: return the first user row (like SQL LIMIT 1) ──
    const firstUser = SQL_USERS_TABLE[0];
    return {
      success: true,
      injected: true,
      user: { ...firstUser },
      query
    };
  }

  // ── Step 3: Normal authentication (no injection detected) ─────────────────
  const matched = SQL_USERS_TABLE.find(
    u => u.username === rawUsername && u.password === rawPassword
  );

  return {
    success: !!matched,
    injected: false,
    user: matched ? { ...matched } : null,
    query
  };
}

// ─────────────────────────────────────────────────────────────────────────────
//  SQL CONSOLE UI — updates the live query panel in real-time
// ─────────────────────────────────────────────────────────────────────────────
function updateSQLConsole(query, username, password) {
  const queryEl   = document.getElementById("sqlQueryText");
  const statusEl  = document.getElementById("sqlStatus");
  const noteEl    = document.getElementById("sqlInjectionNote");
  if (!queryEl) return;

  // Syntax-highlight the query: colour injected characters red
  const safe = (s) => s.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
  const normalPart = `<span class="sql-keyword">SELECT</span> * <span class="sql-keyword">FROM</span> users <span class="sql-keyword">WHERE</span> username=<span class="sql-string">'`;
  const closeNorm  = `'</span> <span class="sql-keyword">AND</span> password=<span class="sql-string">'`;

  // Mark injected characters in the input as red
  const highlightInput = (val) => {
    const injChars = /['";#\-]|or|and/gi;
    return safe(val).replace(injChars, m => `<span class="sql-injected">${m}</span>`);
  };

  queryEl.innerHTML =
    normalPart +
    highlightInput(username) +
    closeNorm +
    highlightInput(password) +
    `'</span>`;

  // Determine if injection is happening right now (live)
  const commentInUsername = /['"`]\s*(--|#|\/\*)/i.test(username);
  const orTautology = /'\s*or\s+/i.test(username) || /'\s*or\s+/i.test(password) ||
                      /or\s+1\s*=\s*1/i.test(username) || /or\s+1\s*=\s*1/i.test(password);
  const isLiveInjection = commentInUsername || orTautology;

  if (statusEl) {
    if (isLiveInjection) {
      statusEl.textContent  = "⚡ INJECTION DETECTED — query logic has been altered!";
      statusEl.className    = "sql-status injecting";
    } else if (username || password) {
      statusEl.textContent  = "⏳ Query built — no injection detected yet.";
      statusEl.className    = "sql-status normal";
    } else {
      statusEl.textContent  = "💡 Type credentials above to see the SQL query.";
      statusEl.className    = "sql-status idle";
    }
  }

  if (noteEl) {
    noteEl.style.display = isLiveInjection ? "block" : "none";
  }
}

// ─────────────────────────────────────────────────────────────────────────────
//  MAIN DOM-READY CONTROLLER
// ─────────────────────────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
  const loginForm     = document.getElementById("loginForm");
  const authAlert     = document.getElementById("authAlert");

  // ── Alert helper ──────────────────────────────────────────────────────────
  function showAlert(message, type = "danger", autoHide = true) {
    if (!authAlert) return;
    authAlert.className   = `auth-alert ${type}`;
    authAlert.textContent = message;
    authAlert.style.display = "block";
    if (autoHide && type !== "danger") {
      setTimeout(() => { authAlert.style.display = "none"; }, 5000);
    }
  }
  function hideAlert() {
    if (authAlert) authAlert.style.display = "none";
  }

  // ── Password visibility toggles ───────────────────────────────────────────
  function setupPasswordToggle(btnId, inputId) {
    const btn   = document.getElementById(btnId);
    const input = document.getElementById(inputId);
    if (!btn || !input) return;
    btn.addEventListener("click", () => {
      input.type = (input.type === "password") ? "text" : "password";
      btn.textContent = (input.type === "password") ? "👁️" : "🙈";
    });
  }
  setupPasswordToggle("toggleLoginPassword",       "password");

  const usernameInput = document.getElementById("username");
  const passwordInput = document.getElementById("password");

  // ── API base (kept for completeness; not used in lab mode) ───────────────
  const AUTH_API_BASE = (window.location.origin.includes(':5000'))
    ? 'http://localhost:5000/api'
    : (window.location.protocol === 'file:'
        ? 'http://localhost:5000/api'
        : (window.location.origin + '/api'));

  // ─────────────────────────────────────────────────────────────────────────
  //  LOGIN HANDLER — Uses vulnerable SQL simulation as primary path
  // ─────────────────────────────────────────────────────────────────────────
  if (loginForm) {
    loginForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      hideAlert();

      const user = usernameInput ? usernameInput.value : "";
      const pass = passwordInput ? passwordInput.value : "";

      const loginBtn = document.getElementById("loginBtn");
      if (loginBtn) loginBtn.disabled = true;

      // ── Try backend API first (if running) ──────────────────────────────
      try {
        const response = await fetch(`${AUTH_API_BASE}/auth/login`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username: user, password: pass }),
          signal: AbortSignal.timeout(3000)
        });
        const data = await response.json();
        if (response.ok && data.success) {
          sessionStorage.setItem("loggedIn",  "true");
          sessionStorage.setItem("token",     data.token);
          sessionStorage.setItem("username",  data.user.username);
          sessionStorage.setItem("name",      data.user.name);
          sessionStorage.setItem("role",      data.user.role);
          window.location.href = "dashboard.html";
          return;
        }
        // Backend rejected credentials — fall through to SQL simulation
      } catch (_) {
        // Backend unavailable — fall through to SQL simulation
      }

      // ── ⚠️  CEH LAB: Vulnerable SQL simulation (no backend needed) ──────
      const result = simulateVulnerableSQLLogin(user, pass);

      if (result.success) {
        const account = result.user;

        // ── ⚠️  CEH LAB: SQL injection succeeded ────────────────────────────
        //  Instead of exposing the DCIM dashboard, the lab now shows a single
        //  confirmation message so the exercise ends on the "access gained"
        //  proof without revealing any infrastructure data.
        if (result.injected) {
          showInjectionThankYou();
          return;
        }

        // ── Legitimate credential login → normal dashboard ──────────────────
        sessionStorage.setItem("loggedIn",  "true");
        sessionStorage.setItem("username",  account.username);
        sessionStorage.setItem("name",      account.name);
        sessionStorage.setItem("role",      account.role);
        window.location.href = "dashboard.html";
      } else {
        showAlert("Invalid username or password. Please verify credentials.", "danger");
        if (loginBtn) loginBtn.disabled = false;
      }
    });
  }
});
