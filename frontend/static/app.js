"use strict";
// RBAC demo SPA. The navbar hides links the user lacks access to, but that is
// only a convenience: every page authorizes again on the server (try visiting
// a page you can't access — the API returns 403 and we show "Access denied").
// All untrusted text is rendered via textContent (never innerHTML).

// User is the base role everyone holds; it is not grantable/removable, so only
// the elevated roles are toggleable here.
const ROLE_OPTIONS = ["Manager", "Admin"];
let ME = null;

// ---- CSRF + fetch ----------------------------------------------------------
function getCookie(name) {
  const m = document.cookie.match("(^|;)\\s*" + name + "\\s*=\\s*([^;]+)");
  return m ? decodeURIComponent(m.pop()) : "";
}

async function api(method, path, body, { retry = true } = {}) {
  const headers = {};
  if (body) headers["Content-Type"] = "application/json";
  if (!["GET", "HEAD", "OPTIONS"].includes(method)) {
    headers["X-CSRFToken"] = getCookie("csrftoken");
  }
  const res = await fetch(path, {
    method, headers, credentials: "same-origin",
    body: body ? JSON.stringify(body) : undefined,
  });
  if (res.status === 401 && retry && path !== "/api/auth/refresh/") {
    const r = await fetch("/api/auth/refresh/", {
      method: "POST",
      headers: { "X-CSRFToken": getCookie("csrftoken") },
      credentials: "same-origin",
    });
    if (r.ok) return api(method, path, body, { retry: false });
  }
  return res;
}

function flash(msg, isError) {
  const el = document.getElementById("flash");
  el.textContent = msg;
  el.classList.remove("hidden");
  el.classList.toggle("error", !!isError);
}

function can(perm) {
  return ME && ME.permissions.includes(perm);
}

function show(id, visible) {
  document.getElementById(id).classList.toggle("hidden", !visible);
}

// ---- Routing ---------------------------------------------------------------
const PAGES = ["home", "user", "manager", "admin"];

function go(page) {
  PAGES.forEach((p) => show(`${p}-view`, p === page));
  if (page === "user") loadSimplePage("/api/auth/pages/user/", "user-msg");
  if (page === "manager") loadSimplePage("/api/auth/pages/manager/", "manager-msg");
  if (page === "admin") loadUsers();
}

async function loadSimplePage(path, targetId) {
  const el = document.getElementById(targetId);
  const res = await api("GET", path);
  if (res.ok) {
    el.textContent = (await res.json()).message;
  } else {
    el.textContent = `Access denied (HTTP ${res.status}). The server rejected this request.`;
  }
}

// ---- Session bootstrap -----------------------------------------------------
async function loadMe() {
  const res = await api("GET", "/api/auth/me/");
  if (res.ok) {
    ME = await res.json();
    renderShell();
  } else {
    ME = null;
    show("auth-view", true);
    show("navbar", false);
    PAGES.forEach((p) => show(`${p}-view`, false));
  }
}

function renderShell() {
  show("auth-view", false);
  show("navbar", true);
  document.getElementById("whoami").textContent = ME.username;
  document.getElementById("home-username").textContent = ME.username;
  document.getElementById("home-roles").textContent = ME.roles.join(", ") || "(none)";

  // Navbar link visibility follows the user's permissions.
  document.querySelectorAll("#navbar a[data-perm]").forEach((a) => {
    a.classList.toggle("hidden", !can(a.dataset.perm));
  });

  go("home");
}

// ---- Admin: users + roles + delete ----------------------------------------
async function loadUsers() {
  const res = await api("GET", "/api/auth/users/");
  const tbody = document.querySelector("#users-table tbody");
  tbody.replaceChildren();
  if (!res.ok) {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = 4;
    td.textContent = `Access denied (HTTP ${res.status}).`;
    tr.appendChild(td);
    tbody.appendChild(tr);
    return;
  }
  (await res.json()).forEach((u) => tbody.appendChild(userRow(u)));
}

function userRow(u) {
  const tr = document.createElement("tr");
  [String(u.id), u.username, u.roles.join(", ") || "(none)"]
    .forEach((t) => {
      const td = document.createElement("td");
      td.textContent = t;
      tr.appendChild(td);
    });

  const actions = document.createElement("td");
  if (u.id === ME.id) {
    actions.textContent = "— (you)";
  } else {
    ROLE_OPTIONS.forEach((role) => {
      const label = document.createElement("label");
      const cb = document.createElement("input");
      cb.type = "checkbox";
      cb.value = role;
      cb.checked = u.roles.includes(role);
      label.append(cb, document.createTextNode(role));
      actions.appendChild(label);
    });
    actions.appendChild(btn("Save roles", () => saveRoles(u.id, actions)));
    actions.appendChild(btn("Delete user", () => deleteUser(u.id, u.username), "danger"));
  }
  tr.appendChild(actions);
  return tr;
}

function btn(label, handler, cls) {
  const b = document.createElement("button");
  b.type = "button";
  b.textContent = label;
  if (cls) b.classList.add(cls);
  b.addEventListener("click", handler);
  return b;
}

async function saveRoles(userId, cell) {
  const roles = [...cell.querySelectorAll("input:checked")].map((c) => c.value);
  const res = await api("POST", `/api/auth/users/${userId}/roles/`, { roles });
  const data = await res.json().catch(() => ({}));
  flash(res.ok ? "Roles updated." : data.detail || "Denied.", !res.ok);
  if (res.ok) loadUsers();
}

async function deleteUser(userId, username) {
  if (!window.confirm(`Delete user "${username}"? This cannot be undone.`)) return;
  const res = await api("DELETE", `/api/auth/users/${userId}/`);
  if (res.ok) { flash("User deleted."); loadUsers(); }
  else {
    const data = await res.json().catch(() => ({}));
    flash(data.detail || `Delete denied (HTTP ${res.status}).`, true);
  }
}

// ---- Auth forms ------------------------------------------------------------
document.getElementById("login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = e.target;
  const res = await api("POST", "/api/auth/login/", {
    username: f.username.value, password: f.password.value,
  });
  const data = await res.json().catch(() => ({}));
  if (res.ok) { ME = data; renderShell(); flash("Welcome."); }
  else flash(data.detail || "Login failed.", true);
});

document.getElementById("register-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = e.target;
  const res = await api("POST", "/api/auth/register/", {
    username: f.username.value, email: f.email.value, password: f.password.value,
  });
  const data = await res.json().catch(() => ({}));
  if (res.ok) { f.reset(); flash("Account created — now log in."); }
  else flash(data.detail || Object.values(data).flat().join(" ") || "Registration failed.", true);
});

document.getElementById("logout-btn").addEventListener("click", async () => {
  await api("POST", "/api/auth/logout/");
  ME = null;
  flash("Logged out.");
  loadMe();
});

// Navbar navigation
document.querySelectorAll("#navbar a[data-page]").forEach((a) => {
  a.addEventListener("click", (e) => { e.preventDefault(); go(a.dataset.page); });
});

// ---- Boot ------------------------------------------------------------------
loadMe();
