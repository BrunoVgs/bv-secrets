/* Comptes du portail. Les garde-fous (dernier admin) sont portés côté Symfony ;
   l'UI les reflète en désactivant les contrôles correspondants. */
import { $, bindAll, esc } from "../dom.js";
import { rel } from "../format.js";
import { startJob, watchJob } from "../jobs.js";
import { ROLES } from "../labels.js";
import { register } from "../render.js";
import { S } from "../state.js";
import * as log from "../worklog.js";

const SKELETON_ROWS = 3;

function skeleton() {
  return Array.from({ length: SKELETON_ROWS }, () =>
    '<div class="row g-user"><div class="skel" style="width:60%"></div>'
    + '<div class="skel" style="width:80%"></div><div class="skel" style="width:50%"></div>'
    + '<div class="skel" style="width:40%"></div></div>').join("");
}

function rowHtml(user, index, onlyAdmin) {
  const locked = user.role === "admin" && onlyAdmin;
  const buttons = ROLES.map((role) =>
    `<button class="filt${user.role === role ? " on" : ""}" data-role-set="${esc(user.username)}"
      data-role="${role}"${user.role === role || locked ? " disabled" : ""} data-busy>${role}</button>`
  ).join("");
  const action = locked
    ? '<span class="cli">dernier admin</span>'
    : `<button class="btn" data-del="${esc(user.username)}" data-busy>supprimer</button>`;
  return `<div class="row g-user" style="--i:${index}">
    <div class="cell"><div class="nm">${esc(user.username)}</div></div>
    <div class="edit">${buttons}</div>
    <div class="mono" style="font-size:11px;color:#a8a8a8">${rel(user.created)}</div>
    <div class="right">${action}</div></div>`;
}

function renderUsers() {
  const host = $("#userRows");
  if (S.users === null) {
    host.innerHTML = skeleton();
    return;
  }
  if (!S.users.length) {
    host.innerHTML = '<div class="empty">aucun compte</div>';
    return;
  }
  const onlyAdmin = S.users.filter((u) => u.role === "admin").length <= 1;
  host.innerHTML = S.users.map((u, i) => rowHtml(u, i, onlyAdmin)).join("");

  bindAll("data-role-set", (username, el) => userOp("role", username, el.dataset.role));
  bindAll("data-del", (username) => {
    if (confirm(`Supprimer le compte « ${username} » ?\n\nIrréversible.`)) {
      userOp("delete", username);
    }
  });
}

/* Chargement silencieux : pas de console, la vue affiche son squelette. */
export async function loadUsers() {
  const job = await startJob("api/users", null, { silent: true });
  if (!job) return;
  try {
    const result = await watchJob(job.id, () => {});
    if (result.status === "done" && result.data) S.users = result.data;
  } catch { /* la vue reste sur le squelette ; bouton rafraîchir pour réessayer */ }
  log.setBusy(false);
  renderUsers();
}

async function userOp(op, username, role) {
  const job = await startJob("api/user", { op, username, role },
    { title: "comptes…", header: `# user ${op} ${username}${role ? ` -> ${role}` : ""}` });
  if (!job) return;
  const result = await watchJob(job.id, (l) => log.line(l));
  if (result.status === "done") {
    if (result.data) S.users = result.data;
    log.line("✓ terminé", "jl-done");
  } else {
    log.line(`✗ ${result.status}`, "jl-err");
  }
  log.setBusy(false);
  renderUsers();
}

$("#usersReload").onclick = () => {
  S.users = null;
  renderUsers();
  loadUsers();
};

register(renderUsers);
