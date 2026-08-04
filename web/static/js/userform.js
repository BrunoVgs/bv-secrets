/* Création d'un compte du portail : identifiant, rôle, mot de passe.

   Même contrat que l'ajout d'un secret (addform.js) : le formulaire refuse ce que
   le worker refuserait, et comme la requête porte un mot de passe elle se
   ré-authentifie au mot de passe du dashboard. */
import { createUser } from "./api.js";
import { $, esc } from "./dom.js";
import { watchJob } from "./jobs.js";
import { register, render } from "./render.js";
import { ROLES, S } from "./state.js";
import { toast } from "./toast.js";
import * as log from "./worklog.js";

const host = $("#userHost");
const USERNAME_RE = /^[A-Za-z0-9._-]{2,64}$/;
const MIN_PASSWORD = 8;
const WEAKEST = ROLES[ROLES.length - 1];   // nouveau compte : le rôle le plus faible

export function openUserForm() {
  S.addingUser = { username: "", role: WEAKEST, value: "" };
  render();
}

function close() {
  S.addingUser = null;
  render();
}

function problem(form) {
  if (!USERNAME_RE.test(form.username)) {
    return "Identifiant : 2 à 64 caractères parmi lettres, chiffres, . _ -";
  }
  if ((S.users || []).some((u) => u.username === form.username)) {
    return `${form.username} existe déjà.`;
  }
  if (form.value.length < MIN_PASSWORD) {
    return `Mot de passe : ${MIN_PASSWORD} caractères minimum.`;
  }
  return null;
}

function renderUserForm() {
  const form = S.addingUser;
  if (!form) {
    host.innerHTML = "";
    return;
  }
  const err = problem(form);

  host.innerHTML = `<div id="scrim"></div><aside id="drawer">
    <div class="dh"><div style="flex:1;min-width:0">
      <div class="dn">Nouveau compte</div>
      <div class="ds">Compte du portail d'authentification, avec son rôle.</div>
    </div><button class="btn" id="uclose">✕</button></div>

    <div class="sec" style="--i:0"><div class="lb">IDENTIFIANT</div>
      <input class="search" id="uname" value="${esc(form.username)}" spellcheck="false"
        autocomplete="off" placeholder="prenom" style="width:100%"></div>

    <div class="sec" style="--i:1"><div class="lb">RÔLE</div>
      <div class="edit">${ROLES.map((role) =>
        `<button class="filt${role === form.role ? " on" : ""}" data-urole="${role}">${role}</button>`
      ).join("")}</div>
      <div class="cli">Le détail service par service est dans « Accès &amp; rôles ».</div>
    </div>

    <div class="sec" style="--i:2"><div class="lb">MOT DE PASSE DU COMPTE</div>
      <input type="password" id="uvalue" class="search" style="width:100%"
        autocomplete="new-password" value="${esc(form.value)}"
        placeholder="${MIN_PASSWORD} caractères minimum">
      <div class="cli">Transmis au portail sur STDIN, jamais écrit dans un log ni
        conservé par bv-secrets.</div>
    </div>

    <div class="sec" style="--i:3"><div class="lb">CONFIRMER</div>
      <input type="password" id="upw" class="search" style="width:100%"
        autocomplete="current-password" placeholder="mot de passe du dashboard">
      <div class="warn${err ? "" : " hidden"}" id="uerr">${esc(err || "")}</div>
      <div class="bar" style="margin-top:8px">
        <button class="btn big solid" id="usave" data-busy${err ? " disabled" : ""}>
          Créer le compte</button>
        <span class="cli" id="ustatus"></span>
      </div>
    </div>
  </aside>`;

  wire(form);
}

/* Les champs texte ne redessinent pas le tiroir : réécrire son HTML à chaque
   frappe ferait perdre le focus. Seuls l'erreur et le bouton bougent. */
function refreshValidity(form) {
  const err = problem(form);
  const box = $("#uerr");
  box.textContent = err || "";
  box.classList.toggle("hidden", !err);
  $("#usave").disabled = Boolean(err) || S.busy;
}

function wire(form) {
  $("#scrim").onclick = close;
  $("#uclose").onclick = close;
  $("#uname").oninput = (e) => { form.username = e.target.value; refreshValidity(form); };
  $("#uvalue").oninput = (e) => { form.value = e.target.value; refreshValidity(form); };
  document.querySelectorAll("[data-urole]").forEach((el) => {
    el.onclick = () => { form.role = el.dataset.urole; render(); };
  });
  $("#usave").onclick = () => submit(form);
}

async function submit(form) {
  const password = $("#upw").value;
  if (!password) {
    $("#ustatus").textContent = "mot de passe requis";
    return;
  }
  let job;
  try {
    job = await createUser({
      username: form.username,
      role: form.role,
      value: form.value,
      password,
    });
  } catch (e) {
    $("#ustatus").textContent = `refusé : ${e.message}`;
    return;
  }
  const { username, role } = form;
  close();
  // Le mot de passe a quitté le navigateur : la suite est un job comme un autre.
  log.open("comptes…");
  log.line(`# user create ${username} -> ${role}`, "jl-run");
  log.setBusy(true);
  const result = await watchJob(job.id, (l) => log.line(l));
  const ok = result.status === "done";
  log.line(ok ? "✓ terminé" : `✗ ${result.status}`, ok ? "jl-done" : "jl-err");
  log.setBusy(false);
  // Le job de création renvoie la liste à jour : pas de second aller-retour.
  if (result.data) S.users = result.data;
  render();
  if (ok) toast(`✓ compte ${username} créé`);
}

document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && S.addingUser) close();
});

register(renderUserForm);
