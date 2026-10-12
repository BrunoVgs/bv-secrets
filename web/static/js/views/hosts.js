/* Instances : les autres machines qui font tourner bv-secrets.

   Chacune a son store, ses declarations et son worker privilegie. Cette page ne
   pilote jamais le disque d'une autre machine : « pousser » depose un `apply`
   cible dans le spool LOCAL, et c'est le worker d'ici qui envoie la valeur.

   L'etat n'est jamais teste au chargement : un hote eteint ne repond pas, et
   attendre son timeout figerait la page. Tester est une action explicite. */
import { hostDeploy } from "../api.js";
import { $, bindAll, esc } from "../dom.js";
import { openSheet } from "../hostsheet.js";
import { finishJob, startJob } from "../jobs.js";
import { HOST_STATE } from "../labels.js";
import { register, render } from "../render.js";
import { CSRF, S } from "../state.js";
import * as log from "../worklog.js";

function statsHtml() {
  const tested = Object.values(S.hostState);
  const ok = tested.filter((h) => h.state === "ok").length;
  const hosted = S.secrets.filter((s) => s.host).length;
  return [
    { label: "INSTANCES", value: S.hosts.length, color: "#ececec" },
    { label: "SECRETS PILOTÉS D'ICI", value: hosted, color: "#ececec" },
    {
      label: "JOIGNABLES",
      value: tested.length ? `${ok}/${tested.length}` : "—",
      color: tested.length && ok === tested.length ? "#3fbf5f"
        : tested.length ? "#d9a13b" : "#888",
    },
  ].map((c, i) => `<div class="stat" style="--i:${i}"><div class="l">${c.label}</div>
      <div class="v" style="font-size:26px;color:${c.color}">${c.value}</div></div>`).join("");
}

function warnHtml() {
  if (!S.hostOrphans.length) return "";
  return `<div class="panel" style="border-color:#d9a13b">
    <div class="ph"><span class="sq" style="background:#d9a13b"></span>
      <span class="t">INSTANCE DÉCLARÉE NULLE PART</span></div>
    <div class="empty" style="text-align:left">
      ${esc(S.hostOrphans.join(", "))} — des secrets portent <code>host:</code> vers
      ${S.hostOrphans.length > 1 ? "ces instances" : "cette instance"}, qui n'existe
      pas ici. Rien ne leur sera poussé : l'ajouter ci-dessous.</div></div>`;
}

function stateCell(name) {
  const probe = S.hostState[name];
  if (!probe) return '<span style="color:#888">non testé</span>';
  const meta = HOST_STATE[probe.state] || HOST_STATE.unknown;
  return `<span class="dot" style="background:${meta.color};display:inline-block;
    width:8px;height:8px;border-radius:50%;margin-right:6px"></span>
    <span title="${esc(probe.detail || "")}">${esc(probe.detail || meta.label)}</span>`;
}

function rowHtml(host, index) {
  return `<div class="row g-host" style="--i:${index}" data-hostopen="${esc(host.name)}">
    <div class="cell nm" title="${esc(host.note)}">${esc(host.name)}</div>
    <div class="mono" style="font-size:11px;color:#a8a8a8">${esc(host.url)}</div>
    <div><span class="tag" style="--g:${host.hasKey ? "#3fbf5f" : "#e06060"}"
      title="${host.hasKey ? "clé posée" : "aucune clé : cette instance est injoignable"}"
      >${host.hasKey ? "oui" : "NON"}</span></div>
    <div title="${esc(host.secrets.join(", "))}">${host.secrets.length}</div>
    <div style="min-width:0">${stateCell(host.name)}</div>
    <div class="right">
      <button class="btn" data-busy data-hosttest="${esc(host.name)}">tester</button>
      <button class="btn acc" data-busy data-hostpush="${esc(host.name)}"
        ${host.secrets.length ? "" : "disabled"}>pousser</button></div></div>`;
}

function formHtml() {
  const f = S.hostForm;
  if (!f) return "";
  return `<div class="hostform">
    <input class="search" id="hfName" placeholder="nom (xeon, vps1…)" value="${esc(f.name)}"
      ${f.editing ? "disabled" : ""}>
    <input class="search" id="hfUrl" placeholder="http://10.8.0.4:8765" value="${esc(f.url)}">
    <input class="search" id="hfNote" placeholder="note : rôle de la machine, hébergeur…"
      value="${esc(f.note)}">
    <div class="wide">
      <input class="search" id="hfSsh" value="${esc(f.ssh)}"
        placeholder="envoyer l'instance par ssh : compte@machine (facultatif)">
      <input class="search" id="hfPw" type="password" autocomplete="current-password"
        placeholder="mot de passe du dashboard, pour l'envoi">
      <button class="btn acc" id="hfSave" data-busy>${f.editing ? "enregistrer" : "ajouter"}</button>
      <button class="btn" id="hfCancel">annuler</button></div>
    <div class="wide cli">Sans ssh : l'instance est seulement déclarée, à installer là-bas
      à la main. Avec : le worker d'ici s'y connecte, installe ou met à jour bv-secrets,
      pose la clé partagée, lance le service et vérifie qu'elle répond.</div></div>`;
}

export async function testHost(name) {
  try {
    const response = await fetch("api/hosts/test", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-CSRF": CSRF },
      body: JSON.stringify({ name }),
    });
    S.hostState[name] = await response.json();
  } catch (e) {
    S.hostState[name] = { state: "unreachable", detail: `réseau: ${e.message}` };
  }
  render();
}

export async function pushHost(name) {
  const host = S.hosts.find((h) => h.name === name);
  if (!host || !confirm(`Pousser vers ${name} :\n\n${host.secrets.join(", ")}\n\n`
    + "Les valeurs partent par le tunnel ; l'instance distante applique SES sinks.")) return;
  const job = await startJob("api/hosts/push", { name },
    { title: `push ${name}…`, header: `# push -> ${name}` });
  if (!job) return;
  await finishJob(job.id);
}

/* Le registre vit cote serveur : apres un job qui le modifie, on repart d'un
   chargement propre plutot que de recopier sa logique ici. */
export async function hostJob(url, payload, label) {
  const job = await startJob(url, payload, { title: `${label}…`, header: `# ${label}` });
  if (!job) return;
  await finishJob(job.id, { onDone: () => location.reload() });
}

/* L'envoi porte le mot de passe du dashboard : il passe par la route authentifiee,
   puis se suit comme n'importe quel job. */
async function deploy(payload) {
  let job;
  try {
    job = await hostDeploy(payload);
  } catch (e) {
    alert(`Envoi refusé : ${e.message === "bad password" ? "mot de passe incorrect" : e.message}`);
    return;
  }
  log.setBusy(true);
  log.open(`envoi ${payload.name}…`);
  log.line(`# instance ${payload.name} -> ${payload.ssh}`, "jl-run");
  await finishJob(job.id, { onDone: () => location.reload() });
}

export function editHost(host) {
  S.hostForm = { name: host.name, url: host.url, note: host.note, ssh: "", editing: true };
  S.hostSheet = null;
  render();
}

function wireForm() {
  if (!S.hostForm) return;
  const read = () => Object.assign(S.hostForm, {
    name: $("#hfName").value.trim(), url: $("#hfUrl").value.trim(), note: $("#hfNote").value.trim(),
    ssh: $("#hfSsh").value.trim(),
  });
  $("#hfCancel").onclick = () => { S.hostForm = null; render(); };
  $("#hfSave").onclick = () => {
    const f = read();
    if (!/^[a-z0-9][a-z0-9_-]{0,31}$/.test(f.name) || !/^https?:\/\/\S+$/.test(f.url)) {
      alert("Nom en minuscules sans espace, et URL du type http://adresse:8765.");
      return;
    }
    const payload = { name: f.name, url: f.url, note: f.note };
    if (f.ssh) {
      deploy({ ...payload, ssh: f.ssh, password: $("#hfPw").value });
    } else {
      hostJob("api/hosts/save", payload, `instance ${f.name}`);
    }
  };
}

function renderHosts() {
  $("#hostStats").innerHTML = statsHtml();
  $("#hostWarn").innerHTML = warnHtml();
  $("#hostForm").innerHTML = formHtml();
  $("#hostRows").innerHTML = S.hosts.length
    ? S.hosts.map(rowHtml).join("")
    : `<div class="empty">Aucune instance. Une instance est un autre bv-secrets, sur une
       autre machine : ses secrets s'éditent ici et partent chez elle par le tunnel.<br><br>
       « + instance » pour en déclarer une.</div>`;
  bindAll("data-hosttest", testHost);
  bindAll("data-hostpush", pushHost);
  bindAll("data-hostopen", openSheet);
  wireForm();
}

$("#hostTestAll").onclick = () => S.hosts.forEach((h) => testHost(h.name));
$("#hostAdd").onclick = () => {
  S.hostForm = { name: "", url: "http://", note: "", ssh: "", editing: false };
  render();
};
register(renderHosts);
