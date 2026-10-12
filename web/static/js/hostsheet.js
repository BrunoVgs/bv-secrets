/* Fiche d'une instance : la machine, ses secrets tels qu'ELLE les declare, et ce
   qu'on en pilote d'ici.

   La fiche est lue chez l'instance a l'ouverture (un aller-retour signe). Elle ne
   contient aucune valeur : des noms, des formats, des longueurs, un etat. */
import { hostKey, hostSheet } from "./api.js";
import { $, bindAll, esc } from "./dom.js";
import { rel } from "./format.js";
import { HOST_STATE, REMOTE_SECRET } from "./labels.js";
import { register, render } from "./render.js";
import { S } from "./state.js";
import { toast } from "./toast.js";
import { editHost, hostJob, pushHost, testHost } from "./views/hosts.js";

const root = $("#hostSheet");
const GIB = 1024 ** 3;

export async function openSheet(name) {
  S.selected = null;
  S.hostSheet = { name, data: null, error: null, picked: new Set(), key: null };
  render();
  testHost(name);
  try {
    S.hostSheet.data = await hostSheet(name);
  } catch (e) {
    if (S.hostSheet?.name === name) S.hostSheet.error = e.message;
  }
  render();
}

function close() {
  S.hostSheet = null;
  render();
}

function duration(seconds) {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  return days ? `${days} j ${hours} h` : `${hours} h ${Math.floor((seconds % 3600) / 60)} min`;
}

const cell = (label, value) => `<div class="m"><div class="ml">${label}</div>
  <div class="mv">${esc(value)}</div></div>`;

function machineHtml(m) {
  if (!m.hostname) return "";
  return `<div class="sec" style="--i:0"><div class="lb">MACHINE</div>
      <div class="cli">${esc(m.hostname)} · ${esc(m.os)} · noyau ${esc(m.kernel)}</div></div>
    <div class="meta" style="--i:1">
      ${cell("ALLUMÉE DEPUIS", duration(m.uptime))}
      ${cell("CŒURS", m.cpus)}
      ${cell("MÉMOIRE LIBRE", `${(m.memAvailable / GIB).toFixed(1)} / ${(m.memTotal / GIB).toFixed(1)} Go`)}
      ${cell("DISQUE LIBRE", `${Math.round(m.diskFree / GIB)} / ${Math.round(m.diskTotal / GIB)} Go`)}
    </div>`;
}

function secretRow(secret, picked) {
  const meta = REMOTE_SECRET[secret.state] || REMOTE_SECRET.unknown;
  const lead = secret.managed
    ? '<span class="dot" style="background:#3fbf5f;width:8px;height:8px" title="piloté d\'ici"></span>'
    : `<input type="checkbox" data-pick="${esc(secret.name)}" ${picked.has(secret.name) ? "checked" : ""}
        ${secret.kind === "computed" ? "disabled" : ""} title="piloter d'ici">`;
  return `<div class="row g-hsec">
    <div>${lead}</div>
    <div class="cell nm" title="${esc(secret.note || "")}">${esc(secret.name)}
      <div class="cli">${esc(secret.kind)} · ${secret.len ? `${secret.len} c` : "vide"}
        · ${rel(secret.lastSet)}</div></div>
    <div class="st" title="${esc(secret.detail)}"><span style="color:${meta.color}">${meta.label}</span>
      <div style="color:${secret.managed ? "#3fbf5f" : "#888"}">
        ${secret.managed ? "piloté d'ici" : "là-bas seulement"}</div></div></div>`;
}

function secretsHtml(sheet) {
  const { data, picked } = sheet;
  const managed = data.secrets.filter((s) => s.managed).length;
  const rows = data.secrets.length
    ? data.secrets.map((s) => secretRow(s, picked)).join("")
    : '<div class="cli">Cette instance ne déclare encore aucun secret.</div>';
  const missing = data.missing.length
    ? `<div class="warn">Déclarés ici pour cette instance mais inconnus chez elle :
       <b>${esc(data.missing.join(", "))}</b>. Une poussée échouera tant qu'elle ne les
       déclare pas avec ses sinks.</div>` : "";
  return `<div class="sec" style="--i:2">
    <div class="lb">SECRETS CHEZ ELLE · ${data.secrets.length} DONT ${managed} PILOTÉS D'ICI</div>
    ${rows}${missing}
    <div class="edit"><button class="btn acc" id="hsLink" data-busy
      ${picked.size ? "" : "disabled"}>piloter d'ici (${picked.size})</button></div>
    <div class="cli">Piloter d'ici déclare le secret dans cette instance-ci, sans sink :
      sa valeur s'édite et se rote ici, et part chez elle. Aucune valeur n'est rapatriée.</div>
  </div>`;
}

function keyHtml(sheet, host) {
  if (sheet.key !== null) {
    return `<div class="valbox"><div class="v on">${esc(sheet.key || "(aucune clé)")}</div>
      <button class="btn" id="hsKeyHide">cacher</button></div>
      <div class="cli">À poser chez elle dans <b>&lt;store&gt;/hosts/self.key</b> (0600), avec
        <b>BV_WORKER_BIND</b> sur son adresse de tunnel.</div>`;
  }
  if (!host.hasKey) return '<div class="cli">Aucune clé : « nouvelle clé » en génère une.</div>';
  return `<div class="valbox">
    <input type="password" id="hsPw" placeholder="mot de passe du dashboard"
      autocomplete="current-password">
    <button class="btn acc" id="hsKeyShow">voir</button></div>`;
}

function renderSheet() {
  const sheet = S.hostSheet;
  const host = sheet && S.hosts.find((h) => h.name === sheet.name);
  if (!host) {
    root.innerHTML = "";
    return;
  }
  const probe = S.hostState[host.name];
  const state = probe ? (HOST_STATE[probe.state] || HOST_STATE.unknown) : { color: "#888" };
  const body = sheet.error
    ? `<div class="sec"><div class="warn">Fiche illisible : ${esc(sheet.error)}</div></div>`
    : sheet.data ? machineHtml(sheet.data.machine) + secretsHtml(sheet)
      : '<div class="sec"><div class="cli">lecture de la fiche chez l\'instance…</div></div>';

  root.innerHTML = `<div id="scrim"></div><aside id="drawer">
    <div class="dh"><div style="flex:1;min-width:0">
      <div style="display:flex;align-items:center;gap:9px">
        <div class="dot" style="width:9px;height:9px;background:${state.color}"></div>
        <div class="dn cell">${esc(host.name)}</div></div>
      <div class="ds">${esc(host.url)}${probe ? ` · ${esc(probe.detail || "")}` : ""}</div>
      ${host.note ? `<div class="ds">${esc(host.note)}</div>` : ""}
    </div><button class="btn" id="hsClose">✕</button></div>
    ${body}
    <div class="sec" style="--i:3"><div class="lb">ACTIONS</div><div class="edit">
      <button class="btn" id="hsRefresh" data-busy>relire</button>
      <button class="btn acc" id="hsPush" data-busy ${host.secrets.length ? "" : "disabled"}>
        pousser ${host.secrets.length} secret(s)</button>
      <button class="btn" id="hsEdit" ${host.editable ? "" : "disabled"}
        title="${host.editable ? "" : "déclarée dans bv-secrets.ini : à modifier là"}">modifier</button>
      <button class="btn" id="hsNewKey" data-busy ${host.editable ? "" : "disabled"}>nouvelle clé</button>
      <button class="btn" id="hsRemove" data-busy ${host.editable ? "" : "disabled"}>retirer</button>
    </div></div>
    <div class="sec" style="--i:4"><div class="lb">CLÉ PARTAGÉE</div>${keyHtml(sheet, host)}</div>
  </aside>`;
  wire(sheet, host);
}

function wire(sheet, host) {
  $("#scrim").onclick = close;
  $("#hsClose").onclick = close;
  $("#hsRefresh").onclick = () => openSheet(host.name);
  $("#hsPush").onclick = () => pushHost(host.name);
  $("#hsEdit").onclick = () => editHost(host);
  $("#hsNewKey").onclick = () => {
    if (confirm(`Générer une nouvelle clé pour ${host.name} ?\n\nL'instance refusera tout `
      + "jusqu'à ce que la même clé soit posée chez elle.")) {
      hostJob("api/hosts/save", { name: host.name, url: host.url, note: host.note, newkey: true },
        `nouvelle clé ${host.name}`);
    }
  };
  $("#hsRemove").onclick = () => {
    if (confirm(`Retirer l'instance ${host.name} et sa clé ?\n\nSes secrets restent déclarés `
      + "ici et chez elle ; rien n'est effacé sur la machine distante.")) {
      hostJob("api/hosts/remove", { name: host.name }, `retrait ${host.name}`);
    }
  };
  bindAll("data-pick", (name, el) => {
    if (el.checked) sheet.picked.add(name); else sheet.picked.delete(name);
    render();
  });
  const link = $("#hsLink");
  if (link) {
    link.onclick = () => hostJob("api/hosts/link",
      { name: host.name, secrets: [...sheet.picked] }, `piloter ${sheet.picked.size} secret(s)`);
  }
  const hide = $("#hsKeyHide");
  if (hide) hide.onclick = () => { sheet.key = null; render(); };
  const show = $("#hsKeyShow");
  if (!show) return;
  const input = $("#hsPw");
  const reveal = async () => {
    try {
      sheet.key = (await hostKey(host.name, input.value)).key;
      render();
    } catch {
      input.value = "";
      input.placeholder = "mot de passe incorrect";
      toast("clé non révélée");
    }
  };
  show.onclick = reveal;
  input.onkeydown = (e) => { if (e.key === "Enter") reveal(); };
}

document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && S.hostSheet) close();
});

register(renderSheet);
