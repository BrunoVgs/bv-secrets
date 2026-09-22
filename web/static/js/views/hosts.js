/* Hotes : les autres instances bv-secrets.

   Chacune a son store, ses declarations et son worker privilegie. Cette page ne
   pilote jamais le disque d'une autre machine : « pousser » depose un `apply`
   cible dans le spool LOCAL, et c'est le worker d'ici qui envoie la valeur.

   L'etat n'est jamais teste au chargement : un hote eteint ne repond pas, et
   attendre son timeout figerait la page. Tester est une action explicite. */
import { $, bindAll, esc } from "../dom.js";
import { finishJob, startJob } from "../jobs.js";
import { HOST_STATE } from "../labels.js";
import { register, render } from "../render.js";
import { CSRF, S } from "../state.js";

function statsHtml() {
  const tested = Object.values(S.hostState);
  const ok = tested.filter((h) => h.state === "ok").length;
  const hosted = S.secrets.filter((s) => s.host).length;
  return [
    { label: "INSTANCES", value: S.hosts.length, color: "#ececec" },
    { label: "SECRETS HÉBERGÉS", value: hosted, color: "#ececec" },
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
      <span class="t">HÔTE DÉCLARÉ NULLE PART</span></div>
    <div class="empty" style="text-align:left">
      ${esc(S.hostOrphans.join(", "))} — des secrets portent <code>host:</code> vers
      ${S.hostOrphans.length > 1 ? "ces hôtes" : "cet hôte"}, absent de la section
      <code>[hosts]</code> de <code>bv-secrets.ini</code>. Rien ne leur sera poussé.
    </div></div>`;
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
  return `<div class="row g-host" style="--i:${index}">
    <div class="cell nm">${esc(host.name)}</div>
    <div class="mono" style="font-size:11px;color:#a8a8a8">${esc(host.url)}</div>
    <div><span class="tag" style="--g:${host.hasKey ? "#3fbf5f" : "#e06060"}"
      title="${host.hasKey ? "clé posée" : "aucune clé : cet hôte est injoignable"}"
      >${host.hasKey ? "oui" : "NON"}</span></div>
    <div title="${esc(host.secrets.join(", "))}">${host.secrets.length}</div>
    <div style="min-width:0">${stateCell(host.name)}</div>
    <div class="right">
      <button class="btn" data-busy data-hosttest="${esc(host.name)}">tester</button>
      <button class="btn acc" data-busy data-hostpush="${esc(host.name)}"
        ${host.secrets.length ? "" : "disabled"}>pousser</button></div></div>`;
}

async function test(name) {
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

async function push(name) {
  const host = S.hosts.find((h) => h.name === name);
  if (!host || !confirm(`Pousser vers ${name} :\n\n${host.secrets.join(", ")}\n\n`
    + "Les valeurs partent par le tunnel ; l'instance distante applique SES sinks.")) return;
  const job = await startJob("api/hosts/push", { name },
    { title: `push ${name}…`, header: `# push -> ${name}` });
  if (!job) return;
  await finishJob(job.id);
}

function renderHosts() {
  $("#hostStats").innerHTML = statsHtml();
  $("#hostWarn").innerHTML = warnHtml();
  $("#hostRows").innerHTML = S.hosts.length
    ? S.hosts.map(rowHtml).join("")
    : `<div class="empty">Aucune instance déclarée. Section <code>[hosts]</code>
       de <code>bv-secrets.ini</code> :<br><br>
       <code>[hosts]</code><br><code>xeon = http://10.8.0.4:8765</code><br><br>
       Puis <code>bv-secrets hosts xeon --key -</code> pour la clé partagée.</div>`;
  bindAll("data-hosttest", test);
  bindAll("data-hostpush", push);
}

$("#hostTestAll").onclick = () => S.hosts.forEach((h) => test(h.name));
register(renderHosts);
