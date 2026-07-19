/* Tiroir de détail d'un secret : valeur révélable, format et politique de rotation. */
import { reveal } from "./api.js";
import { $, esc } from "./dom.js";
import { dotColor, rel } from "./format.js";
import { finishJob, startJob } from "./jobs.js";
import { GRP_HELP, KIND_HELP } from "./labels.js";
import { register, render } from "./render.js";
import { GROUPS, KINDS, S } from "./state.js";
import { toast } from "./toast.js";

const host = $("#drawerHost");

export function openDrawer(name) {
  S.selected = name;
  S.pendingKind = null;
  S.pendingGroup = null;
  render();
}

export function closeDrawer() {
  S.selected = null;
  S.pendingKind = null;
  S.pendingGroup = null;
  render();
}

function valueSection(secret, revealed) {
  if (revealed) {
    return `<div class="valbox"><div class="v on">${esc(S.revealed[secret.name] || "(vide)")}</div>
      <button class="btn" id="dhide">cacher</button>
      <button class="btn acc" id="dcopy">copier</button></div>`;
  }
  if (!secret.present) return '<div class="valbox"><div class="v">aucune valeur</div></div>';
  return `<div class="valbox">
    <input type="password" id="dpw" placeholder="mot de passe du dashboard"
      autocomplete="current-password">
    <button class="btn acc" id="dreveal">voir</button></div>`;
}

function formatNotice(secret, kind, group) {
  const generable = KINDS.gen.includes(kind);
  const wasGenerableAuto = KINDS.gen.includes(secret.kind) && secret.group === "auto";
  // rendre un secret générable ET auto revient à le faire écraser au prochain rotate
  const warn = generable && group === "auto" && !wasGenerableAuto
    ? '<div class="warn">Le prochain <b>rotate</b> du groupe auto écrasera cette valeur.</div>'
    : "";
  if (secret.computed) {
    return warn + '<div class="cli">secret calculé — format figé (clé <b>compute</b>, CLI)</div>';
  }
  if (secret.apikey) {
    return warn + '<div class="warn">Clé API : émise par l\'app, jamais générée ici. '
      + 'La roter écrirait une valeur que l\'app refuse. La régénérer dans l\'app, puis '
      + `<b>bv-secrets set ${esc(secret.name)} &lt;valeur&gt;</b>.</div>`;
  }
  return warn;
}

function options(list, current, secret) {
  return list.map((o) => {
    const disabled = secret.apikey && KINDS.gen.includes(o) ? " disabled" : "";
    return `<option value="${o}"${o === current ? " selected" : ""}${disabled}>${o}</option>`;
  }).join("");
}

function renderDrawer() {
  const secret = S.selected ? S.byName[S.selected] : null;
  if (!secret) {
    host.innerHTML = "";
    return;
  }
  const revealed = S.revealed[secret.name] !== undefined;
  const kind = S.pendingKind ?? secret.kind;
  const group = S.pendingGroup ?? secret.group;
  const dirty = kind !== secret.kind || group !== secret.group;

  host.innerHTML = `<div id="scrim"></div><aside id="drawer">
    <div class="dh"><div style="flex:1;min-width:0">
      <div style="display:flex;align-items:center;gap:9px">
        <div class="dot" style="width:9px;height:9px;background:${dotColor(secret)}"></div>
        <div class="dn cell">${esc(secret.name)}</div></div>
      ${secret.note ? `<div class="ds">${esc(secret.note)}</div>` : ""}
    </div><button class="btn" id="dclose">✕</button></div>

    <div class="sec" style="--i:0"><div class="lb">VALEUR</div>
      ${valueSection(secret, revealed)}</div>

    <div class="meta" style="--i:1">
      <div class="m"><div class="ml">DERNIER SET</div>
        <div class="mv" title="${esc(secret.last_set || "")}">${rel(secret.last_set)}</div></div>
      <div class="m"><div class="ml">LONGUEUR</div>
        <div class="mv" style="color:${secret.present ? "#ececec" : "#d9a13b"}">
          ${secret.present ? `${secret.len} c` : "vide"}</div></div>
    </div>

    <div class="sec" style="--i:2"><div class="lb">FORMAT · ROTATION</div>
      <div class="edit">
        <select id="dkind" title="${esc(KIND_HELP[kind] || "")}"${secret.computed ? " disabled" : ""}>
          ${options(KINDS.all, kind, secret)}</select>
        <select id="dgroup" title="${esc(GRP_HELP[group] || "")}">
          ${options(GROUPS, group, secret)}</select>
        <button class="btn acc" id="dmeta" data-busy${dirty ? "" : " disabled"}>enregistrer</button>
      </div>
      <div class="cli">${esc(KIND_HELP[kind] || "")} · ${esc(GRP_HELP[group] || "")}</div>
      ${formatNotice(secret, kind, group)}
    </div>

    ${chips("SINKS", secret.sink_types, 3)}
    ${chips("SERVICES", secret.services, 4)}
  </aside>`;

  wireDrawer(secret, kind, group);
}

function chips(label, items, index) {
  if (!items.length) return "";
  return `<div class="sec" style="--i:${index}"><div class="lb">${label}</div><div>
    ${items.map((t) => `<span class="chip">${esc(t)}</span>`).join("")}</div></div>`;
}

function copyValue(name) {
  try {
    navigator.clipboard.writeText(S.revealed[name] || "");
  } catch { /* presse-papier indisponible hors contexte sécurisé */ }
  toast(`✓ ${name} copié`);
}

function wireDrawer(secret, kind, group) {
  $("#scrim").onclick = closeDrawer;
  $("#dclose").onclick = closeDrawer;
  $("#dkind").onchange = (e) => { S.pendingKind = e.target.value; render(); };
  $("#dgroup").onchange = (e) => { S.pendingGroup = e.target.value; render(); };
  $("#dmeta").onclick = () => saveMeta(secret.name, kind, group);

  const hide = $("#dhide");
  if (hide) {
    hide.onclick = () => { delete S.revealed[secret.name]; render(); };
  }
  const copy = $("#dcopy");
  if (copy) copy.onclick = () => copyValue(secret.name);

  const button = $("#dreveal");
  if (!button) return;
  const input = $("#dpw");
  const doReveal = async () => {
    let value;
    try {
      value = await reveal(secret.name, input.value);
    } catch {
      toast("réseau indisponible");
      return;
    }
    if (value === null) {
      input.value = "";
      input.placeholder = "mot de passe incorrect";
      input.focus();
      return;
    }
    S.revealed[secret.name] = value;
    render();
  };
  button.onclick = doReveal;
  input.onkeydown = (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      doReveal();
    }
  };
  input.focus();
}

async function saveMeta(name, kind, group) {
  const job = await startJob("api/meta/apply", { changes: [{ name, kind, group }] },
    { title: "format…", header: `# meta ${name} kind=${kind} group=${group}` });
  if (!job) return;
  // la conf est relue côté serveur : on recharge pour repartir d'un boot cohérent
  await finishJob(job.id, { onDone: () => location.reload() });
}

document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && S.selected) closeDrawer();
});

register(renderDrawer);
