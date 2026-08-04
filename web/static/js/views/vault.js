/* Coffre : inventaire consultable, filtrable, triable. Aucune rotation ici. */
import { $, $$, bindAll, esc } from "../dom.js";
import { openDrawer } from "../drawer.js";
import { dotColor, rel } from "../format.js";
import { OBJ_COLOR, OBJ_HELP, OBJ_LABEL, OBJ_ORDER,
         ROT_COLOR, ROT_HELP, ROT_LABEL, KIND_HELP } from "../labels.js";
import { register } from "../render.js";
import { bindSort, paintHead, sortRows } from "../sort.js";
import { S } from "../state.js";
import { toast } from "../toast.js";

const ALL = "tous";

/* Le filtre porte sur l'OBJET : mes mots de passe, ou les cles des apps tierces.
   La rotation n'est pas un filtre, c'est une colonne -- ce sont deux questions. */
function kindFilters() {
  const present = new Set(S.secrets.map((s) => s.obj));
  return [ALL, ...OBJ_ORDER.filter((c) => present.has(c))];
}

function filterLabel(key) {
  return key === ALL ? ALL : (OBJ_LABEL[key] || key);
}

function matchesFilter(secret) {
  return S.kindFilter === ALL || secret.obj === S.kindFilter;
}

function matchesSearch(secret) {
  if (!S.search) return true;
  return secret.name.toLowerCase().includes(S.search)
    || secret.services.join(" ").toLowerCase().includes(S.search);
}

function rowHtml(secret, index) {
  const revealed = S.revealed[secret.name] !== undefined;
  const value = revealed
    ? esc(S.revealed[secret.name] || "(vide)")
    : (secret.present ? "••••••••••••••••" : "—");
  return `<div class="row g-coffre click${S.selected === secret.name ? " on" : ""}"
    style="--i:${index}" data-open="${esc(secret.name)}">
    <div class="dot" style="background:${dotColor(secret)}"></div>
    <div class="cell"><div class="nm">${esc(secret.name)}</div>
      <div class="sv" title="${esc(secret.services.join(", "))}">
        ${esc(secret.note || secret.services.join(", ") || "—")}</div></div>
    <div><span class="tag cls" style="--c:${OBJ_COLOR[secret.obj] || "#888"}"
      title="${esc(OBJ_HELP[secret.obj] || "")} — format ${esc(secret.kind)}">
      ${esc(OBJ_LABEL[secret.obj] || secret.obj)}</span></div>
    <div><span class="tag cls" style="--c:${ROT_COLOR[secret.rot] || "#888"}"
      title="${esc(ROT_HELP[secret.rot] || "")} — groupe ${esc(secret.group)}">
      ${esc(ROT_LABEL[secret.rot] || secret.rot)}</span></div>
    <div class="cell mono" style="font-size:12px;color:${revealed ? "#e8c9a0" : "#5a5a5a"}">
      ${value}</div>
    <div class="mono" style="font-size:11px;color:#a8a8a8"
      title="${esc(secret.last_set || "")}">${rel(secret.last_set)}</div>
    <div class="right">
      ${revealed ? `<button class="btn" data-copy="${esc(secret.name)}">copier</button>` : ""}
      <button class="btn" data-open="${esc(secret.name)}">${revealed ? "détail" : "voir"}</button>
    </div></div>`;
}

function renderVault() {
  $$("#kindFilters .filt").forEach((b) => b.classList.toggle("on", b.dataset.kind === S.kindFilter));
  const rows = sortRows(S.secrets.filter((s) => matchesFilter(s) && matchesSearch(s)), "coffre");
  paintHead("#coffreHead", "coffre");

  // Deux blocs separes plutot qu'une liste unique : la premiere chose a savoir
  // d'un secret est s'il est a moi ou a une app tierce.
  let html = "";
  if (!rows.length) {
    html = `<div class="empty">Aucun secret ne correspond à « ${esc(S.search)} »</div>`;
  } else {
    let i = 0;
    for (const obj of OBJ_ORDER) {
      const group = rows.filter((s) => s.obj === obj);
      if (!group.length) continue;
      html += `<div class="grp" style="--c:${OBJ_COLOR[obj] || "#888"}">
        <div class="grp-hd"><span class="grp-nm">${esc(OBJ_LABEL[obj] || obj)}</span>
        <span class="grp-hint">${esc(OBJ_HELP[obj] || "")}</span>
        <span class="grp-n">${group.length}</span></div>
        ${group.map((s) => rowHtml(s, i++)).join("")}</div>`;
    }
  }
  $("#coffreRows").innerHTML = html;
  $("#coffreCount").textContent = `${rows.length} / ${S.secrets.length}`;

  bindAll("data-open", openDrawer);
  bindAll("data-copy", (name) => {
    try {
      navigator.clipboard.writeText(S.revealed[name] || "");
    } catch { /* presse-papier indisponible hors contexte sécurisé */ }
    toast(`✓ ${name} copié`);
  });
}

$("#kindFilters").innerHTML = kindFilters()
  .map((k) => `<button class="filt${k === ALL ? "" : " cls"}" data-kind="${esc(k)}"
    ${k === ALL ? "" : `style="--c:${OBJ_COLOR[k] || "#888"}" title="${esc(OBJ_HELP[k] || "")}"`}
    >${esc(filterLabel(k))}</button>`).join("");
$$("#kindFilters .filt").forEach((b) => {
  b.onclick = () => { S.kindFilter = b.dataset.kind; renderVault(); };
});
$("#search").oninput = (e) => { S.search = e.target.value.toLowerCase(); renderVault(); };
bindSort("#coffreHead", "coffre", renderVault);

// collapsed by default: it sits at the bottom and only serves the first read
const legend = $("#leg");
legend.open = localStorage.getItem("bvLeg") === "1";
legend.addEventListener("toggle", () => localStorage.setItem("bvLeg", legend.open ? "1" : "0"));

register(renderVault);
export { renderVault };
