/* Coffre : inventaire consultable, filtrable, triable. Aucune rotation ici. */
import { $, $$, bindAll, esc } from "../dom.js";
import { openDrawer } from "../drawer.js";
import { dotColor, rel } from "../format.js";
import { GRP_COLOR, GRP_HELP, GRP_LABEL, KIND_HELP } from "../labels.js";
import { register } from "../render.js";
import { bindSort, paintHead, sortRows } from "../sort.js";
import { S } from "../state.js";
import { toast } from "../toast.js";

const ALL = "tous";
const API_FILTER = "clés API";

function kindFilters() {
  const kinds = new Set(S.secrets.filter((s) => !s.apikey).map((s) => s.kind));
  return [ALL, API_FILTER, ...kinds];
}

function matchesFilter(secret) {
  if (S.kindFilter === ALL) return true;
  if (S.kindFilter === API_FILTER) return secret.apikey;
  return !secret.apikey && secret.kind === S.kindFilter;
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
    <div><span class="tag${secret.apikey ? " api" : ""}"
      title="${esc(KIND_HELP[secret.kind] || "")}">
      ${esc(secret.apikey ? "clé API" : secret.kind)}</span></div>
    <div><span class="tag g" style="--g:${GRP_COLOR[secret.group] || "#888"}"
      title="${esc(GRP_HELP[secret.group] || "")}">
      ${esc(GRP_LABEL[secret.group] || secret.group)}</span></div>
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

  $("#coffreRows").innerHTML = rows.length
    ? rows.map(rowHtml).join("")
    : `<div class="empty">Aucun secret ne correspond à « ${esc(S.search)} »</div>`;
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
  .map((k) => `<button class="filt" data-kind="${esc(k)}">${esc(k)}</button>`).join("");
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
