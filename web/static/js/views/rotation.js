/* Rotation: secrets rotatable from the web. Non-generatable kinds (apikey, opaque,
   computed) and non-rotatable groups are counted apart, never offered. */
import { rotate } from "../actions.js";
import { $, bindAll, esc } from "../dom.js";
import { dotColor, rel } from "../format.js";
import { GRP_COLOR, GRP_HELP, GRP_LABEL, KIND_HELP } from "../labels.js";
import { register } from "../render.js";
import { bindSort, paintHead, sortRows } from "../sort.js";
import { S } from "../state.js";

function statsHtml(rotatable, blocked) {
  return [
    { label: "GROUPE AUTO", value: S.auto.length, color: "#ececec" },
    { label: "ROTABLES ICI", value: rotatable, color: "#ececec" },
    { label: "NON ROTABLES", value: blocked, color: blocked ? "#d9a13b" : "#3fbf5f" },
  ].map((c, i) => `<div class="stat" style="--i:${i}"><div class="l">${c.label}</div>
      <div class="v" style="font-size:26px;color:${c.color}">${c.value}</div></div>`).join("");
}

function rowHtml(secret, index) {
  return `<div class="row g-rot" style="--i:${index}">
    <div style="display:flex;align-items:center;gap:10px;min-width:0">
      <div class="dot" style="background:${dotColor(secret)}"></div>
      <div class="cell nm">${esc(secret.name)}</div></div>
    <div><span class="tag" title="${esc(KIND_HELP[secret.kind] || "")}">${esc(secret.kind)}</span></div>
    <div><span class="tag g" style="--g:${GRP_COLOR[secret.group] || "#888"}"
      title="${esc(GRP_HELP[secret.group] || "")}">
      ${esc(GRP_LABEL[secret.group] || secret.group)}</span></div>
    <div class="mono" style="font-size:11px;color:#a8a8a8"
      title="${esc(secret.last_set || "")}">${rel(secret.last_set)}</div>
    <div class="right">
      <button class="btn acc" data-busy data-rot="${esc(secret.name)}">rotate</button></div></div>`;
}

function renderRotation() {
  const rows = sortRows(S.secrets.filter((s) => s.rotatable), "rotation");
  const blocked = S.secrets.filter((s) => !s.rotatable).length;
  paintHead("#rotHead", "rotation");
  $("#rotStats").innerHTML = statsHtml(rows.length, blocked);
  $("#rotRows").innerHTML = rows.length
    ? rows.map(rowHtml).join("")
    : '<div class="empty">Aucun secret rotable ici.</div>';
  bindAll("data-rot", (name) => rotate([name]));
}

bindSort("#rotHead", "rotation", renderRotation);
register(renderRotation);
