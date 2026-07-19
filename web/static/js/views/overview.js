/* Vue d'ensemble : compteurs et derniers changements. */
import { $, bindAll, esc } from "../dom.js";
import { openDrawer } from "../drawer.js";
import { rel } from "../format.js";
import { GRP_COLOR } from "../labels.js";
import { register } from "../render.js";
import { S } from "../state.js";

const RECENT_LIMIT = 6;

function statCards() {
  const empty = S.secrets.filter((s) => !s.present && !s.computed).length;
  const declared = S.secrets.filter((s) => s.probed).length;
  const tested = Object.keys(S.doctor).length;
  const failed = Object.values(S.doctor).filter((d) => !d.ok).length;
  return [
    { label: "SECRETS", value: S.secrets.length, unit: "", color: "#ececec" },
    { label: "SANS VALEUR", value: empty, unit: "", color: empty ? "#d9a13b" : "#3fbf5f" },
    { label: "ROTATION AUTO", value: S.auto.length, unit: "", color: "#ececec" },
    {
      label: "PROBES",
      value: tested ? `${tested - failed}/${tested}` : declared,
      unit: tested ? "ok" : "déclarées",
      color: tested ? (failed ? "#d63a42" : "#3fbf5f") : "#8b8b8b",
    },
  ];
}

function renderOverview() {
  $("#ovStats").innerHTML = statCards().map((c, i) =>
    `<div class="stat" style="--i:${i}"><div class="l">${c.label}</div>
      <div style="display:flex;align-items:baseline;gap:8px">
        <div class="v" style="color:${c.color}">${c.value}</div>
        ${c.unit ? `<div class="u">${c.unit}</div>` : ""}</div></div>`).join("");

  const recent = S.secrets
    .filter((s) => s.last_set)
    .sort((a, b) => b.last_set.localeCompare(a.last_set))
    .slice(0, RECENT_LIMIT);

  $("#ovRecent").innerHTML = recent.length
    ? recent.map((s, i) => `<div class="row g-recent click" style="--i:${i}"
        data-open="${esc(s.name)}">
        <div class="cell"><div class="nm">${esc(s.name)}</div></div>
        <div><span class="tag g" style="--g:${GRP_COLOR[s.group] || "#888"}">${esc(s.group)}</span></div>
        <div class="mono" style="font-size:11px;color:#a8a8a8;text-align:right"
          title="${esc(s.last_set)}">${rel(s.last_set)}</div></div>`).join("")
    : '<div class="empty">—</div>';

  bindAll("data-open", openDrawer);
}

register(renderOverview);
