/* Audit: read-only timeline from the worker digest. Client-side filter + render,
   no mutation. */
import { $, esc } from "../dom.js";
import { register } from "../render.js";
import { S } from "../state.js";

const OUT = {
  allow: ["autorisé", "✓"], deny: ["refusé", "✗"], change: ["modifié", "~"],
  login: ["connexion", "→"], check: ["vérifié", "?"], info: ["info", "·"],
};

function fmt(ts) {
  const d = new Date(ts * 1000);
  if (isNaN(d)) return "?";
  const p = (n) => String(n).padStart(2, "0");
  return `${p(d.getDate())}/${p(d.getMonth() + 1)} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

function ago(ts) {
  if (!ts) return "jamais";
  const s = Math.floor(Date.now() / 1000 - ts);
  if (s < 60) return "à l'instant";
  if (s < 3600) return `il y a ${Math.floor(s / 60)} min`;
  if (s < 86400) return `il y a ${Math.floor(s / 3600)} h`;
  return `il y a ${Math.floor(s / 86400)} j`;
}

function rowHtml(e, i) {
  const [label, glyph] = OUT[e.outcome] || OUT.info;
  return `<div class="row g-audit" style="--i:${i}">
    <div class="mono" style="color:#a8a8a8">${fmt(e.ts)}</div>
    <div><span class="chip">${esc(e.source)}</span></div>
    <div class="mono cell" title="${esc(e.actor)}">${esc(e.actor)}</div>
    <div class="cell" title="${esc(e.target)}">${esc(e.target)}</div>
    <div class="o-${e.outcome}">${glyph} ${label}</div>
    <div class="cli cell" title="${esc(e.detail)}">${esc(e.detail)}</div></div>`;
}

function renderAudit() {
  const host = $("#auditRows");
  if (!host) return;
  if (S.audit === null) {
    host.innerHTML = '<div class="empty">chargement…</div>';
    return;
  }
  const src = $("#auditSource").value;
  const svc = $("#auditService").value.trim().toLowerCase();
  const deniedOnly = $("#auditDenied").checked;
  const rows = (S.audit.events || []).filter((e) => {
    if (src !== "all" && e.source !== src) return false;
    if (deniedOnly && e.outcome !== "deny") return false;
    if (svc && !`${e.target} ${e.detail} ${e.actor}`.toLowerCase().includes(svc)) return false;
    return true;
  });

  $("#auditFresh").textContent = `mis à jour ${ago(S.audit.ts)}`;
  host.innerHTML = rows.length
    ? rows.map(rowHtml).join("")
    : '<div class="empty">aucun événement</div>';
}

export async function loadAudit() {
  try {
    S.audit = await fetch("api/audit").then((r) => r.json());
  } catch {
    S.audit = { events: [], as_of: {} };
  }
  renderAudit();
}

["auditSource", "auditService", "auditDenied"].forEach((id) => {
  const el = $(`#${id}`);
  if (el) el.addEventListener("input", renderAudit);
});

register(renderAudit);
