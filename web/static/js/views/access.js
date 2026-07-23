/* Service x role matrix. The table is server-rendered; this module only handles
   editing and sending the diff.

   Only actually-changed rows are sent: a naive "everything that looks unchecked"
   diff removed trusted from services never touched. */
import { $, $$ } from "../dom.js";
import { startJob, watchJob } from "../jobs.js";
import { S } from "../state.js";
import * as log from "../worklog.js";

const status = $("#accessStatus");

function collectChanges() {
  const changes = [];
  $$('#accessTable tbody tr[data-dirty="1"]').forEach((tr) => {
    const roles = $$("input[type=checkbox]", tr).filter((c) => c.checked).map((c) => c.dataset.role);
    const current = roles.slice().sort().join(",");
    const original = (tr.dataset.orig || "").split(",").filter(Boolean).sort().join(",");
    if (current !== original) changes.push({ service: tr.dataset.svc, roles });
  });
  return changes;
}

async function save() {
  if (S.busy) return;
  const changes = collectChanges();
  if (!changes.length) {
    status.textContent = "aucun changement";
    return;
  }
  const summary = changes.map((c) => `${c.service} → ${c.roles.join("+")}`);
  if (!confirm(`Appliquer ${changes.length} changement(s) :\n\n${summary.join("\n")}`)) return;

  status.textContent = "en cours…";
  const job = await startJob("api/access/apply", { changes },
    { title: "accès…", header: `# access — ${summary.join(", ")}` });
  if (!job) {
    status.textContent = "refusé";
    return;
  }
  log.line(`job ${job.id}…`, "jl-run");
  status.textContent = "application…";
  const result = await watchJob(job.id, (l) => log.line(l));
  if (result.status === "done") {
    status.textContent = "✓ appliqué";
    log.setStatus("✓ terminé");
    setTimeout(() => location.reload(), 1200);   // la matrice est rendue côté serveur
  } else {
    log.line(`✗ ${result.status}`, "jl-err");
    status.textContent = `✗ ${result.status}`;
    log.setBusy(false);
  }
}

$$('#accessTable input[type=checkbox]:not([disabled])').forEach((box) => {
  box.addEventListener("change", () => { box.closest("tr").dataset.dirty = "1"; });
});
$("#accessSave").onclick = save;
