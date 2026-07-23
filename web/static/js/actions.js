/* Secret actions: rotate and doctor. All go through the spool. */
import { finishJob, startJob } from "./jobs.js";
import { S } from "./state.js";
import * as log from "./worklog.js";

/* Doctor prints "✓ NAME detail (dernier set: …)"; each row's dot is updated as the
   log streams rather than at the end. */
const DOCTOR_LINE = /^([✓✗·])\s+(\S+)\s+(.*?)\s+\(dernier set: (.*)\)$/;

function applyDoctorLine(line) {
  const m = line.match(DOCTOR_LINE);
  if (!m || m[1] === "·") return;            // "·" = aucune probe déclarée
  S.doctor[m[2]] = { ok: m[1] === "✓", detail: m[3] };
}

export async function rotate(names) {
  if (S.busy || !names.length) return;
  if (!confirm(`Roter :\n\n${names.join(", ")}\n\n`
    + "Régénère, applique et redémarre les services concernés.")) return;

  const job = await startJob("api/rotate", { only: names },
    { title: "envoi…", header: `# rotate ${names.join(", ")}` });
  if (!job) return;
  if (job.rejected?.length) log.line(`rejetés: ${job.rejected.join(", ")}`, "jl-err");
  log.line(`job ${job.id}…`, "jl-run");
  await finishJob(job.id);
}

export async function doctor() {
  const job = await startJob("api/doctor", null, { title: "vérification…", header: "# doctor" });
  if (!job) return;
  log.line(`job ${job.id}…`, "jl-run");
  await finishJob(job.id, { onLine: applyDoctorLine });
}
