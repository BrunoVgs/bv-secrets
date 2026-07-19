/* Cycle de vie d'un job : dépôt, suivi du log en direct, resynchronisation.

   Les cinq actions (rotate, doctor, comptes, format, accès) partagent cette
   logique de streaming et de timeout — un correctif ici porte partout. */
import { fetchJob, postJob, refreshList } from "./api.js";
import { render } from "./render.js";
import { S } from "./state.js";
import * as log from "./worklog.js";

const POLL_MS = 1000;
const MAX_TICKS = 300;                  // 5 minutes
const PENDING = new Set(["queued", "pending", "running"]);

/* Résout avec le résultat final. onLine reçoit chaque nouvelle ligne : le worker
   réécrit son résultat pendant l'exécution, seul le delta est émis. */
export function watchJob(id, onLine) {
  return new Promise((resolve) => {
    let ticks = 0;
    let shown = 0;
    const timer = setInterval(async () => {
      if (++ticks > MAX_TICKS) {
        clearInterval(timer);
        resolve({ status: "timeout", log: [] });
        return;
      }
      let result;
      try {
        result = await fetchJob(id);
      } catch {
        return;                          // coupure réseau : on retente au tick suivant
      }
      const lines = result.log || [];
      for (; shown < lines.length; shown++) onLine(lines[shown]);
      if (PENDING.has(result.status)) {
        log.setStatus(result.status === "running"
          ? `en cours — ${lines.length} étape${lines.length > 1 ? "s" : ""}`
          : "en attente du worker…");
        return;
      }
      clearInterval(timer);
      resolve(result);
    }, POLL_MS);
  });
}

/* Fin d'un job touchant aux secrets : log, statut, puis resync AVANT le rendu —
   redessiner d'abord réafficherait l'état précédent. */
export async function finishJob(id, { onLine, onDone } = {}) {
  const result = await watchJob(id, (l) => {
    log.line(l);
    onLine?.(l);
  });
  const ok = result.status === "done";
  log.line(ok ? "✓ terminé" : `✗ ${result.status}`, ok ? "jl-done" : "jl-err");
  log.setStatus(ok ? "✓ terminé" : "✗ échec");
  log.setBusy(false);
  await refreshList();
  render();
  if (ok && onDone) setTimeout(onDone, 900);
  return result;
}

/* Dépose un job et branche la console. Renvoie null si le dépôt est refusé.
   `silent` sert aux chargements de fond, qui ne doivent pas ouvrir la console. */
export async function startJob(url, payload, { title, header, silent } = {}) {
  if (S.busy) return null;
  log.setBusy(true);
  if (!silent) {
    log.open(title);
    if (header) log.line(header, "jl-run");
  }
  try {
    return await postJob(url, payload);
  } catch (e) {
    if (!silent) {
      log.line(`refusé: ${e.message}`, "jl-err");
      log.setStatus("refusé");
    }
    log.setBusy(false);
    return null;
  }
}
