/* Mise en forme des valeurs affichées. */
import { S } from "./state.js";

/* "2026-07-14 09:12" -> "il y a 4 j" */
export function rel(ts) {
  if (!ts) return "jamais";
  const d = new Date(ts.replace(" ", "T"));
  if (isNaN(d)) return ts;
  const min = Math.floor((Date.now() - d.getTime()) / 60000);
  if (min < 1) return "à l'instant";
  if (min < 60) return `il y a ${min} min`;
  const h = Math.floor(min / 60);
  if (h < 24) return `il y a ${h} h`;
  const j = Math.floor(h / 24);
  if (j < 31) return `il y a ${j} j`;
  const mo = Math.floor(j / 30.44);
  if (mo < 12) return `il y a ${mo} mois`;
  const a = Math.floor(j / 365.25);
  return `il y a ${a} an${a > 1 ? "s" : ""}`;
}

/* Couleur de la pastille d'état : résultat du dernier doctor s'il existe,
   sinon simple présence de la valeur en store. */
export function dotColor(secret) {
  const probe = S.doctor[secret.name];
  if (probe) return probe.ok ? "#3fbf5f" : "#d63a42";
  if (!secret.present) return "#d9a13b";
  return "rgba(255,255,255,.18)";
}
