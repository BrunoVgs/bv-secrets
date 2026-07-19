/* Accès HTTP. Toutes les mutations passent par un job : le dashboard n'écrit rien. */
import { CSRF, setSecrets } from "./state.js";

async function json(url, options) {
  const response = await fetch(url, options);
  return { response, body: await response.json().catch(() => ({})) };
}

/* Resynchronise l'inventaire après un job. En cas d'échec l'état courant est
   conservé : le log du job reste la source de vérité affichée. */
export async function refreshList() {
  try {
    const { body } = await json("api/list");
    if (body && body.secrets) setSecrets(body.secrets, body.auto);
  } catch { /* état courant conservé */ }
}

export async function postJob(url, payload) {
  const options = { method: "POST", headers: { "X-CSRF": CSRF } };
  if (payload) {
    options.headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(payload);
  }
  let result;
  try {
    result = await json(url, options);
  } catch (e) {
    throw new Error(`réseau: ${e.message}`);
  }
  if (!result.response.ok || !result.body.id) {
    throw new Error(result.body.error || `HTTP ${result.response.status}`);
  }
  return result.body;
}

export function fetchJob(id) {
  return fetch(`api/jobs/${id}`).then((r) => r.json());
}

export async function reveal(name, password) {
  const { response, body } = await json("api/reveal", {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-CSRF": CSRF },
    body: JSON.stringify({ name, password }),
  });
  if (!response.ok) return null;
  return body.value == null ? "" : body.value;
}

export function logout() {
  return fetch("api/logout", { method: "POST", headers: { "X-CSRF": CSRF } });
}
