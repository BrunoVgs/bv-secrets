/* HTTP access. Every mutation goes through a job: the dashboard writes nothing. */
import { CSRF, S, setSecrets } from "./state.js";

async function json(url, options) {
  const response = await fetch(url, options);
  return { response, body: await response.json().catch(() => ({})) };
}

/* Resync the inventory after a job. On failure the current state is kept: the
   job log stays the displayed source of truth. */
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

/* Resync the adopted-file inventory. Same contract as refreshList: on failure the
   current state is kept rather than blanked. */
export async function refreshFiles() {
  try {
    const { body } = await json("api/files");
    if (body && body.files) S.files = body.files;
  } catch { /* état courant conservé */ }
}

/* Jobs carrying a value re-authenticate like reveal does. The dashboard password
   is not stored: it travels with this one request. */
async function postAuthed(url, payload) {
  const { response, body } = await json(url, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-CSRF": CSRF },
    body: JSON.stringify(payload),
  });
  if (!response.ok) throw new Error(body.error || `HTTP ${response.status}`);
  return body;
}

export const addSecret = (payload) => postAuthed("api/secret/add", payload);
export const createUser = (payload) => postAuthed("api/user/create", payload);

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
