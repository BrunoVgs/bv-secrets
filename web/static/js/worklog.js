/* Worker console: live job log and UI lock. */
import { $, $$ } from "./dom.js";
import { S } from "./state.js";

const panel = $("#jobpanel");
const log = $("#joblog");
const status = $("#jobstatus");

export function open(title) {
  panel.classList.add("on");
  log.textContent = "";
  status.textContent = title || "";
}

export function close() {
  panel.classList.remove("on");
}

export function line(text, cls) {
  const div = document.createElement("div");
  if (cls) div.className = cls;
  div.textContent = text;
  log.appendChild(div);
  log.scrollTop = log.scrollHeight;
}

export function setStatus(text) {
  status.textContent = text;
}

export function setBusy(busy) {
  S.busy = busy;
  $$("[data-busy]").forEach((el) => { el.disabled = busy; });
}

$("#jobclose").onclick = close;
