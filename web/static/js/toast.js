/* Notification brève. Un seul toast à l'écran : le précédent est remplacé. */
import { $ } from "./dom.js";

let timer;

export function toast(message) {
  $("#toast")?.remove();
  const el = document.createElement("div");
  el.id = "toast";
  el.textContent = message;
  document.body.appendChild(el);
  clearTimeout(timer);
  timer = setTimeout(() => el.remove(), 2400);
}
