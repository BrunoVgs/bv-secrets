/* Navigation entre les vues. */
import { $, $$ } from "./dom.js";
import { VIEW_TITLES } from "./labels.js";
import { render } from "./render.js";
import { S } from "./state.js";
import { loadUsers } from "./views/users.js";

export function go(view) {
  S.view = view;
  S.selected = null;
  $$(".nav").forEach((n) => n.classList.toggle("on", n.dataset.view === view));
  $$(".view").forEach((section) => {
    section.classList.toggle("hidden", section.dataset.view !== view);
  });
  const [title, sub] = VIEW_TITLES[view];
  $("#viewTitle").textContent = title;
  $("#viewSub").textContent = sub;
  $("#viewSub").classList.toggle("hidden", !sub);
  render();
  if (view === "comptes" && S.users === null) loadUsers();
}

$$(".nav").forEach((nav) => { nav.onclick = () => go(nav.dataset.view); });
