/* Helpers DOM partagés. */
export const $ = (sel, root = document) => root.querySelector(sel);
export const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

export const esc = (s) => String(s).replace(/[&<>"]/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

/* Attache un handler à chaque élément portant l'attribut, en coupant la
   propagation : les lignes de tableau sont elles-mêmes cliquables. */
export function bindAll(attr, handler) {
  $$(`[${attr}]`).forEach((el) => {
    el.onclick = (ev) => {
      ev.stopPropagation();
      handler(el.getAttribute(attr), el, ev);
    };
  });
}
