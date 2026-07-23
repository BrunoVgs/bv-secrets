/* Shared DOM helpers. */
export const $ = (sel, root = document) => root.querySelector(sel);
export const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

export const esc = (s) => String(s).replace(/[&<>"]/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

/* Bind a handler to each element carrying the attribute, stopping propagation:
   table rows are themselves clickable. */
export function bindAll(attr, handler) {
  $$(`[${attr}]`).forEach((el) => {
    el.onclick = (ev) => {
      ev.stopPropagation();
      handler(el.getAttribute(attr), el, ev);
    };
  });
}
