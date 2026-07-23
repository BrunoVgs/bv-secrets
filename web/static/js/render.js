/* Render registry.

   Each view registers its render function; actions call render() without knowing
   the views. Avoids cross-imports between views and actions. */
const renderers = [];

export function register(fn) {
  renderers.push(fn);
}

export function render() {
  renderers.forEach((fn) => fn());
}
