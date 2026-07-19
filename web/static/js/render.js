/* Registre de rendu.

   Chaque vue enregistre sa fonction de rendu ; les actions appellent render()
   sans connaître les vues. Évite les imports croisés entre vues et actions. */
const renderers = [];

export function register(fn) {
  renderers.push(fn);
}

export function render() {
  renderers.forEach((fn) => fn());
}
