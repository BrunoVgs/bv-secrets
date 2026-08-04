/* Tri des colonnes.

   Clic simple : la colonne devient le critère PRIMAIRE, un second clic l'inverse.
   Maj+clic : ajoute un critère secondaire, puis l'inverse, puis le retire.

   Le critère primaire doit primer : `name` étant unique par secret, le laisser en
   tête rendait tout critère ajouté après lui sans effet visible. */
import { $, $$ } from "./dom.js";
import { OBJ_ORDER } from "./labels.js";

const GRP_RANK = { auto: 0, app: 1, careful: 2, manual: 3 };

export const SORT = {
  coffre: [{ key: "name", dir: 1 }],
  rotation: [{ key: "name", dir: 1 }],
};

function sortValue(secret, key) {
  switch (key) {
    case "name": return secret.name.toLowerCase();
    case "kind": return `${OBJ_ORDER.indexOf(secret.obj)} ${secret.kind}`;  // par objet
    case "group": return GRP_RANK[secret.group] ?? 9;
    case "value": return (secret.present ? 1 : 0) * 100000 + (secret.len || 0);
    case "last": return secret.last_set || "";        // "AAAA-MM-JJ hh:mm" -> ordre chrono
    default: return "";
  }
}

export function sortRows(list, which) {
  const keys = SORT[which];
  return list.slice().sort((a, b) => {
    for (const { key, dir } of keys) {
      const x = sortValue(a, key);
      const y = sortValue(b, key);
      if (x < y) return -dir;
      if (x > y) return dir;
    }
    return a.name.localeCompare(b.name);             // départage stable
  });
}

function toggle(keys, col, additive) {
  const i = keys.findIndex((k) => k.key === col);
  if (!additive) {
    // column already sole and primary: flip it; otherwise it becomes the only key
    if (i === 0 && keys.length === 1) keys[0].dir = -keys[0].dir;
    else keys.splice(0, keys.length, { key: col, dir: 1 });
    return;
  }
  if (i < 0) keys.push({ key: col, dir: 1 });
  else if (keys[i].dir === 1) keys[i].dir = -1;
  else keys.splice(i, 1);
  if (!keys.length) keys.push({ key: "name", dir: 1 });
}

export function paintHead(selector, which) {
  const keys = SORT[which];
  $$(`${selector} .srt`).forEach((head) => {
    const i = keys.findIndex((k) => k.key === head.dataset.sort);
    head.classList.toggle("on", i >= 0);
    // rank only matters once two keys are active
    $(".ar", head).textContent = i < 0
      ? "↕"
      : (keys[i].dir === 1 ? "▲" : "▼") + (keys.length > 1 ? i + 1 : "");
  });
}

export function bindSort(selector, which, redraw) {
  $$(`${selector} .srt`).forEach((head) => {
    head.onclick = (ev) => {
      toggle(SORT[which], head.dataset.sort, ev.shiftKey);
      redraw();
    };
  });
}
