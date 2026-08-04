/* Ajout d'un secret : mot de passe généré, ou clé API saisie.

   Le formulaire refuse ce que le worker refuserait — un nom en API/TOKEN ne peut
   pas être généré, un format non générable exige une valeur. L'UI ne doit pas
   pouvoir produire un état qui sera rejeté après coup.

   L'ajout porte une valeur : il se ré-authentifie au mot de passe du dashboard,
   comme la révélation. */
import { addSecret, refreshFiles } from "./api.js";
import { $, esc } from "./dom.js";
import { finishJob } from "./jobs.js";
import { GRP_HELP, KIND_HELP } from "./labels.js";
import { register, render } from "./render.js";
import { GROUPS, KINDS, S, SINK_TYPES } from "./state.js";
import { toast } from "./toast.js";

const host = $("#addHost");
const APIKEY_RE = /(^|_)(API|TOKEN)(_|$)/;

/* Même règle que looks_like_apikey côté serveur : le nom décide. */
const isApiKey = (name) => APIKEY_RE.test(name.toUpperCase());

export function openAdd() {
  S.adding = { name: "", kind: "password", group: "app", sinks: [""], note: "", value: "" };
  render();
}

function close() {
  S.adding = null;
  render();
}

/* Les formats proposés dépendent du nom : une clé API n'est jamais générable, donc
   les formats générables disparaissent au lieu d'être proposés puis refusés. */
function kindsFor(name) {
  return isApiKey(name) ? KINDS.all.filter((k) => !KINDS.gen.includes(k)) : KINDS.all;
}

function problem(form) {
  if (!/^[A-Z][A-Z0-9_]*$/.test(form.name)) {
    return "Nom : majuscules, chiffres et _ (commençant par une lettre).";
  }
  if (S.byName[form.name]) return `${form.name} existe déjà.`;
  if (form.kind === "apikey" && !isApiKey(form.name)) {
    return "Le format « apikey » exige API ou TOKEN dans le nom.";
  }
  const sinks = form.sinks.map((s) => s.trim()).filter(Boolean);
  if (!sinks.length) return "Donner au moins un sink.";
  const bad = sinks.find((s) => !SINK_TYPES.includes(s.split(":", 1)[0]));
  if (bad) return `Sink invalide : ${bad}`;
  if (!form.value && !KINDS.gen.includes(form.kind)) {
    return `Le format ${form.kind} n'est pas générable : saisir une valeur.`;
  }
  return null;
}

function sinkRows(sinks) {
  return sinks.map((value, i) => `<div class="bar" style="gap:6px">
    <input class="search" data-sink="${i}" style="flex:1" value="${esc(value)}"
      placeholder="env:service#VAR, envfile:/chemin/.env#CLE, mysql:user@conteneur…">
    ${sinks.length > 1 ? `<button class="btn" data-delsink="${i}">✕</button>` : ""}
  </div>`).join("");
}

function renderAdd() {
  const form = S.adding;
  if (!form) {
    host.innerHTML = "";
    return;
  }
  const apikey = isApiKey(form.name);
  const generable = KINDS.gen.includes(form.kind);
  const err = problem(form);

  host.innerHTML = `<div id="scrim"></div><aside id="drawer">
    <div class="dh"><div style="flex:1;min-width:0">
      <div class="dn">Nouveau secret</div>
      <div class="ds">Déclaré dans secrets.conf, valeur écrite dans le store.</div>
    </div><button class="btn" id="aclose">✕</button></div>

    <div class="sec" style="--i:0"><div class="lb">NOM</div>
      <input class="search" id="aname" value="${esc(form.name)}" spellcheck="false"
        placeholder="MON_SERVICE_PASSWORD" style="width:100%">
      ${apikey ? '<div class="warn">Nom en API/TOKEN : traité comme une clé émise par '
        + "une app tierce. Elle ne peut pas être générée ici — coller la valeur "
        + "produite par l'app.</div>" : ""}
    </div>

    <div class="sec" style="--i:1"><div class="lb">FORMAT · ROTATION</div>
      <div class="edit">
        <select id="akind" title="${esc(KIND_HELP[form.kind] || "")}">
          ${kindsFor(form.name).map((k) => `<option value="${k}"${
            k === form.kind ? " selected" : ""}>${k}</option>`).join("")}</select>
        <select id="agroup" title="${esc(GRP_HELP[form.group] || "")}">
          ${GROUPS.map((g) => `<option value="${g}"${
            g === form.group ? " selected" : ""}>${g}</option>`).join("")}</select>
      </div>
      <div class="cli">${esc(KIND_HELP[form.kind] || "")} · ${esc(GRP_HELP[form.group] || "")}</div>
    </div>

    <div class="sec" style="--i:2"><div class="lb">VALEUR</div>
      <input type="password" id="avalue" class="search" style="width:100%"
        autocomplete="new-password" value="${esc(form.value)}"
        placeholder="${generable ? "laisser vide pour générer" : "valeur (obligatoire)"}">
      ${generable ? '<div class="cli">Vide = le worker génère une valeur du format choisi.</div>' : ""}
    </div>

    <div class="sec" style="--i:3"><div class="lb">SINKS · OÙ LA VALEUR DOIT VIVRE</div>
      ${sinkRows(form.sinks)}
      <button class="btn" id="asinkadd" style="margin-top:6px">+ sink</button>
      <div class="cli">Types acceptés : ${esc(SINK_TYPES.join(", "))}</div>
    </div>

    <div class="sec" style="--i:4"><div class="lb">NOTE</div>
      <input class="search" id="anote" style="width:100%" value="${esc(form.note)}"
        placeholder="à quoi sert ce secret"></div>

    <div class="sec" style="--i:5"><div class="lb">CONFIRMER</div>
      <input type="password" id="apw" class="search" style="width:100%"
        autocomplete="current-password" placeholder="mot de passe du dashboard">
      ${err ? `<div class="warn">${esc(err)}</div>` : ""}
      <div class="bar" style="margin-top:8px">
        <button class="btn big solid" id="asave" data-busy${err ? " disabled" : ""}>
          Créer le secret</button>
        <span class="cli" id="astatus"></span>
      </div>
    </div>
  </aside>`;

  wire(form);
}

function wire(form) {
  const keep = (id, key) => {
    const el = $(id);
    if (!el) return;
    el.oninput = () => { form[key] = el.value; render(); };
  };
  $("#scrim").onclick = close;
  $("#aclose").onclick = close;
  keep("#aname", "name");
  keep("#avalue", "value");
  keep("#anote", "note");
  $("#akind").onchange = (e) => { form.kind = e.target.value; render(); };
  $("#agroup").onchange = (e) => { form.group = e.target.value; render(); };
  $("#asinkadd").onclick = () => { form.sinks.push(""); render(); };
  document.querySelectorAll("[data-sink]").forEach((el) => {
    el.oninput = () => { form.sinks[Number(el.dataset.sink)] = el.value; };
  });
  document.querySelectorAll("[data-delsink]").forEach((el) => {
    el.onclick = () => {
      form.sinks.splice(Number(el.dataset.delsink), 1);
      render();
    };
  });
  const save = $("#asave");
  if (save) save.onclick = () => submit(form);
}

async function submit(form) {
  const password = $("#apw").value;
  if (!password) {
    $("#astatus").textContent = "mot de passe requis";
    return;
  }
  let job;
  try {
    job = await addSecret({
      name: form.name,
      kind: form.kind,
      group: form.group,
      sinks: form.sinks.map((s) => s.trim()).filter(Boolean),
      note: form.note,
      value: form.value,
      password,
    });
  } catch (e) {
    $("#astatus").textContent = `refusé : ${e.message}`;
    return;
  }
  const name = form.name;
  close();
  // La valeur a quitté le navigateur : la suite est un job comme un autre.
  await finishJob(job.id, {
    onDone: async () => {
      await refreshFiles();
      render();
      toast(`✓ ${name} créé`);
    },
  });
}

document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && S.adding) close();
});

register(renderAdd);
