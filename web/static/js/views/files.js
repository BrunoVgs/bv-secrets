/* Fichiers : où vivent les valeurs adoptées, et adoption d'un nouveau fichier.

   L'inventaire n'est pas un registre séparé : il est déduit des sinks déclarés
   dans secrets.conf, donc il ne peut pas diverger de la config.

   L'analyse et l'adoption passent par le worker : le conteneur web ne voit pas le
   disque de l'hôte, et c'est le worker qui applique l'allowlist de chemins. */
import { refreshFiles, refreshList } from "../api.js";
import { $, $$, bindAll, esc } from "../dom.js";
import { MODE_COLOR, MODE_HELP, MODE_LABEL } from "../labels.js";
import { openDrawer } from "../drawer.js";
import { startJob, watchJob } from "../jobs.js";
import { register, render } from "../render.js";
import { ADOPT_ROOTS, S } from "../state.js";
import { toast } from "../toast.js";
import * as log from "../worklog.js";

function fileRow(entry, index) {
  const names = entry.secrets.map((s) => s.name).join(", ");
  // Le sélecteur est l'emplacement exact dans le fichier : c'est lui qui répond à
  // « où vit cette valeur », pas seulement le chemin.
  const spots = entry.secrets
    .map((s) => `<span class="chip" title="${esc(s.name)} · ${esc(s.kind)}"
      data-open="${esc(s.name)}">${esc(s.selector || "fichier entier")}</span>`)
    .join(" ");
  return `<div class="row g-files" style="--i:${index}">
    <div class="cell"><div class="nm">${esc(entry.path)}</div>
      <div class="sv" title="${esc(names)}">${esc(names)}</div></div>
    <div><span class="tag cls" style="--c:${MODE_COLOR[entry.mode] || "#888"}"
      title="${esc(MODE_HELP[entry.mode] || "")} — sink ${esc(entry.scheme)}"
      >${esc(MODE_LABEL[entry.mode] || entry.mode)}</span></div>
    <div class="cell">${esc(entry.secrets.length)} secret${entry.secrets.length > 1 ? "s" : ""}
      ${entry.exists ? "" : '<span class="tag" title="declare dans la conf mais absent du disque">absent</span>'}
      ${entry.mode === "entier" || entry.in_scope ? "" : '<span class="tag" title="hors des racines adoptables : '
        + 'lisible ici, mais une nouvelle adoption y serait refusée">hors périmètre</span>'}</div>
    <div class="right">${spots}</div></div>`;
}

function propRow(proposal, index) {
  return `<div class="row g-prop" style="--i:${index}">
    <div><input type="checkbox" class="propc" data-key="${esc(proposal.key)}" checked></div>
    <div class="cell mono" style="font-size:12px">${esc(proposal.key)}</div>
    <div class="cell nm">${esc(proposal.name)}</div>
    <div><span class="tag">${esc(proposal.kind)}</span></div>
    <div><span class="tag">${esc(proposal.group)}</span></div>
    <div class="mono" style="font-size:11px;color:#a8a8a8">${proposal.len} c</div></div>`;
}

function planHtml(plan) {
  if (!plan.proposals.length) {
    return `<div class="empty">Aucun secret détecté dans ${esc(plan.file)}.</div>`;
  }
  const notes = [];
  if (plan.ignored.length) {
    notes.push(`<div class="cli">Ignorés (jugés config) : ${esc(plan.ignored.join(", "))}</div>`);
  }
  if (plan.conflicts.length) {
    notes.push(`<div class="warn">Noms déjà pris — utiliser un préfixe :
      ${esc(plan.conflicts.join(", "))}</div>`);
  }
  return `<div class="panel" style="margin-top:4px">
    <div class="ph"><span class="sq"></span><span class="t">PROPOSITIONS</span>
      <span class="cli">${esc(plan.file)}</span></div>
    <div class="row g-prop head"><div></div><div>CLÉ</div><div>SECRET</div>
      <div>FORMAT</div><div>ROTATION</div><div>LONG.</div></div>
    ${plan.proposals.map(propRow).join("")}
    <div class="pb" style="display:flex;gap:10px;align-items:center">
      <button class="btn big solid" id="adoptGo" data-busy>Adopter la sélection</button>
      <button class="btn" id="adoptCancel">Annuler</button>
      <span class="cli">Les valeurs sont lues en place et importées dans le store.</span>
    </div>
    ${notes.join("")}
  </div>`;
}

function renderFiles() {
  $("#adoptRoots").textContent = `racines adoptables : ${ADOPT_ROOTS.join(", ")}`;
  const files = S.files || [];
  $("#filesRows").innerHTML = files.length
    ? files.map(fileRow).join("")
    : '<div class="empty">Aucun fichier adopté. Analyser un fichier ci-dessus pour commencer.</div>';
  $("#filesCount").textContent = files.length
    ? `${files.length} fichier(s) · ${files.reduce((n, f) => n + f.secrets.length, 0)} secret(s)`
    : "";

  $("#adoptResult").innerHTML = S.adoptPlan ? planHtml(S.adoptPlan) : "";
  bindAll("data-open", openDrawer);
  if (!S.adoptPlan) return;
  const go = $("#adoptGo");
  if (go) go.onclick = runAdopt;
  const cancel = $("#adoptCancel");
  if (cancel) cancel.onclick = () => { S.adoptPlan = null; render(); };
}

/* Le plan est un job comme un autre : on attend son résultat plutôt que de lire un
   log, car ce sont les données structurées qui alimentent le tableau. */
async function runScan() {
  const file = $("#adoptPath").value.trim();
  if (!file.startsWith("/")) {
    toast("donner un chemin absolu");
    return;
  }
  S.adoptPlan = null;
  render();
  const job = await startJob("api/adopt/plan",
    { file, prefix: $("#adoptPrefix").value.trim() },
    { title: "analyse…", header: `# adopt --plan ${file}` });
  if (!job) return;
  const result = await watchJob(job.id, (line) => log.line(line));
  log.setBusy(false);
  if (result.status !== "done" || !result.data) {
    log.line(`✗ ${result.status}`, "jl-err");
    log.setStatus("✗ échec");
    return;
  }
  log.setStatus("✓ analysé");
  S.adoptPlan = result.data;
  render();
}

async function runAdopt() {
  const plan = S.adoptPlan;
  const only = $$(".propc").filter((c) => c.checked).map((c) => c.dataset.key);
  if (!only.length) {
    toast("aucune clé sélectionnée");
    return;
  }
  const job = await startJob("api/adopt/apply",
    { file: plan.file, only, prefix: $("#adoptPrefix").value.trim() },
    { title: "adoption…", header: `# adopt ${plan.file} (${only.length})` });
  if (!job) return;
  const result = await watchJob(job.id, (line) => log.line(line));
  const ok = result.status === "done";
  log.line(ok ? "✓ terminé" : `✗ ${result.status}`, ok ? "jl-done" : "jl-err");
  log.setStatus(ok ? "✓ terminé" : "✗ échec");
  log.setBusy(false);
  if (!ok) return;
  S.adoptPlan = null;
  await refreshList();
  await refreshFiles();
  render();
  toast(`✓ ${only.length} secret(s) adopté(s)`);
}

$("#adoptScan").onclick = runScan;
$("#adoptPath").onkeydown = (e) => {
  if (e.key === "Enter") {
    e.preventDefault();
    runScan();
  }
};

register(renderFiles);
