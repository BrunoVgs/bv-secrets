/* Page de login : second verrou applicatif devant le dashboard.

   Au succès on ne recharge pas immédiatement : les champs s'effacent, les
   anneaux tournent autour du logo, et le dashboard se charge dans une iframe
   hors écran. Le cache est donc chaud au moment du rechargement, ce qui évite
   l'écran vide puis le re-rendu. */
const form = document.getElementById("loginForm");
const pw = document.getElementById("pw");
const err = document.getElementById("loginErr");

const HOLD_MS = 1000;      // durée minimale des anneaux
const PRELOAD_CAP = 4000;  // au-delà, on recharge sans attendre la fin
const SETTLE_MS = 1000;    // laisse le dashboard finir de se peindre

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function fail(message) {
  err.textContent = message;
  form.classList.remove("shake");
  void form.offsetWidth;          // relance l'animation même sur deux échecs d'affilée
  form.classList.add("shake");
  pw.value = "";
  pw.focus();
}

/* Preload the destination off-screen. Resolves on load or a cap, whichever first:
   a slow page must not block entry. */
function preload(url) {
  return new Promise((resolve) => {
    let done = false;
    const finish = () => { if (!done) { done = true; resolve(); } };
    const frame = document.createElement("iframe");
    frame.setAttribute("aria-hidden", "true");
    frame.tabIndex = -1;
    frame.style.cssText =
      "position:fixed;width:1px;height:1px;opacity:0;border:0;" +
      "left:-9999px;top:-9999px;pointer-events:none";
    frame.addEventListener("load", finish);
    frame.addEventListener("error", finish);
    document.body.appendChild(frame);
    frame.src = url;
    setTimeout(finish, PRELOAD_CAP);
  });
}

form.onsubmit = async (ev) => {
  ev.preventDefault();
  err.textContent = "";
  form.classList.add("pending");

  const held = sleep(HOLD_MS);
  let response;
  try {
    response = await fetch("api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password: pw.value }),
    });
  } catch {
    await held;
    form.classList.remove("pending");
    fail("réseau indisponible");
    return;
  }

  if (!response.ok) {
    await held;
    form.classList.remove("pending");
    fail("Mot de passe incorrect");
    return;
  }

  // Session open: the dashboard is now preloadable.
  await Promise.all([held, preload(location.href)]);
  await sleep(SETTLE_MS);
  location.reload();
};
