/* Page de login : second verrou applicatif devant le dashboard.

   Pendant l'attente, les huit orbes du fond CONVERGENT vers le centre en
   laissant leurs traînées s'enrouler derrière le sigle. L'effet d'attente est
   donc le décor lui-même, pas un anneau posé par-dessus.

   Au succès on ne recharge pas immédiatement : le dashboard se charge dans une
   iframe hors écran, donc le cache est chaud au moment du rechargement, ce qui
   évite l'écran vide puis le re-rendu. Un échec renvoie les orbes sur leur
   orbite : le décor revient exactement à son état d'avant. */
const form = document.getElementById("loginForm");
const fx = document.getElementById("loginfx");
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
  // `?.` : sans WebGL (ou CDN injoignable) le composant reste vide et n'expose
  // aucune methode. La page doit rester utilisable sans le decor.
  fx?.converge?.();

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
    fx?.expand?.();
    fail("réseau indisponible");
    return;
  }

  if (!response.ok) {
    await held;
    form.classList.remove("pending");
    fx?.expand?.();
    fail("Mot de passe incorrect");
    return;
  }

  // Session open: the dashboard is now preloadable.
  await Promise.all([held, preload(location.href)]);
  await sleep(SETTLE_MS);
  location.reload();
};
