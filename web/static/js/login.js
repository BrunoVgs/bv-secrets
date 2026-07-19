/* Page de login : second verrou applicatif devant le dashboard. */
const form = document.getElementById("loginForm");
const pw = document.getElementById("pw");
const err = document.getElementById("loginErr");

function fail(message) {
  err.textContent = message;
  form.classList.remove("shake");
  void form.offsetWidth;          // relance l'animation même sur deux échecs d'affilée
  form.classList.add("shake");
  pw.value = "";
  pw.focus();
}

form.onsubmit = async (ev) => {
  ev.preventDefault();
  err.textContent = "";
  form.classList.add("pending");
  let response;
  try {
    response = await fetch("api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password: pw.value }),
    });
  } catch {
    form.classList.remove("pending");
    fail("réseau indisponible");
    return;
  }
  form.classList.remove("pending");
  if (response.ok) location.reload();
  else fail("Mot de passe incorrect");
};
