/* Labels and contextual help — one place to fix the vocabulary. */

export const GRP_COLOR = { auto: "#3fbf5f", app: "#d9a13b", careful: "#d63a42", manual: "#8b8b8b" };
export const GRP_LABEL = { auto: "auto", app: "si nommé", careful: "si nommé ⚠", manual: "jamais" };
export const GRP_HELP = {
  auto: "rotée par « Roter le groupe auto »",
  app: "rotée seulement si elle est ciblée",
  careful: "rotée seulement si elle est ciblée — impactant",
  manual: "jamais rotée automatiquement",
};

export const KIND_HELP = {
  apikey: "clé émise par une app tierce — JAMAIS générée : la régénérer dans l'app puis `set`",
  password: "mot de passe aléatoire",
  hex: "chaîne hexadécimale aléatoire",
  b64: "chaîne base64 aléatoire",
  passphrase: "longue suite alphanumérique",
  userpass: "paire user:motdepasse",
  opaque: "posée à la main (seed, littéral) — jamais générée",
  computed: "dérivée d'autres secrets, jamais stockée",
};

export const VIEW_TITLES = {
  overview: ["Vue d'ensemble", ""],
  coffre: ["Coffre", "Consulter et copier. La rotation se fait dans l'onglet Rotation."],
  rotation: ["Rotation", ""],
  comptes: ["Comptes", ""],
  acces: ["Accès & rôles", ""],
  audit: ["Audit", "Qui a atteint quoi, quand, d'où, et ce qui a changé."],
  docs: ["Docs", ""],
};

export const ROLES = ["guest", "trusted", "admin"];
