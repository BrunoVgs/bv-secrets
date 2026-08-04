/* Labels and contextual help — one place to fix the vocabulary. */

export const GRP_COLOR = { auto: "#3fbf5f", app: "#d9a13b", careful: "#d63a42", manual: "#8b8b8b" };
export const GRP_LABEL = { auto: "auto", app: "si nommé", careful: "si nommé ⚠", manual: "jamais" };
export const GRP_HELP = {
  auto: "rotée par « Roter le groupe auto »",
  app: "rotée seulement si elle est ciblée",
  careful: "rotée seulement si elle est ciblée — impactant",
  manual: "jamais rotée automatiquement",
};

/* Deux axes SEPARES, jamais fusionnes.
   OBJ  : a qui appartient la valeur -> mon mot de passe, ou la cle d'une app tierce.
          C'est ce qui decide si on peut la regenerer. Rouge / jaune.
   ROT  : quand elle est regeneree. Sa propre colonne, sa propre couleur.
   Les melanger disait deux fois la meme chose et cachait la vraie question. */
export const OBJ_ORDER = ["password", "token", "computed"];
export const OBJ_COLOR = { password: "#d63a42", token: "#d9a13b", computed: "#8fbaff" };
export const OBJ_LABEL = {
  password: "mot de passe", token: "clé API / token", computed: "calculé",
};
export const OBJ_HELP = {
  password: "le tien : générable et rotable ici",
  token: "émis par l'app tierce : la régénérer dedans, puis « set »",
  computed: "dérivé d'autres secrets, jamais stocké",
};

export const ROT_ORDER = ["auto", "ondemand", "never"];
export const ROT_COLOR = { auto: "#3fbf5f", ondemand: "#c86fd0", never: "#8b8b8b" };
export const ROT_LABEL = { auto: "auto", ondemand: "sur demande", never: "jamais" };
export const ROT_HELP = {
  auto: "roté par « Roter le groupe auto », sans avoir à le nommer",
  ondemand: "roté seulement si explicitement ciblé",
  never: "jamais roté d'ici",
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

// ROLES now comes from the boot payload (state.js), not hardcoded here.

export const VIEW_TITLES = {
  overview: ["Vue d'ensemble", ""],
  coffre: ["Coffre", "Consulter et copier. La rotation se fait dans l'onglet Rotation."],
  rotation: ["Rotation", ""],
  fichiers: ["Fichiers", "Où vivent les valeurs adoptées, et comment en adopter d'autres."],
  comptes: ["Comptes", ""],
  acces: ["Accès & rôles", ""],
  audit: ["Audit", "Qui a atteint quoi, quand, d'où, et ce qui a changé."],
  docs: ["Docs", ""],
};

/* Comment bv-secrets ecrit dans un fichier gere. Une seule distinction, parce
   qu'une seule change quelque chose a l'usage : soit il fabrique le fichier en
   entier, soit il n'y touche qu'une cle et laisse le reste byte pour byte. */
export const MODE_COLOR = { entier: "#8fbaff", cle: "#3fbf5f" };
export const MODE_LABEL = { entier: "fichier entier", cle: "clé par clé" };
export const MODE_HELP = {
  entier: "bv-secrets fabrique tout le fichier",
  cle: "une seule valeur est réécrite, le reste du fichier ne bouge pas",
};
