/* Tab state. Nothing persisted except the legend's localStorage. */
const BOOT = JSON.parse(document.getElementById("bv-boot").textContent);

export const CSRF = BOOT.csrf;
export const KINDS = BOOT.kinds;
export const GROUPS = BOOT.groups;
export const ROLES = BOOT.roles;

export const S = {
  secrets: BOOT.secrets,
  auto: BOOT.auto,
  byName: {},
  doctor: {},        // nom -> {ok, detail}, alimenté par les lignes de doctor
  revealed: {},      // nom -> valeur révélée, mémoire de l'onglet uniquement
  users: null,       // null tant que la vue Comptes n'a pas chargé
  audit: null,       // null tant que la vue Audit n'a pas chargé
  view: "overview",
  busy: false,
  search: "",
  kindFilter: "tous",
  selected: null,
  pendingKind: null,
  pendingGroup: null,
};

/* Index rebuilt on every resync: after a rotate the secret objects are replaced,
   a frozen index would keep the old lengths and dates. */
export function reindex() {
  S.byName = Object.fromEntries(S.secrets.map((s) => [s.name, s]));
}
reindex();

export function setSecrets(secrets, auto) {
  S.secrets = secrets;
  S.auto = auto || [];
  reindex();
}
