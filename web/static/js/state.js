/* État de l'onglet. Rien n'est persisté hors localStorage de la légende. */
const BOOT = JSON.parse(document.getElementById("bv-boot").textContent);

export const CSRF = BOOT.csrf;
export const KINDS = BOOT.kinds;
export const GROUPS = BOOT.groups;

export const S = {
  secrets: BOOT.secrets,
  auto: BOOT.auto,
  byName: {},
  doctor: {},        // nom -> {ok, detail}, alimenté par les lignes de doctor
  revealed: {},      // nom -> valeur révélée, mémoire de l'onglet uniquement
  users: null,       // null tant que la vue Comptes n'a pas chargé
  view: "overview",
  busy: false,
  search: "",
  kindFilter: "tous",
  selected: null,
  pendingKind: null,
  pendingGroup: null,
};

/* L'index est reconstruit à chaque resync : après un rotate les objets secrets
   sont remplacés, un index figé garderait les anciennes longueurs et dates. */
export function reindex() {
  S.byName = Object.fromEntries(S.secrets.map((s) => [s.name, s]));
}
reindex();

export function setSecrets(secrets, auto) {
  S.secrets = secrets;
  S.auto = auto || [];
  reindex();
}
