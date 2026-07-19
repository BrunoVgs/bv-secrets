/* Point d'entrée : charge les vues (chacune s'enregistre au rendu) et câble les
   actions globales. */
import { doctor, rotate } from "./actions.js";
import { logout } from "./api.js";
import { $ } from "./dom.js";
import { go } from "./router.js";
import { S } from "./state.js";

import "./views/overview.js";
import "./views/vault.js";
import "./views/rotation.js";
import "./views/users.js";
import "./views/access.js";

$("#rotauto").onclick = () => rotate(S.auto);
$("#doctor").onclick = doctor;
$("#logout").onclick = async () => {
  await logout();
  location.reload();
};

go("overview");
