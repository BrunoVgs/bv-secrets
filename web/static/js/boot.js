/* Entry point: load the views (each registers itself) and wire global actions. */
import { doctor, rotate } from "./actions.js";
import { openAdd } from "./addform.js";
import { logout } from "./api.js";
import { $ } from "./dom.js";
import { go } from "./router.js";
import { S } from "./state.js";
import { openUserForm } from "./userform.js";

import "./views/overview.js";
import "./views/vault.js";
import "./views/rotation.js";
import "./views/files.js";
import "./views/users.js";
import "./views/access.js";
import "./views/audit.js";

$("#rotauto").onclick = () => rotate(S.auto);
$("#doctor").onclick = doctor;
$("#addOpen").onclick = openAdd;
$("#userAdd").onclick = openUserForm;
$("#logout").onclick = async () => {
  await logout();
  location.reload();
};

go("overview");
