import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from bvsecrets import conf_yaml, migrate
from bvsecrets.config import ConfigError

ROOT = Path(__file__).resolve().parent.parent

SAMPLE = """\
# en-tete
x-apikey: &apikey { kind: apikey, group: manual }
x-pass: &pass
  kind: password
  group: auto
  length: 20

secrets:

  PIHOLE_ADMIN_PASSWORD:
    <<: *pass
    length: 14
    sinks:
      - env:pihole#FTLCONF_webserver_api_password
      - env:homepage#HOMEPAGE_VAR_PIHOLE_KEY
    note: mdp/API Pi-hole

  JELLYFIN_API_KEY:
    <<: *apikey
    sinks:
      - env:homepage#HOMEPAGE_VAR_JELLYFIN_KEY

  DB_URL:
    kind: computed
    group: manual
    compute: raw mysql://u:{DB_PASSWORD}@mariadb:3306/db
    norestart:
      - mariadb
"""


def _load(text, name="secrets.yaml", extra=None):
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / name
        p.write_text(text, encoding="utf-8")
        for fname, body in (extra or {}).items():
            (Path(d) / fname).write_text(body, encoding="utf-8")
        return conf_yaml.load(p)


class TestReader(unittest.TestCase):
    def test_template_fills_the_gaps(self):
        cfg = _load(SAMPLE)
        self.assertEqual(cfg["PIHOLE_ADMIN_PASSWORD"]["kind"], "password")
        self.assertEqual(cfg["PIHOLE_ADMIN_PASSWORD"]["group"], "auto")

    def test_the_secret_own_key_beats_the_template(self):
        # length: 20 dans le gabarit, 14 dans le secret
        self.assertEqual(_load(SAMPLE)["PIHOLE_ADMIN_PASSWORD"]["length"], 14)

    def test_a_sink_selector_survives_comment_stripping(self):
        """Un sink porte un `#` colle. Le retirer comme un commentaire couperait
        la moitie droite et la valeur serait poussee dans le vide."""
        sinks = _load(SAMPLE)["PIHOLE_ADMIN_PASSWORD"]["sinks"]
        self.assertEqual(sinks[0], "env:pihole#FTLCONF_webserver_api_password")
        self.assertEqual(len(sinks), 2)

    def test_a_list_stops_at_the_next_secret(self):
        cfg = _load(SAMPLE)
        self.assertEqual(len(cfg["PIHOLE_ADMIN_PASSWORD"]["sinks"]), 2)
        self.assertEqual(cfg["JELLYFIN_API_KEY"]["sinks"],
                         ["env:homepage#HOMEPAGE_VAR_JELLYFIN_KEY"])

    def test_block_style_template_works_like_the_flow_one(self):
        self.assertEqual(_load(SAMPLE)["JELLYFIN_API_KEY"]["kind"], "apikey")

    def test_defaults_match_the_ini_reader(self):
        cfg = _load(SAMPLE)
        self.assertEqual(cfg["JELLYFIN_API_KEY"]["length"], 0)
        self.assertEqual(cfg["JELLYFIN_API_KEY"]["note"], "")
        self.assertEqual(cfg["JELLYFIN_API_KEY"]["norestart"], [])

    def test_include_merges_another_file(self):
        cfg = _load("include:\n  - extra.yaml\n\nsecrets:\n  A:\n    kind: hex\n",
                    extra={"extra.yaml": "secrets:\n  B:\n    kind: b64\n"})
        self.assertEqual(sorted(cfg), ["A", "B"])

    def test_a_name_declared_twice_is_refused(self):
        with self.assertRaises(ConfigError) as cm:
            _load("include:\n  - extra.yaml\n\nsecrets:\n  A:\n    kind: hex\n",
                  extra={"extra.yaml": "secrets:\n  A:\n    kind: b64\n"})
        self.assertIn("deux fois", str(cm.exception))

    def test_an_unknown_template_names_the_secret(self):
        with self.assertRaises(ConfigError) as cm:
            _load("secrets:\n  A:\n    <<: *absent\n")
        self.assertIn("A", str(cm.exception))

    def test_an_unknown_top_level_key_is_refused(self):
        """La liste des cles racine est fermee : une faute de frappe doit se voir
        ici, pas se traduire par une regle silencieusement absente."""
        with self.assertRaises(ConfigError) as cm:
            _load("egres:\n  zone:\n    subnet: 10.0.0.0/8\n")
        self.assertIn("egres", str(cm.exception))

    def test_the_host_keys_are_accepted(self):
        doc = conf_yaml.parse(
            "egress:\n  console:\n    subnet: 172.22.0.0/16\n"
            "    block: [192.168.0.0/16, 10.0.0.0/8]\n"
            "audit:\n  elevation:\n    trace: [sudo, doas]\n"
            "secrets:\n  A:\n    kind: hex\n")
        self.assertEqual(doc["host"]["egress"]["console"]["subnet"], "172.22.0.0/16")
        self.assertEqual(doc["host"]["egress"]["console"]["block"],
                         ["192.168.0.0/16", "10.0.0.0/8"])
        self.assertEqual(doc["host"]["audit"]["elevation"]["trace"], ["sudo", "doas"])
        self.assertEqual(sorted(doc["secrets"]), ["A"])

    def test_tabs_are_named_rather_than_silently_wrong(self):
        with self.assertRaises(ConfigError) as cm:
            _load("secrets:\n\tA:\n\t  kind: hex\n")
        self.assertIn("tabulation", str(cm.exception))

    def test_an_escaped_note_round_trips(self):
        cfg = _load('secrets:\n  A:\n    kind: hex\n    note: "deux\\nlignes"\n')
        self.assertEqual(cfg["A"]["note"], "deux\nlignes")


class TestMigration(unittest.TestCase):
    INI = """\
[PIHOLE_ADMIN_PASSWORD]
kind  = password
group = auto
length = 14
sinks =
    env:pihole#FTLCONF_webserver_api_password
note  = mdp/API Pi-hole

[JELLYFIN_API_KEY]
kind  = apikey
group = manual
sinks =
    env:homepage#HOMEPAGE_VAR_JELLYFIN_KEY
"""

    def _ini_cfg(self):
        import configparser
        cp = configparser.ConfigParser(interpolation=None)
        cp.optionxform = str
        cp.read_string(self.INI)
        out = {}
        for n in cp.sections():
            s = cp[n]
            out[n] = {
                "kind": s.get("kind", "manual").strip(),
                "length": int((s.get("length", "") or "0").strip() or 0),
                "group": s.get("group", "manual").strip(),
                "sinks": [x.strip() for x in s.get("sinks", "").splitlines() if x.strip()],
                "norestart": [], "compute": "", "probe": "", "validate": "",
                "note": s.get("note", "").strip(),
            }
        return out

    def test_conversion_round_trips(self):
        cfg = self._ini_cfg()
        text = migrate.convert(cfg)            # leve si un champ bouge
        self.assertEqual(migrate.equivalent(cfg, _load(text)), [])

    def test_a_lost_field_aborts_instead_of_writing(self):
        cfg = self._ini_cfg()
        original = migrate.render

        def lossy(c, header=""):
            out = original(c, header)
            return out.replace("    note: mdp/API Pi-hole\n", "")
        migrate.render = lossy
        try:
            with self.assertRaises(ConfigError) as cm:
                migrate.convert(cfg)
            self.assertIn("note", str(cm.exception))
        finally:
            migrate.render = original

    def test_templates_need_three_uses(self):
        cfg = {f"S{i}": {"kind": "hex", "group": "auto", "length": 32, "sinks": [],
                         "norestart": [], "compute": "", "probe": "", "validate": "",
                         "note": ""} for i in range(3)}
        self.assertEqual(len(migrate.plan_templates(cfg)), 1)
        del cfg["S2"]
        self.assertEqual(migrate.plan_templates(cfg), {})


class TestShippedTemplate(unittest.TestCase):
    """Le modele livre par `init` est la premiere chose que voit un inconnu : il
    doit se relire sans surprise, y compris ses cas tordus (probe pleine de
    guillemets et de JSON, note multi-lignes, sink cmd avec des quotes)."""

    def setUp(self):
        example = ROOT / "bvsecrets" / "secrets.conf.example"
        if not example.exists():
            self.skipTest("modele absent")
        self.cfg = conf_yaml.load(example)

    def test_it_parses(self):
        self.assertGreaterEqual(len(self.cfg), 5)

    def test_a_multiline_note_survives(self):
        self.assertIn("\n", self.cfg["DB_APP_PASSWORD"]["note"])

    def test_a_quoted_command_sink_keeps_its_quotes(self):
        sinks = self.cfg["FILES_PASSWORD"]["sinks"]
        self.assertTrue(any(s.startswith("cmd:") and "'{value}'" in s for s in sinks))

    def test_a_probe_full_of_json_survives(self):
        self.assertIn('"username":"admin"', self.cfg["FILES_PASSWORD"]["probe"])

    def test_a_validate_rule_is_not_polluted_by_its_comment(self):
        # en INI le commentaire de fin de ligne faisait partie de la valeur
        self.assertEqual(self.cfg["MEDIA_API_KEY"]["validate"], "prefix:mk_")


class TestWriter(unittest.TestCase):
    def test_append_keeps_the_inode(self):
        """Le fichier est bind-monte fichier par fichier dans le dashboard, qui
        reste accroche a l'inode vu au demarrage."""
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "secrets.yaml"
            p.write_text(SAMPLE, encoding="utf-8")
            before = p.stat().st_ino
            block = conf_yaml.render_section("NEW", "hex", "auto", ["file:/tmp/x"], length=32)
            conf_yaml.append_sections([block], p)
            self.assertEqual(p.stat().st_ino, before)
            self.assertEqual(conf_yaml.load(p)["NEW"]["length"], 32)

    def test_appending_to_a_file_without_secrets_key_still_works(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "secrets.yaml"
            p.write_text("# rien encore\n", encoding="utf-8")
            conf_yaml.append_sections(
                [conf_yaml.render_section("A", "hex", "auto", [])], p)
            self.assertEqual(sorted(conf_yaml.load(p)), ["A"])


if __name__ == "__main__":
    unittest.main()
