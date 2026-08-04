"""Connecteurs de localisation : lecture, round-trip et surtout ecriture
chirurgicale — seule la valeur ciblee change, tout le reste est preserve."""
import sqlite3
import tempfile
import unittest
from pathlib import Path

from bvsecrets.engine import sink_service
from bvsecrets.locations import LocationError, read_location, write_location


def _changed_lines(before: str, after: str):
    """Indices des lignes qui different entre deux versions du meme fichier."""
    b, a = before.splitlines(), after.splitlines()
    return [i for i in range(max(len(b), len(a)))
            if (b[i] if i < len(b) else None) != (a[i] if i < len(a) else None)]


class SurgicalWriteMixin:
    """Chaque format : ecrire une valeur ne touche QU'A la ligne cible, la relecture
    rend bien la valeur, et le reste du fichier est intact octet pour octet."""

    scheme = ""          # rempli par les sous-classes
    fixture = ""         # contenu initial du fichier
    selector = ""        # ce qui suit le #
    target_line = 0      # ligne (0-based) censee changer
    survive = ""         # une sous-chaine qui doit rester presente apres ecriture

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.path = Path(self.dir.name) / "conf"
        self.path.write_text(self.fixture)

    def tearDown(self):
        self.dir.cleanup()

    def _loc(self):
        sel = f"#{self.selector}" if self.selector else ""
        return f"{self.scheme}:{self.path}{sel}"

    def test_roundtrip(self):
        write_location(self._loc(), "NEWVALUE123")
        self.assertEqual(read_location(self._loc()), "NEWVALUE123")

    def test_only_target_line_changes(self):
        before = self.path.read_text()
        write_location(self._loc(), "NEWVALUE123")
        after = self.path.read_text()
        self.assertEqual(_changed_lines(before, after), [self.target_line])

    def test_surroundings_preserved(self):
        write_location(self._loc(), "NEWVALUE123")
        self.assertIn(self.survive, self.path.read_text())

    def test_read_absent_file_is_none(self):
        missing = f"{self.scheme}:{self.path}.nope"
        if self.selector:
            missing += f"#{self.selector}"
        self.assertIsNone(read_location(missing))


class TestEnvfile(SurgicalWriteMixin, unittest.TestCase):
    scheme = "envfile"
    fixture = "# header comment\nexport API_KEY=keep\nDB_PASS=old\nOTHER=untouched\n"
    selector = "DB_PASS"
    target_line = 2
    survive = "# header comment"


class TestJson(SurgicalWriteMixin, unittest.TestCase):
    scheme = "json"
    fixture = '{\n  "database": {\n    "password": "old",\n    "port": 5432\n  }\n}\n'
    selector = "database.password"
    target_line = 2
    survive = '"port": 5432'


class TestYaml(SurgicalWriteMixin, unittest.TestCase):
    scheme = "yaml"
    fixture = ("# app config\ndatabase:\n  password: old   # inline note\n"
               "  port: 5432\nserver:\n  host: localhost\n")
    selector = "database.password"
    target_line = 2
    survive = "# inline note"


class TestIni(SurgicalWriteMixin, unittest.TestCase):
    scheme = "ini"
    fixture = ("[security]\nadmin_password = old\nadmin_user = admin\n\n"
               "[server]\nhttp_port = 3000\n")
    selector = "security.admin_password"
    target_line = 1
    survive = "http_port = 3000"


class TestToml(SurgicalWriteMixin, unittest.TestCase):
    scheme = "toml"
    fixture = '# toml file\n[database]\npassword = "old"\nport = 5432\n'
    selector = "database.password"
    target_line = 2
    survive = "port = 5432"


class TestRegex(SurgicalWriteMixin, unittest.TestCase):
    scheme = "regex"
    fixture = 'line one\ntoken = "old" trailing\nline three\n'
    selector = 'token = "(.*?)"'
    target_line = 1
    survive = "trailing"

    def test_read_absent_file_is_none(self):
        self.assertIsNone(read_location(f"regex:{self.path}.nope#{self.selector}"))


class TestFile(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.path = Path(self.dir.name) / "secret.key"

    def tearDown(self):
        self.dir.cleanup()

    def test_roundtrip_whole_file(self):
        write_location(f"file:{self.path}", "the entire value\n")
        self.assertEqual(read_location(f"file:{self.path}"), "the entire value\n")

    def test_read_absent_is_none(self):
        self.assertIsNone(read_location(f"file:{self.path}"))


class TestSqlite(unittest.TestCase):
    """Le garde-fou du connecteur `sqlite` : une table n'a pas d'ancre textuelle,
    donc c'est la condition qui tient lieu d'adresse et elle doit viser une ligne
    et une seule, en lecture comme en ecriture."""

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.path = Path(self.dir.name) / "app.db"
        con = sqlite3.connect(self.path)
        con.executescript(
            "CREATE TABLE monitor (id INTEGER PRIMARY KEY, name TEXT, token TEXT);"
            "INSERT INTO monitor VALUES (1, 'import', 'old');"
            "INSERT INTO monitor VALUES (2, 'jumeau', 'autre');"
            "INSERT INTO monitor VALUES (3, 'jumeau', 'encore');")
        con.commit()
        con.close()

    def tearDown(self):
        self.dir.cleanup()

    def _loc(self, selector="monitor.token?id=1"):
        return f"sqlite:{self.path}#{selector}"

    def _rows(self):
        con = sqlite3.connect(self.path)
        rows = con.execute("SELECT id, name, token FROM monitor ORDER BY id").fetchall()
        con.close()
        return rows

    def test_roundtrip(self):
        write_location(self._loc(), "NEWVALUE123")
        self.assertEqual(read_location(self._loc()), "NEWVALUE123")

    def test_neighbours_untouched(self):
        write_location(self._loc(), "NEWVALUE123")
        self.assertEqual(self._rows()[1:],
                         [(2, "jumeau", "autre"), (3, "jumeau", "encore")])

    def test_where_on_a_text_column(self):
        self.assertEqual(read_location(self._loc("monitor.token?name=import")), "old")

    def test_quote_in_value_is_not_injection(self):
        write_location(self._loc(), "a'; DROP TABLE monitor; --")
        self.assertEqual(read_location(self._loc()), "a'; DROP TABLE monitor; --")
        self.assertEqual(len(self._rows()), 3)

    def test_ambiguous_where_refuses_to_write(self):
        with self.assertRaises(LocationError):
            write_location(self._loc("monitor.token?name=jumeau"), "v")
        self.assertEqual(self._rows()[1][2], "autre")

    def test_ambiguous_where_refuses_to_read(self):
        with self.assertRaises(LocationError):
            read_location(self._loc("monitor.token?name=jumeau"))

    def test_no_match_reads_none_and_refuses_to_write(self):
        self.assertIsNone(read_location(self._loc("monitor.token?id=99")))
        with self.assertRaises(LocationError):
            write_location(self._loc("monitor.token?id=99"), "v")

    def test_absent_database_is_none(self):
        self.assertIsNone(read_location(f"sqlite:{self.path}.nope#monitor.token?id=1"))

    def test_malformed_selector(self):
        for bad in ["monitor.token", "monitor?id=1", "monitor.token?id"]:
            with self.assertRaises(LocationError):
                read_location(self._loc(bad))


class TestSinkService(unittest.TestCase):
    """Le service a recreer se DEDUIT du sink, il ne se declare jamais."""

    def test_derived(self):
        self.assertEqual(sink_service("env:pihole#FTLCONF_X"), "pihole")
        self.assertEqual(
            sink_service("sqlite:/app/data/kuma.db@uptime-kuma#monitor.token?id=1"),
            "uptime-kuma")

    def test_none_when_nothing_to_recreate(self):
        self.assertIsNone(sink_service("envfile:/home/bv/x.sh#TOKEN"))
        self.assertIsNone(sink_service("sqlite:/srv/local.db#t.col?id=1"))
        self.assertIsNone(sink_service("file:/srv/key"))


class TestErrors(unittest.TestCase):
    def test_unknown_scheme_read(self):
        with self.assertRaises(LocationError):
            read_location("bogus:/tmp/x#y")

    def test_write_missing_json_target(self):
        with self.assertRaises(LocationError):
            write_location("json:/nonexistent/path.json#a.b", "v")

    def test_absent_key_write_raises(self):
        d = tempfile.TemporaryDirectory()
        p = Path(d.name) / "c.ini"
        p.write_text("[sec]\nother = 1\n")
        with self.assertRaises(LocationError):
            write_location(f"ini:{p}#sec.missing", "v")
        d.cleanup()


if __name__ == "__main__":
    unittest.main()
