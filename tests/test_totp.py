"""TOTP et codes de secours.

Le test qui compte vraiment est celui des vecteurs de la RFC 6238 : une
implementation qui les passe est interoperable avec les applications
d'authentification reelles. Tout le reste ne prouverait que la coherence du
code avec lui-meme.
"""
import base64
import time
import unittest

from bvsecrets import totp

# RFC 6238, appendice B : seed ASCII "12345678901234567890", SHA-1, 8 chiffres.
RFC_SEED = base64.b32encode(b"12345678901234567890").decode().rstrip("=")
RFC_VECTORS = [
    (59, "94287082"),
    (1111111109, "07081804"),
    (1111111111, "14050471"),
    (1234567890, "89005924"),
    (2000000000, "69279037"),
    (20000000000, "65353130"),
]


class TestAgainstTheRFC(unittest.TestCase):
    def test_the_published_vectors_match(self):
        for at, expected in RFC_VECTORS:
            with self.subTest(at=at):
                self.assertEqual(totp.code(RFC_SEED, at=at, digits=8), expected)

    def test_a_published_vector_verifies(self):
        self.assertIsNotNone(
            totp.verify(RFC_SEED, "94287082", at=59, digits=8))


class TestVerification(unittest.TestCase):
    def setUp(self):
        self.seed = totp.new_seed()
        self.now = 1_700_000_000

    def test_the_current_code_passes(self):
        current = totp.code(self.seed, at=self.now)
        self.assertIsNotNone(totp.verify(self.seed, current, at=self.now))

    def test_one_window_of_drift_is_tolerated(self):
        for shift in (-totp.STEP, totp.STEP):
            got = totp.code(self.seed, at=self.now + shift)
            self.assertIsNotNone(totp.verify(self.seed, got, at=self.now), shift)

    def test_beyond_the_drift_it_is_refused(self):
        far = totp.code(self.seed, at=self.now + 5 * totp.STEP)
        self.assertIsNone(totp.verify(self.seed, far, at=self.now))

    def test_it_returns_the_window_so_a_code_can_be_burned(self):
        """Un code reste valable toute sa fenetre. L'appelant doit pouvoir
        retenir celle qu'il vient de consommer, sinon un code vu par-dessus
        l'epaule se rejoue pendant une minute et demie."""
        current = totp.code(self.seed, at=self.now)
        window = totp.verify(self.seed, current, at=self.now)
        self.assertEqual(window, self.now // totp.STEP)

    def test_junk_is_refused_without_raising(self):
        for junk in ("", None, "abcdef", "12345", "1234567", "  ", "12 34 56"):
            self.assertIsNone(totp.verify(self.seed, junk, at=self.now), junk)

    def test_another_seed_does_not_open_it(self):
        other = totp.code(totp.new_seed(), at=self.now)
        self.assertIsNone(totp.verify(self.seed, other, at=self.now))

    def test_a_seed_copied_by_hand_still_works(self):
        """Le base32 d'un QR arrive en minuscules, espace, sans remplissage."""
        current = totp.code(self.seed, at=self.now)
        messy = " ".join(self.seed.lower()[i:i + 4]
                         for i in range(0, len(self.seed), 4))
        self.assertIsNotNone(totp.verify(messy, current, at=self.now))


class TestEnrolment(unittest.TestCase):
    def test_two_seeds_are_never_the_same(self):
        self.assertEqual(len({totp.new_seed() for _ in range(50)}), 50)

    def test_the_uri_carries_what_an_app_needs(self):
        seed = totp.new_seed()
        got = totp.uri(seed, "bv", "bv-secrets")
        self.assertTrue(got.startswith("otpauth://totp/"))
        for needle in (f"secret={seed}", "issuer=bv-secrets", "period=30",
                       "digits=6", "algorithm=SHA1"):
            self.assertIn(needle, got)


class TestRecoveryCodes(unittest.TestCase):
    def test_they_are_distinct_and_readable(self):
        codes = totp.new_recovery_codes(20)
        self.assertEqual(len(set(codes)), 20)
        for c in codes:
            # alphabet sans I, O, 0 ni 1 : un code se dicte sans ambiguite
            self.assertNotRegex(c, r"[IO01]")

    def test_a_code_checks_against_its_own_hash(self):
        code = totp.new_recovery_codes(1)[0]
        self.assertTrue(totp.check_recovery(code, totp.hash_recovery(code)))

    def test_another_code_does_not(self):
        a, b = totp.new_recovery_codes(2)
        self.assertFalse(totp.check_recovery(b, totp.hash_recovery(a)))

    def test_the_same_code_hashes_differently_every_time(self):
        """Un sel par code : deux empreintes identiques dans le store
        diraient a un lecteur que deux codes sont les memes."""
        code = totp.new_recovery_codes(1)[0]
        self.assertNotEqual(totp.hash_recovery(code), totp.hash_recovery(code))

    def test_presentation_does_not_change_the_answer(self):
        code = totp.new_recovery_codes(1)[0]
        stored = totp.hash_recovery(code)
        for variant in (code.lower(), code.replace("-", ""), f"  {code}  "):
            self.assertTrue(totp.check_recovery(variant, stored), variant)

    def test_a_malformed_stored_value_refuses_instead_of_raising(self):
        for broken in ("", "nimporte quoi", "scrypt$x$y$z$a$b", "md5$1$1$1$a$b"):
            self.assertFalse(totp.check_recovery("ABCDE-FGHIJ", broken), broken)
