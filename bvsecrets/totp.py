"""TOTP (RFC 6238) et codes de secours, en stdlib pure.

Deux objets de nature opposee, et c'est ce qui decide de leur stockage :

- le **seed TOTP** est un secret PARTAGE et symetrique. Le verifier exige de le
  detenir en clair, donc il ne se hache pas : le saler ou le poivrer n'a aucun
  sens ici. Il se protege par le chiffrement au repos du store et par l'endroit
  ou on le rend, pas par un hachage.
- les **codes de secours** sont des porteurs a usage unique. On n'a jamais besoin
  de les relire, seulement de verifier qu'on en presente un bon : ils se hachent,
  avec un sel par code.

Pas de dependance : un TOTP tient en un HMAC-SHA1 sur un compteur de 8 octets.
"""
import base64
import hashlib
import hmac
import os
import secrets as pysecrets
import struct
import time

from .config import TOTP_DIGITS, TOTP_DRIFT, TOTP_STEP

STEP = TOTP_STEP          # 30 s : ce que toute application suppose
DIGITS = TOTP_DIGITS
DRIFT = TOTP_DRIFT        # une fenetre avant et une apres : horloges imparfaites
SEED_BYTES = 20           # 160 bits, la taille recommandee par la RFC 4226

RECOVERY_COUNT = 10
RECOVERY_BYTES = 10       # ~50 bits par code, hors de portee d'un devinage
# scrypt : parametres OWASP 2024 pour un secret a forte entropie.
_SCRYPT = {"n": 2 ** 14, "r": 8, "p": 1, "dklen": 32}
_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"   # sans I, O, 0, 1


# --------------------------------------------------------------------------- #
# Seed et codes
# --------------------------------------------------------------------------- #
def new_seed() -> str:
    """Un seed base32 sans remplissage, tel que les applications l'attendent."""
    return base64.b32encode(pysecrets.token_bytes(SEED_BYTES)).decode().rstrip("=")


def seed_hex(seed: str) -> str:
    """Le seed en octets hexadecimaux, pour un jeton materiel.

    Une application de telephone lit le base32 ou le QR ; un firmware, lui, veut
    le tableau d'octets. Le donner evite une conversion a la main, qui est
    exactement le genre d'etape ou on se trompe d'un octet sans le voir."""
    return _key(seed).hex()


def _key(seed: str) -> bytes:
    """Le base32 d'un QR arrive souvent en minuscules, avec des espaces, et sans
    son remplissage. Accepter les trois evite un « code invalide » dont la cause
    est une recopie, pas une erreur d'authentification."""
    cleaned = "".join(seed.split()).upper()
    return base64.b32decode(cleaned + "=" * (-len(cleaned) % 8))


def code_at(seed: str, step_index: int, digits: int = DIGITS) -> str:
    mac = hmac.new(_key(seed), struct.pack(">Q", step_index), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    truncated = struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(truncated % (10 ** digits)).zfill(digits)


def code(seed: str, at=None, digits: int = DIGITS) -> str:
    return code_at(seed, int((at if at is not None else time.time()) // STEP), digits)


def verify(seed: str, candidate: str, at=None, drift: int = DRIFT,
           digits: int = DIGITS):
    """-> l'index de fenetre qui correspond, ou None.

    Rend l'index plutot qu'un booleen EXPRES : un code reste valable toute sa
    fenetre, donc l'appelant doit pouvoir retenir celle qu'il vient de consommer
    et refuser le meme code une seconde fois. Sans ca, un code vu par-dessus
    l'epaule se rejoue pendant une minute et demie."""
    candidate = "".join((candidate or "").split())
    if not candidate.isdigit() or len(candidate) != digits:
        return None
    now = int((at if at is not None else time.time()) // STEP)
    for offset in range(-drift, drift + 1):
        if hmac.compare_digest(candidate, code_at(seed, now + offset, digits)):
            return now + offset
    return None


def uri(seed: str, account: str, issuer: str) -> str:
    """L'URI `otpauth://` a coller dans une application."""
    from urllib.parse import quote
    label = f"{quote(issuer)}:{quote(account)}"
    return (f"otpauth://totp/{label}?secret={seed}&issuer={quote(issuer)}"
            f"&algorithm=SHA1&digits={DIGITS}&period={STEP}")


# --------------------------------------------------------------------------- #
# Codes de secours
# --------------------------------------------------------------------------- #
def new_recovery_codes(count: int = RECOVERY_COUNT) -> list:
    """Des codes lisibles a voix haute : alphabet sans I, O, 0 ni 1."""
    out = []
    for _ in range(count):
        raw = "".join(pysecrets.choice(_ALPHABET) for _ in range(RECOVERY_BYTES))
        out.append(f"{raw[:5]}-{raw[5:]}")
    return out


def hash_recovery(plain: str, salt: bytes = None) -> str:
    """-> `scrypt$n$r$p$sel$empreinte`, tout en base64 urlsafe."""
    salt = salt or os.urandom(16)
    digest = hashlib.scrypt(_normalise(plain).encode(), salt=salt, **_SCRYPT)
    b64 = lambda raw: base64.urlsafe_b64encode(raw).decode().rstrip("=")
    return (f"scrypt${_SCRYPT['n']}${_SCRYPT['r']}${_SCRYPT['p']}$"
            f"{b64(salt)}${b64(digest)}")


def check_recovery(plain: str, stored: str) -> bool:
    """Verification a temps constant contre UNE empreinte."""
    try:
        scheme, n, r, p, salt_b64, digest_b64 = stored.split("$")
        if scheme != "scrypt":
            return False
        unb64 = lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
        salt, expected = unb64(salt_b64), unb64(digest_b64)
        got = hashlib.scrypt(_normalise(plain).encode(), salt=salt,
                             n=int(n), r=int(r), p=int(p), dklen=len(expected))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(got, expected)


def _normalise(plain: str) -> str:
    """Le tiret et la casse sont de la presentation : les ignorer evite qu'un
    code recopie a la main soit refuse pour une raison qui n'en est pas une."""
    return "".join((plain or "").split()).replace("-", "").upper()
