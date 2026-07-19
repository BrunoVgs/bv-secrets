"""Sessions et CSRF.

Deuxième garde applicatif, en plus du portail admin assuré par Caddy. Les sessions
vivent en mémoire du process : un redémarrage déconnecte, ce qui est voulu.
"""
import os
import secrets as pysecrets
import time

PASSWORD = os.environ.get("BV_DASH_PASSWORD", "")
SESSION_TTL = 12 * 3600
COOKIE_PATH = "/secrets"
_sessions = {}


def configured() -> bool:
    return bool(PASSWORD)


def check_password(candidate: str) -> bool:
    return bool(PASSWORD) and pysecrets.compare_digest(candidate, PASSWORD)


def new() -> str:
    token = pysecrets.token_urlsafe(24)
    _sessions[token] = time.time() + SESSION_TTL
    now = time.time()
    for expired in [t for t, exp in _sessions.items() if exp < now]:
        _sessions.pop(expired, None)
    return token


def valid(token: str) -> bool:
    expiry = _sessions.get(token)
    if not expiry:
        return False
    if expiry < time.time():
        _sessions.pop(token, None)
        return False
    return True


def drop(token: str):
    _sessions.pop(token, None)


def cookie(name, value, extra=""):
    return ("Set-Cookie", f"{name}={value}; Path={COOKIE_PATH}; {extra}".rstrip())


def session_cookie(token):
    return cookie("bv_sess", token, "HttpOnly; Secure; SameSite=Strict")


def csrf_cookie(token):
    return cookie("bv_csrf", token, "Secure; SameSite=Strict")


def clear_session_cookie():
    return ("Set-Cookie", f"bv_sess=; Path={COOKIE_PATH}; Max-Age=0")


def csrf_ok(cookie_token: str, header_token: str) -> bool:
    """Double-submit : le cookie non-HttpOnly est relu par le JS et renvoyé en
    en-tête ; une origine tierce ne peut pas lire le cookie pour le reproduire."""
    return bool(cookie_token) and bool(header_token) \
        and pysecrets.compare_digest(cookie_token, header_token)
