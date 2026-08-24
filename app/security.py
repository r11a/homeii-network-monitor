"""Password hashing and login throttling primitives."""

from __future__ import annotations

import hashlib
import hmac
import base64
import secrets
import threading
import time
from typing import Dict, List

_login_lock = threading.Lock()
_login_attempts: Dict[str, List[int]] = {}


def password_hash(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 240_000)
    return f"pbkdf2_sha256$240000${base64.b64encode(salt).decode()}${base64.b64encode(digest).decode()}"


def password_matches(password: str, stored: str) -> bool:
    try:
        algorithm, rounds, salt_value, digest_value = stored.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        salt = base64.b64decode(salt_value)
        expected = base64.b64decode(digest_value)
        actual = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, int(rounds)
        )
        return hmac.compare_digest(actual, expected)
    except (TypeError, ValueError):
        return False


def login_attempt_allowed(client_key: str, timestamp: int | None = None) -> bool:
    current_time = int(time.time()) if timestamp is None else timestamp
    cutoff = current_time - 300
    with _login_lock:
        attempts = [stamp for stamp in _login_attempts.get(client_key, []) if stamp >= cutoff]
        _login_attempts[client_key] = attempts
        return len(attempts) < 5


def record_login_attempt(client_key: str, success: bool, timestamp: int | None = None) -> None:
    current_time = int(time.time()) if timestamp is None else timestamp
    with _login_lock:
        if success:
            _login_attempts.pop(client_key, None)
        else:
            _login_attempts.setdefault(client_key, []).append(current_time)


__all__ = [
    "login_attempt_allowed",
    "password_hash",
    "password_matches",
    "record_login_attempt",
]
