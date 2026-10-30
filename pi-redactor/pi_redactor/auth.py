"""Simple local login with role-based permissions (PBKDF2-hashed passwords, lockout after failed attempts)."""
import hashlib
import hmac
import json
import os
import threading
import time
from pathlib import Path

from .audit import audit
from .config import ROOT

USERS_FILE = Path(os.getenv("USERS_FILE", ROOT / "data" / "users.json"))

ROLES = {"analyst": "Analyst", "compliance_officer": "Compliance Officer"}
PERMISSIONS = {
    "analyst": {"scan", "review", "submit", "results", "assistant"},
    "compliance_officer": {"scan", "review", "submit", "approve", "results", "assistant", "audit", "purge"},
}

MAX_ATTEMPTS = 5
LOCKOUT_SECONDS = 300
SESSION_TIMEOUT_SECONDS = int(os.getenv("SESSION_TIMEOUT_MINUTES", "30")) * 60
_ITERATIONS = 200_000
_failures: dict[str, list[float]] = {}
_lock = threading.Lock()


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _ITERATIONS)
    return f"pbkdf2_sha256${_ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, iterations, salt, expected = stored.split("$")
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(iterations))
        return hmac.compare_digest(digest.hex(), expected)
    except (ValueError, AttributeError):
        return False


def load_users(path: Path = USERS_FILE) -> dict:
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}


def save_users(users: dict, path: Path = USERS_FILE) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(users, indent=2), encoding="utf-8")


def locked_for(username: str) -> int:
    """Seconds remaining on a lockout, 0 if the account is not locked."""
    with _lock:
        recent = [t for t in _failures.get(username, []) if time.time() - t < LOCKOUT_SECONDS]
        _failures[username] = recent
        if len(recent) >= MAX_ATTEMPTS:
            return int(LOCKOUT_SECONDS - (time.time() - recent[0])) + 1
        return 0


def authenticate(username: str, password: str, users: dict | None = None) -> dict | None:
    username = username.strip().lower()
    if locked_for(username):
        audit("login_blocked_locked", user=username)
        return None
    record = (users if users is not None else load_users()).get(username)
    if record and record.get("active", True) and verify_password(password, record["password"]):
        with _lock:
            _failures.pop(username, None)
        audit("login_success", user=username, role=record["role"])
        return {"username": username, "name": record.get("name", username), "role": record["role"],
                "login_at": time.time(), "last_active": time.time()}
    with _lock:
        _failures.setdefault(username, []).append(time.time())
    audit("login_failed", user=username)
    if locked_for(username):
        audit("account_locked", user=username, minutes=LOCKOUT_SECONDS // 60)
    return None


def can(user: dict | None, permission: str) -> bool:
    return bool(user) and permission in PERMISSIONS.get(user["role"], set())


def session_expired(user: dict) -> bool:
    return time.time() - user.get("last_active", 0) > SESSION_TIMEOUT_SECONDS
