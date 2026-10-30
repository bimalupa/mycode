import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pi_redactor import auth  # noqa: E402

USERS = {
    "ana": {"name": "Ana", "role": "analyst", "password": auth.hash_password("Secret#123")},
    "cfo": {"name": "Officer", "role": "compliance_officer", "password": auth.hash_password("Secret#456")},
    "old": {"name": "Old", "role": "analyst", "password": auth.hash_password("Secret#789"), "active": False},
}


def test_password_hash_roundtrip():
    h = auth.hash_password("pw-123456")
    assert h.startswith("pbkdf2_sha256$") and "pw-123456" not in h
    assert auth.verify_password("pw-123456", h)
    assert not auth.verify_password("wrong", h)
    assert not auth.verify_password("x", "garbage")


def test_login_and_roles():
    user = auth.authenticate("ANA ", "Secret#123", USERS)
    assert user and user["role"] == "analyst"
    assert auth.can(user, "submit") and not auth.can(user, "approve") and not auth.can(user, "audit")
    officer = auth.authenticate("cfo", "Secret#456", USERS)
    assert auth.can(officer, "approve") and auth.can(officer, "audit")
    assert auth.authenticate("old", "Secret#789", USERS) is None
    assert not auth.can(None, "scan")


def test_lockout_after_failed_attempts():
    for _ in range(auth.MAX_ATTEMPTS):
        assert auth.authenticate("cfo", "nope", USERS) is None
    assert auth.locked_for("cfo") > 0
    assert auth.authenticate("cfo", "Secret#456", USERS) is None  # correct password still blocked
    auth._failures.pop("cfo", None)


def test_demo_users_file_is_hashed():
    users = auth.load_users()
    assert {u["role"] for u in users.values()} == {"analyst", "compliance_officer"}
    assert all(u["password"].startswith("pbkdf2_sha256$") for u in users.values())
