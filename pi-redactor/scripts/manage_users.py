"""Manage login users.

  python scripts/manage_users.py list
  python scripts/manage_users.py add alice compliance_officer --name "Alice Rao"   (prompts for password)
  python scripts/manage_users.py passwd alice
  python scripts/manage_users.py disable alice
  python scripts/manage_users.py remove alice
"""
import argparse
import getpass
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pi_redactor.auth import ROLES, USERS_FILE, hash_password, load_users, save_users  # noqa: E402


def ask_password() -> str:
    pw = getpass.getpass("Password: ")
    if len(pw) < 8:
        sys.exit("Password must be at least 8 characters.")
    if pw != getpass.getpass("Repeat password: "):
        sys.exit("Passwords do not match.")
    return pw


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list")
    add = sub.add_parser("add")
    add.add_argument("username")
    add.add_argument("role", choices=list(ROLES))
    add.add_argument("--name", default="")
    for cmd in ("passwd", "disable", "enable", "remove"):
        sub.add_parser(cmd).add_argument("username")
    args = ap.parse_args()

    users = load_users()
    name = getattr(args, "username", "").lower()
    if args.cmd == "list":
        for u, r in users.items():
            print(f"{u:20} {ROLES.get(r['role'], r['role']):20} {r.get('name', ''):25} "
                  f"{'active' if r.get('active', True) else 'disabled'}")
        return
    if args.cmd == "add":
        users[name] = {"name": args.name or name, "role": args.role, "password": hash_password(ask_password()),
                       "active": True}
    elif name not in users:
        sys.exit(f"No such user: {name}")
    elif args.cmd == "passwd":
        users[name]["password"] = hash_password(ask_password())
    elif args.cmd in ("disable", "enable"):
        users[name]["active"] = args.cmd == "enable"
    elif args.cmd == "remove":
        del users[name]
    save_users(users)
    print(f"{args.cmd}: {name} -> saved to {USERS_FILE}")


if __name__ == "__main__":
    main()
