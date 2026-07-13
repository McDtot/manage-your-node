import argparse
from datetime import datetime, timezone
from pathlib import Path

from .config import load_settings
from .database import Database
from .security import SecretBox


def backup(db: Database, target: Path) -> None:
    db.backup_to(target)
    check = Database(target)
    try:
        result = check.query_one("PRAGMA integrity_check")
        if not result or next(iter(result.values())) != "ok":
            raise RuntimeError(f"backup integrity check failed: {result}")
    finally:
        check.close()
    print(f"Verified backup written to {target}")


def check_database(db: Database, secret_box: SecretBox) -> None:
    result = db.query_one("PRAGMA integrity_check")
    if not result or next(iter(result.values())) != "ok":
        raise RuntimeError(f"database integrity check failed: {result}")

    encrypted_columns = [
        ("servers", "encrypted_secret"),
        ("deployments", "encrypted_panel_password"),
        ("deployments", "encrypted_api_token"),
        ("proxy_chain_nodes", "encrypted_private_key"),
    ]
    checked = 0
    for table, column in encrypted_columns:
        rows = db.query_all(
            f"SELECT rowid AS record_id, {column} AS value FROM {table} WHERE {column} <> ''"
        )
        for row in rows:
            try:
                secret_box.open(row["value"])
            except ValueError as exc:
                raise RuntimeError(
                    f"configured APP_SECRET cannot decrypt {table}.{column} "
                    f"record {row['record_id']}"
                ) from exc
            checked += 1
    print(f"Database integrity is OK; decrypted {checked} encrypted value(s).")


def main() -> None:
    parser = argparse.ArgumentParser(description="Manage Your Node maintenance utilities")
    subparsers = parser.add_subparsers(dest="command", required=True)
    backup_parser = subparsers.add_parser("backup", help="create and verify an online backup")
    backup_parser.add_argument("target", nargs="?", help="output database path")
    subparsers.add_parser("check", help="check SQLite integrity and the configured APP_SECRET")
    args = parser.parse_args()

    settings = load_settings()
    db = Database(settings.db_path)
    try:
        try:
            if args.command == "backup":
                stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
                target = (
                    Path(args.target)
                    if args.target
                    else Path("backups") / f"manage-node-{stamp}.db"
                )
                backup(db, target.resolve())
            else:
                check_database(db, SecretBox(settings.app_secret))
        except (OSError, RuntimeError, ValueError) as exc:
            raise SystemExit(f"Maintenance failed: {exc}") from exc
    finally:
        db.close()


if __name__ == "__main__":
    main()
