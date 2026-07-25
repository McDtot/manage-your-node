import argparse
from datetime import UTC, datetime
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

    marker = db.query_one(
        "SELECT value FROM app_metadata WHERE key = 'master_secret_check'"
    )
    if marker:
        try:
            marker_value = secret_box.open(marker["value"])
        except ValueError as exc:
            raise RuntimeError("configured APP_SECRET does not match this database") from exc
        if marker_value != "manage-your-node/master-secret-check/v1":
            raise RuntimeError("configured APP_SECRET does not match this database")

    encrypted_columns = [
        ("servers", "encrypted_secret"),
        ("deployments", "encrypted_reality_private_key"),
        ("deployments", "encrypted_ss_password"),
        ("deployments", "encrypted_hy2_obfs_password"),
        ("clients", "encrypted_ss_password"),
        ("clients", "encrypted_anytls_password"),
        ("proxy_chain_nodes", "encrypted_private_key"),
        ("proxy_chain_nodes", "encrypted_ss_password"),
        ("proxy_chain_nodes", "encrypted_hy2_password"),
    ]
    checked = 0
    for table, column in encrypted_columns:
        if not _table_has_column(db, table, column):
            continue
        rows = db.query_all(
            f"SELECT rowid AS record_id, {column} AS value FROM {table} "
            f"WHERE {column} IS NOT NULL AND {column} <> ''"
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


def _table_has_column(db: Database, table: str, column: str) -> bool:
    rows = db.query_all(f"PRAGMA table_info({table})")
    return any(row["name"] == column for row in rows)


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
                stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
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
