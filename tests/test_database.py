from pathlib import Path

import pytest

from app.database import Database


def test_transaction_rolls_back(tmp_path):
    db = Database(tmp_path / "db.sqlite")
    with pytest.raises(RuntimeError):
        with db.transaction():
            db.execute(
                "INSERT INTO subscriptions (id, name, token, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
                ("sub", "name", "token", "now", "now"),
            )
            raise RuntimeError("abort")
    assert db.query_one("SELECT id FROM subscriptions WHERE id = 'sub'") is None


def test_online_backup(tmp_path):
    db = Database(tmp_path / "db.sqlite")
    db.execute(
        "INSERT INTO subscriptions (id, name, token, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
        ("sub", "name", "token", "now", "now"),
    )
    target = tmp_path / "backup.sqlite"
    db.backup_to(target)
    backup = Database(Path(target))
    assert backup.query_one("SELECT name FROM subscriptions WHERE id = 'sub'")["name"] == "name"
