import pytest

from app.database import Database
from app.maintenance import check_database
from app.security import SecretBox
from app.services import AppServices


def test_maintenance_check_rejects_database_master_secret_mismatch(tmp_path):
    db = Database(tmp_path / "manage-node.db")
    try:
        AppServices(db, SecretBox("original-application-secret"))

        with pytest.raises(RuntimeError, match="APP_SECRET does not match"):
            check_database(db, SecretBox("different-application-secret"))
    finally:
        db.close()
