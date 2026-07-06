import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    db_path: Path
    static_dir: Path
    host: str
    port: int
    app_secret: str
    admin_username: str
    admin_password: str
    session_seconds: int


def load_settings() -> Settings:
    base_dir = Path(__file__).resolve().parent
    data_dir = Path(os.getenv("APP_DATA_DIR", "data")).resolve()
    data_dir.mkdir(parents=True, exist_ok=True)
    app_secret = os.getenv("APP_SECRET", "development-only-secret")

    return Settings(
        data_dir=data_dir,
        db_path=data_dir / "manage_node.db",
        static_dir=base_dir / "static",
        host=os.getenv("HOST", "127.0.0.1"),
        port=int(os.getenv("PORT", "8787")),
        app_secret=app_secret,
        admin_username=os.getenv("ADMIN_USERNAME", "admin"),
        admin_password=os.getenv("ADMIN_PASSWORD") or app_secret,
        session_seconds=int(float(os.getenv("SESSION_HOURS", "12")) * 60 * 60),
    )
