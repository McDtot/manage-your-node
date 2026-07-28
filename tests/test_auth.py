import time

from app.auth import AuthManager
from app.database import Database


def _mgr(**kwargs) -> AuthManager:
    return AuthManager("app-secret", "admin", "pw", session_seconds=3600, **kwargs)


def test_credentials():
    mgr = _mgr()
    assert mgr.verify_credentials("admin", "pw")
    assert not mgr.verify_credentials("admin", "wrong")
    assert not mgr.verify_credentials("root", "pw")


def test_session_roundtrip():
    mgr = _mgr()
    token = mgr.issue_session()
    assert mgr.verify_session(token)


def test_session_rejects_tampering():
    mgr = _mgr()
    token = mgr.issue_session()
    encoded, sig = token.rsplit(".", 1)
    assert not mgr.verify_session(encoded + "." + sig[::-1])
    assert not mgr.verify_session("garbage")
    assert not mgr.verify_session(None)


def test_session_signed_by_other_secret_rejected():
    token = _mgr().issue_session()
    other = AuthManager("different-secret", "admin", "pw", 3600)
    assert not other.verify_session(token)


def test_expired_session_rejected():
    mgr = AuthManager("app-secret", "admin", "pw", session_seconds=-1)
    token = mgr.issue_session()
    assert not mgr.verify_session(token)


def test_lockout_after_max_attempts():
    mgr = _mgr(max_attempts=3, window_seconds=300, lockout_seconds=100)
    key = "1.2.3.4"
    assert mgr.lockout_remaining(key) == 0
    for _ in range(3):
        mgr.register_failure(key)
    assert mgr.lockout_remaining(key) > 0
    mgr.register_success(key)
    assert mgr.lockout_remaining(key) == 0


def test_lockout_outlives_failure_window(monkeypatch):
    mgr = _mgr(max_attempts=2, window_seconds=10, lockout_seconds=100)
    key = "5.6.7.8"
    base = [1000.0]
    monkeypatch.setattr(time, "monotonic", lambda: base[0])
    mgr.register_failure(key)
    mgr.register_failure(key)
    assert mgr.lockout_remaining(key) > 0
    base[0] += 20  # move past the failure window
    assert mgr.lockout_remaining(key) > 0
    base[0] += 81  # move past the full lockout period
    assert mgr.lockout_remaining(key) == 0


def test_csrf_is_bound_to_session():
    mgr = _mgr()
    first = mgr.issue_session()
    second = mgr.issue_session()
    token = mgr.csrf_token(first)
    assert mgr.verify_csrf(first, token)
    assert not mgr.verify_csrf(second, token)
    assert not mgr.verify_csrf(first, "bad-token")


def test_lockout_persists_across_managers(monkeypatch, tmp_path):
    db = Database(tmp_path / "auth.sqlite")
    now = [1000.0]
    monkeypatch.setattr(time, "time", lambda: now[0])
    first = AuthManager(
        "app-secret",
        "admin",
        "pw",
        3600,
        max_attempts=2,
        lockout_seconds=100,
        db=db,
    )
    first.register_failure("client")
    first.register_failure("client")
    second = AuthManager("app-secret", "admin", "pw", 3600, db=db)
    assert second.lockout_remaining("client") > 0


def _attempt_failed_login(mgr: AuthManager, key: str) -> bool:
    """Replay the order server.login() uses: check the lockout, then record a failure.

    Regression guard: lockout_remaining() must not clear the failure history it
    reads. Calling register_failure() twice in a row (as the older tests did)
    skips the read entirely and cannot catch that class of bug.
    """
    if mgr.lockout_remaining(key) > 0:
        return False  # request rejected with 429, credentials never checked
    mgr.register_failure(key)
    return True


def test_repeated_failed_logins_eventually_lock_out(monkeypatch, tmp_path):
    db = Database(tmp_path / "auth.sqlite")
    now = [1000.0]
    monkeypatch.setattr(time, "time", lambda: now[0])
    mgr = AuthManager(
        "app-secret", "admin", "pw", 3600, max_attempts=5, window_seconds=300,
        lockout_seconds=900, db=db,
    )
    key = "1.2.3.4"
    for _ in range(5):
        assert _attempt_failed_login(mgr, key), "attempts before the limit must be allowed"
    assert not _attempt_failed_login(mgr, key), "6th attempt must be locked out"
    assert mgr.lockout_remaining(key) == 900


def test_lockout_remaining_does_not_reset_failure_history(monkeypatch, tmp_path):
    db = Database(tmp_path / "auth.sqlite")
    now = [1000.0]
    monkeypatch.setattr(time, "time", lambda: now[0])
    mgr = AuthManager(
        "app-secret", "admin", "pw", 3600, max_attempts=3, lockout_seconds=100, db=db,
    )
    key = "9.9.9.9"
    mgr.register_failure(key)
    for _ in range(10):
        assert mgr.lockout_remaining(key) == 0
    mgr.register_failure(key)
    mgr.register_failure(key)
    assert mgr.lockout_remaining(key) > 0


def test_in_memory_backend_also_locks_out_in_login_order():
    mgr = _mgr(max_attempts=3, window_seconds=300, lockout_seconds=100)
    key = "in-memory"
    for _ in range(3):
        assert _attempt_failed_login(mgr, key)
    assert not _attempt_failed_login(mgr, key)


def test_lockout_expires_and_client_gets_a_clean_slate(monkeypatch, tmp_path):
    db = Database(tmp_path / "auth.sqlite")
    now = [1000.0]
    monkeypatch.setattr(time, "time", lambda: now[0])
    mgr = AuthManager(
        "app-secret", "admin", "pw", 3600, max_attempts=3, window_seconds=300,
        lockout_seconds=100, db=db,
    )
    key = "5.5.5.5"
    for _ in range(3):
        _attempt_failed_login(mgr, key)
    assert mgr.lockout_remaining(key) > 0
    now[0] += 101  # serve the full lockout
    assert mgr.lockout_remaining(key) == 0
    # A served lockout resets the counter: it must take the full quota again.
    for _ in range(3):
        assert _attempt_failed_login(mgr, key), "stale failures must not re-lock immediately"
    assert not _attempt_failed_login(mgr, key)


def test_successful_login_clears_accumulated_failures(monkeypatch, tmp_path):
    db = Database(tmp_path / "auth.sqlite")
    now = [1000.0]
    monkeypatch.setattr(time, "time", lambda: now[0])
    mgr = AuthManager(
        "app-secret", "admin", "pw", 3600, max_attempts=3, lockout_seconds=100, db=db,
    )
    key = "7.7.7.7"
    _attempt_failed_login(mgr, key)
    _attempt_failed_login(mgr, key)
    mgr.register_success(key)
    for _ in range(3):
        assert _attempt_failed_login(mgr, key), "counter must restart after a success"
    assert not _attempt_failed_login(mgr, key)


def test_failures_outside_the_window_do_not_accumulate(monkeypatch, tmp_path):
    db = Database(tmp_path / "auth.sqlite")
    now = [1000.0]
    monkeypatch.setattr(time, "time", lambda: now[0])
    mgr = AuthManager(
        "app-secret", "admin", "pw", 3600, max_attempts=3, window_seconds=60,
        lockout_seconds=100, db=db,
    )
    key = "8.8.8.8"
    for _ in range(4):
        assert _attempt_failed_login(mgr, key)
        now[0] += 61  # each attempt ages out before the next one
    assert mgr.lockout_remaining(key) == 0
