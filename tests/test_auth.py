import time

from app.auth import AuthManager


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


def test_failures_expire_out_of_window(monkeypatch):
    mgr = _mgr(max_attempts=2, window_seconds=10, lockout_seconds=100)
    key = "5.6.7.8"
    base = [1000.0]
    monkeypatch.setattr(time, "monotonic", lambda: base[0])
    mgr.register_failure(key)
    mgr.register_failure(key)
    assert mgr.lockout_remaining(key) > 0
    base[0] += 20  # move past the failure window
    assert mgr.lockout_remaining(key) == 0
