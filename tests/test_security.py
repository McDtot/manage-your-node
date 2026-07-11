import base64
import hashlib
import hmac
import os

import pytest

from app.security import SecretBox


def _legacy_seal(secret: str, value: str) -> str:
    key = hashlib.sha256(secret.encode("utf-8")).digest()

    def stream(nonce: bytes, length: int) -> bytes:
        out = bytearray()
        counter = 0
        while len(out) < length:
            out.extend(
                hmac.new(key, nonce + counter.to_bytes(4, "big"), hashlib.sha256).digest()
            )
            counter += 1
        return bytes(out[:length])

    data = value.encode("utf-8")
    nonce = os.urandom(16)
    cipher = bytes(a ^ b for a, b in zip(data, stream(nonce, len(data))))
    mac = hmac.new(key, b"v1" + nonce + cipher, hashlib.sha256).digest()
    return "v1." + base64.urlsafe_b64encode(nonce + mac + cipher).decode("ascii")


def test_roundtrip():
    box = SecretBox("a-long-test-secret-value")
    sealed = box.seal("super-secret-token")
    assert sealed.startswith("v2.")
    assert box.open(sealed) == "super-secret-token"


def test_empty_values():
    box = SecretBox("a-long-test-secret-value")
    assert box.seal("") == ""
    assert box.seal(None) == ""
    assert box.open("") == ""
    assert box.open(None) == ""


def test_tampered_ciphertext_rejected():
    box = SecretBox("a-long-test-secret-value")
    sealed = box.seal("value")
    tampered = sealed[:-2] + ("AA" if sealed[-2:] != "AA" else "BB")
    with pytest.raises(ValueError):
        box.open(tampered)


def test_wrong_secret_cannot_open():
    sealed = SecretBox("secret-number-one-xxxx").seal("value")
    with pytest.raises(ValueError):
        SecretBox("a-different-secret-yyyy").open(sealed)


def test_unsupported_format_rejected():
    box = SecretBox("a-long-test-secret-value")
    with pytest.raises(ValueError):
        box.open("v9.whatever")


def test_legacy_v1_still_readable():
    secret = "a-long-test-secret-value"
    sealed = _legacy_seal(secret, "legacy-value")
    assert SecretBox(secret).open(sealed) == "legacy-value"
