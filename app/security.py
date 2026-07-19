import base64
import hashlib
import hmac

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# Stable application salt. The master secret (APP_SECRET) is expected to be
# high entropy, so a fixed salt for the at-rest key is an acceptable trade-off
# and keeps decryption stable across restarts.
_KDF_SALT = b"manage-your-node/secretbox/v2"


class SecretBox:
    """Authenticated encryption for local at-rest secrets.

    New values are sealed with Fernet (AES-128-CBC + HMAC-SHA256), keyed by a
    scrypt-derived key from APP_SECRET. Legacy ``v1`` values written by the old
    hand-rolled stream cipher are still readable so existing databases keep
    working; they are transparently upgraded to ``v2`` on the next write.
    """

    def __init__(self, master_secret: str):
        self._legacy_key = hashlib.sha256(master_secret.encode("utf-8")).digest()
        self._fernet = Fernet(self._derive_key(master_secret))

    @staticmethod
    def _derive_key(master_secret: str) -> bytes:
        kdf = Scrypt(salt=_KDF_SALT, length=32, n=2**14, r=8, p=1)
        raw = kdf.derive(master_secret.encode("utf-8"))
        return base64.urlsafe_b64encode(raw)

    def seal(self, value: str | None) -> str:
        if not value:
            return ""
        token = self._fernet.encrypt(value.encode("utf-8")).decode("ascii")
        return f"v2.{token}"

    def open(self, sealed: str | None) -> str:
        if not sealed:
            return ""
        if sealed.startswith("v2."):
            try:
                return self._fernet.decrypt(sealed[3:].encode("ascii")).decode("utf-8")
            except (InvalidToken, ValueError) as exc:
                raise ValueError("Secret authentication failed") from exc
        if sealed.startswith("v1."):
            return self._open_legacy(sealed)
        raise ValueError("Unsupported secret format")

    def _open_legacy(self, sealed: str) -> str:
        payload = base64.urlsafe_b64decode(sealed[3:].encode("ascii"))
        nonce = payload[:16]
        mac = payload[16:48]
        cipher = payload[48:]
        expected = hmac.new(self._legacy_key, b"v1" + nonce + cipher, hashlib.sha256).digest()
        if not hmac.compare_digest(mac, expected):
            raise ValueError("Secret authentication failed")
        stream = self._legacy_stream(nonce, len(cipher))
        data = bytes(a ^ b for a, b in zip(cipher, stream, strict=True))
        return data.decode("utf-8")

    def _legacy_stream(self, nonce: bytes, length: int) -> bytes:
        output = bytearray()
        counter = 0
        while len(output) < length:
            block = hmac.new(
                self._legacy_key,
                nonce + counter.to_bytes(4, "big"),
                hashlib.sha256,
            ).digest()
            output.extend(block)
            counter += 1
        return bytes(output[:length])
