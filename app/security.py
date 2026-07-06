import base64
import hashlib
import hmac
import os


class SecretBox:
    """Small reversible seal for local MVP storage.

    Replace this with OS keychain, KMS, or cryptography.Fernet before production.
    """

    def __init__(self, master_secret: str):
        self._key = hashlib.sha256(master_secret.encode("utf-8")).digest()

    def seal(self, value: str | None) -> str:
        if not value:
            return ""
        nonce = os.urandom(16)
        data = value.encode("utf-8")
        stream = self._stream(nonce, len(data))
        cipher = bytes(a ^ b for a, b in zip(data, stream))
        mac = hmac.new(self._key, b"v1" + nonce + cipher, hashlib.sha256).digest()
        payload = nonce + mac + cipher
        encoded = base64.urlsafe_b64encode(payload).decode("ascii")
        return f"v1.{encoded}"

    def open(self, sealed: str | None) -> str:
        if not sealed:
            return ""
        if not sealed.startswith("v1."):
            raise ValueError("Unsupported secret format")
        payload = base64.urlsafe_b64decode(sealed[3:].encode("ascii"))
        nonce = payload[:16]
        mac = payload[16:48]
        cipher = payload[48:]
        expected = hmac.new(self._key, b"v1" + nonce + cipher, hashlib.sha256).digest()
        if not hmac.compare_digest(mac, expected):
            raise ValueError("Secret authentication failed")
        stream = self._stream(nonce, len(cipher))
        data = bytes(a ^ b for a, b in zip(cipher, stream))
        return data.decode("utf-8")

    def _stream(self, nonce: bytes, length: int) -> bytes:
        output = bytearray()
        counter = 0
        while len(output) < length:
            block = hmac.new(
                self._key,
                nonce + counter.to_bytes(4, "big"),
                hashlib.sha256,
            ).digest()
            output.extend(block)
            counter += 1
        return bytes(output[:length])

