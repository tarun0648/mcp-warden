"""ES256 signing keys on disk, and the JWKS document built from them.

Two keys are active at a time so a rotation does not invalidate tokens that are already in
flight: the newest active key signs, either active key verifies, and a retired key verifies
nothing. The private keys live in `./keys`, which is gitignored; a `detect-private-key`
pre-commit hook is the backstop.
"""

from __future__ import annotations

import base64
import json
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from warden.logging import get_logger

logger = get_logger(__name__)

ALGORITHM: Final = "ES256"
CURVE_NAME: Final = "P-256"
STATE_FILENAME: Final = "jwks-state.json"
MAX_ACTIVE_KEYS: Final = 2
PRIVATE_KEY_MODE: Final = 0o600
KEY_DIR_MODE: Final = 0o700


class KeyStoreError(Exception):
    """The key directory is missing, unreadable or inconsistent."""


@dataclass(frozen=True, slots=True)
class KeyState:
    """Which key ids sign, which still verify, and which are finished."""

    active: tuple[str, ...]
    retired: tuple[str, ...]

    @property
    def signing_kid(self) -> str:
        if not self.active:
            raise KeyStoreError("no active signing key; run `warden keys init-jwt`")
        return self.active[0]


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


class JwtKeyStore:
    """Reads, writes and rotates the ES256 key set in a directory."""

    def __init__(self, directory: Path) -> None:
        self.directory = Path(directory)

    # -- state ---------------------------------------------------------------------------

    @property
    def state_path(self) -> Path:
        return self.directory / STATE_FILENAME

    def private_key_path(self, kid: str) -> Path:
        return self.directory / f"jwt-{kid}.pem"

    def read_state(self) -> KeyState:
        if not self.state_path.exists():
            raise KeyStoreError(
                f"no JWT key state at {self.state_path}; run `warden keys init-jwt` first"
            )
        try:
            raw = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise KeyStoreError(f"could not read {self.state_path}: {exc}") from exc
        active = tuple(str(kid) for kid in raw.get("active", []))
        retired = tuple(str(kid) for kid in raw.get("retired", []))
        if not active:
            raise KeyStoreError(f"{self.state_path} lists no active key")
        for kid in active:
            if not self.private_key_path(kid).exists():
                raise KeyStoreError(f"active key '{kid}' has no private key file")
        return KeyState(active=active, retired=retired)

    def _write_state(self, state: KeyState) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)
        self.directory.chmod(KEY_DIR_MODE)
        self.state_path.write_text(
            json.dumps({"active": list(state.active), "retired": list(state.retired)}, indent=2),
            encoding="utf-8",
        )

    # -- key material --------------------------------------------------------------------

    def initialise(self) -> str:
        """Create the first signing key if there is none. Returns the active kid."""
        if self.state_path.exists():
            return self.read_state().signing_kid
        kid = self._generate()
        self._write_state(KeyState(active=(kid,), retired=()))
        logger.info("jwt signing key created", extra={"warden": {"kid": kid}})
        return kid

    def rotate(self) -> str:
        """Add a new signing key, keep the previous one verifying, retire anything older."""
        state = self.read_state()
        kid = self._generate()
        active = (kid, *state.active)[:MAX_ACTIVE_KEYS]
        retired = tuple(dict.fromkeys((*state.active[MAX_ACTIVE_KEYS - 1 :], *state.retired)))
        retired = tuple(k for k in retired if k not in active)
        self._write_state(KeyState(active=active, retired=retired))
        logger.info(
            "jwt signing key rotated",
            extra={"warden": {"new_kid": kid, "active": list(active), "retired": list(retired)}},
        )
        return kid

    def _generate(self) -> str:
        self.directory.mkdir(parents=True, exist_ok=True)
        self.directory.chmod(KEY_DIR_MODE)
        kid = secrets.token_hex(8)
        key = ec.generate_private_key(ec.SECP256R1())
        path = self.private_key_path(kid)
        path.write_bytes(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        path.chmod(PRIVATE_KEY_MODE)
        return kid

    def private_key_pem(self, kid: str) -> bytes:
        path = self.private_key_path(kid)
        if not path.exists():
            raise KeyStoreError(f"no private key for kid '{kid}'")
        return path.read_bytes()

    def load_private_key(self, kid: str) -> ec.EllipticCurvePrivateKey:
        key = serialization.load_pem_private_key(self.private_key_pem(kid), password=None)
        if not isinstance(key, ec.EllipticCurvePrivateKey):
            raise KeyStoreError(f"key '{kid}' is not an EC private key")
        return key

    def public_key(self, kid: str) -> ec.EllipticCurvePublicKey:
        return self.load_private_key(kid).public_key()

    def public_key_pem(self, kid: str) -> bytes:
        return self.public_key(kid).public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    # -- JWKS ----------------------------------------------------------------------------

    def jwk(self, kid: str) -> dict[str, Any]:
        """One public key in JWK form."""
        numbers = self.public_key(kid).public_numbers()
        size = (self.public_key(kid).curve.key_size + 7) // 8
        return {
            "kty": "EC",
            "crv": CURVE_NAME,
            "kid": kid,
            "use": "sig",
            "alg": ALGORITHM,
            "x": _b64url(numbers.x.to_bytes(size, "big")),
            "y": _b64url(numbers.y.to_bytes(size, "big")),
        }

    def jwks(self) -> dict[str, Any]:
        """The public document served at /.well-known/jwks.json.

        Only active keys are published. A retired key is not advertised and is not accepted, so
        a token signed by it is rejected rather than merely unverifiable.
        """
        state = self.read_state()
        return {"keys": [self.jwk(kid) for kid in state.active]}


__all__ = ["ALGORITHM", "MAX_ACTIVE_KEYS", "JwtKeyStore", "KeyState", "KeyStoreError"]
