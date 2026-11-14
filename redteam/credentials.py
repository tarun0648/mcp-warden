"""Forged and broken credentials, for the auth-forgery cases.

Each builder returns a string to put in `Authorization: Bearer ...`. They are built by hand
rather than through PyJWT where PyJWT would refuse: an attacker has no such guardrail, and a
test that goes through the library's own checks tests the library, not the gateway.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric import ec

from warden.auth.jwt_keys import ALGORITHM, JwtKeyStore


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _segment(data: dict[str, Any]) -> str:
    return _b64url(json.dumps(data, separators=(",", ":")).encode())


def _claims(issuer: str, audience: str, **overrides: Any) -> dict[str, Any]:
    now = int(time.time())
    claims: dict[str, Any] = {
        "iss": issuer,
        "aud": audience,
        "sub": "attacker",
        "roles": ["admin"],
        "iat": now,
        "nbf": now,
        "exp": now + 900,
        "jti": "forged-jti",
    }
    claims.update(overrides)
    return claims


class CredentialForge:
    """Builds the credentials the auth-forgery cases present."""

    def __init__(self, *, key_dir: Path, issuer: str, audience: str) -> None:
        self.keys = JwtKeyStore(key_dir)
        self.issuer = issuer
        self.audience = audience

    # -- the shapes ----------------------------------------------------------------------

    def valid(self) -> str:
        """A genuine token, so the suite proves the negative case too."""
        kid = self.keys.read_state().signing_kid
        return jwt.encode(
            _claims(self.issuer, self.audience),
            self.keys.private_key_pem(kid).decode(),
            algorithm=ALGORITHM,
            headers={"kid": kid},
        )

    def expired(self) -> str:
        kid = self.keys.read_state().signing_kid
        now = int(time.time())
        return jwt.encode(
            _claims(self.issuer, self.audience, iat=now - 7200, nbf=now - 7200, exp=now - 3600),
            self.keys.private_key_pem(kid).decode(),
            algorithm=ALGORITHM,
            headers={"kid": kid},
        )

    def not_yet_valid(self) -> str:
        kid = self.keys.read_state().signing_kid
        now = int(time.time())
        return jwt.encode(
            _claims(self.issuer, self.audience, nbf=now + 3600, exp=now + 7200),
            self.keys.private_key_pem(kid).decode(),
            algorithm=ALGORITHM,
            headers={"kid": kid},
        )

    def wrong_audience(self) -> str:
        kid = self.keys.read_state().signing_kid
        return jwt.encode(
            _claims(self.issuer, "https://some-other-mcp-server.example/mcp"),
            self.keys.private_key_pem(kid).decode(),
            algorithm=ALGORITHM,
            headers={"kid": kid},
        )

    def wrong_issuer(self) -> str:
        kid = self.keys.read_state().signing_kid
        return jwt.encode(
            _claims("https://attacker.example", self.audience),
            self.keys.private_key_pem(kid).decode(),
            algorithm=ALGORITHM,
            headers={"kid": kid},
        )

    def signed_by_a_stranger(self) -> str:
        """Right shape, right kid, signed with a key the gateway never issued."""
        kid = self.keys.read_state().signing_kid
        return jwt.encode(
            _claims(self.issuer, self.audience),
            ec.generate_private_key(ec.SECP256R1()),
            algorithm=ALGORITHM,
            headers={"kid": kid},
        )

    def unknown_kid(self) -> str:
        kid = self.keys.read_state().signing_kid
        token = jwt.encode(
            _claims(self.issuer, self.audience),
            self.keys.private_key_pem(kid).decode(),
            algorithm=ALGORITHM,
            headers={"kid": kid},
        )
        _, payload, signature = token.split(".")
        header = _segment({"alg": ALGORITHM, "kid": "deadbeefdeadbeef", "typ": "JWT"})
        return f"{header}.{payload}.{signature}"

    def alg_none(self) -> str:
        """The oldest JWT attack: claim there is no signature."""
        header = _segment({"alg": "none", "typ": "JWT", "kid": "whatever"})
        return f"{header}.{_segment(_claims(self.issuer, self.audience))}."

    def alg_confusion_hs256(self) -> str:
        """HS256 signed with the published public key.

        Hand-rolled because PyJWT refuses to encode HS256 with a PEM key. If the gateway
        accepted this, anyone who read /.well-known/jwks.json could mint an admin token.
        """
        kid = self.keys.read_state().signing_kid
        public_pem = self.keys.public_key_pem(kid)
        header = _segment({"alg": "HS256", "kid": kid, "typ": "JWT"})
        payload = _segment(_claims(self.issuer, self.audience))
        signing_input = f"{header}.{payload}".encode("ascii")
        signature = _b64url(hmac.new(public_pem, signing_input, hashlib.sha256).digest())
        return f"{header}.{payload}.{signature}"

    def unsigned_payload_swap(self) -> str:
        """A valid token whose payload has been edited to claim the admin role."""
        kid = self.keys.read_state().signing_kid
        token = jwt.encode(
            _claims(self.issuer, self.audience, sub="reader-user", roles=["reader"]),
            self.keys.private_key_pem(kid).decode(),
            algorithm=ALGORITHM,
            headers={"kid": kid},
        )
        header, _payload, signature = token.split(".")
        escalated = _segment(
            _claims(self.issuer, self.audience, sub="reader-user", roles=["admin"])
        )
        return f"{header}.{escalated}.{signature}"

    def missing_claims(self) -> str:
        kid = self.keys.read_state().signing_kid
        return jwt.encode(
            {"sub": "attacker", "roles": ["admin"], "exp": int(time.time()) + 900},
            self.keys.private_key_pem(kid).decode(),
            algorithm=ALGORITHM,
            headers={"kid": kid},
        )

    def invented_api_key(self) -> str:
        return "wdn_" + "A" * 32

    def truncated_api_key(self) -> str:
        return "wdn_short"

    def not_a_credential(self) -> str:
        return "hunter2"

    def empty(self) -> str:
        return ""

    # -- lookup --------------------------------------------------------------------------

    def build(self, name: str) -> str:
        builders: dict[str, Callable[[], str]] = {
            "valid": self.valid,
            "expired": self.expired,
            "not_yet_valid": self.not_yet_valid,
            "wrong_audience": self.wrong_audience,
            "wrong_issuer": self.wrong_issuer,
            "signed_by_a_stranger": self.signed_by_a_stranger,
            "unknown_kid": self.unknown_kid,
            "alg_none": self.alg_none,
            "alg_confusion_hs256": self.alg_confusion_hs256,
            "unsigned_payload_swap": self.unsigned_payload_swap,
            "missing_claims": self.missing_claims,
            "invented_api_key": self.invented_api_key,
            "truncated_api_key": self.truncated_api_key,
            "not_a_credential": self.not_a_credential,
            "empty": self.empty,
        }
        if name not in builders:
            raise ValueError(f"unknown credential '{name}'; have {sorted(builders)}")
        return builders[name]()

    @property
    def names(self) -> list[str]:
        return [
            "valid",
            "expired",
            "not_yet_valid",
            "wrong_audience",
            "wrong_issuer",
            "signed_by_a_stranger",
            "unknown_kid",
            "alg_none",
            "alg_confusion_hs256",
            "unsigned_payload_swap",
            "missing_claims",
            "invented_api_key",
            "truncated_api_key",
            "not_a_credential",
            "empty",
        ]


__all__ = ["CredentialForge"]
