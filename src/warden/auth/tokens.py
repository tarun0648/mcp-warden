"""Issuing and verifying ES256 access tokens.

Only ES256 is accepted. That single rule closes the whole family of algorithm attacks: `none`,
HS256 signed with the published public key, and RS256 against an EC key. PyJWT is told exactly
one algorithm, so it never consults the token's own `alg` header to decide what to trust.

The revocation list lives in Redis, keyed by `jti`, with a TTL equal to the token's remaining
lifetime: once a token would have expired anyway, the entry removes itself.
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass
from typing import Any, Final, Protocol

import jwt
from jwt import PyJWTError

from warden.auth.jwt_keys import ALGORITHM, JwtKeyStore, KeyStoreError
from warden.logging import get_logger
from warden.pipeline import Principal

logger = get_logger(__name__)

AUTH_METHOD: Final = "jwt"
REVOCATION_KEY_PREFIX: Final = "warden:jwt:revoked:"
DEFAULT_TTL_SECONDS: Final = 900
MAX_TTL_SECONDS: Final = 86_400


class InvalidToken(Exception):
    """The presented token is not a usable access token."""


class RevocationStore(Protocol):
    """The slice of Redis the token verifier needs."""

    async def is_revoked(self, jti: str) -> bool: ...
    async def revoke(self, jti: str, ttl_seconds: int) -> None: ...


class NullRevocationStore:
    """Used when no Redis is configured. Fails closed is not possible here, so it is explicit.

    With no revocation store, a revoked token stays valid until it expires. The gateway logs a
    warning once at startup rather than pretending revocation works.
    """

    async def is_revoked(self, jti: str) -> bool:
        return False

    async def revoke(self, jti: str, ttl_seconds: int) -> None:
        logger.warning(
            "token revocation requested but no revocation store is configured",
            extra={"warden": {"jti": jti}},
        )


class RedisRevocationStore:
    """Revoked `jti` values in Redis, each expiring when the token would have expired."""

    def __init__(self, client: Any) -> None:
        self._client = client

    async def is_revoked(self, jti: str) -> bool:
        return bool(await self._client.exists(f"{REVOCATION_KEY_PREFIX}{jti}"))

    async def revoke(self, jti: str, ttl_seconds: int) -> None:
        await self._client.set(f"{REVOCATION_KEY_PREFIX}{jti}", "1", ex=max(ttl_seconds, 1))


@dataclass(frozen=True, slots=True)
class TokenConfig:
    """Everything the issuer and verifier agree on."""

    issuer: str
    audience: str
    #: The MCP authorization spec binds a token to the resource it is for; the gateway's
    #: resource URL is the audience, so a token for another server is rejected here.
    default_ttl_seconds: int = DEFAULT_TTL_SECONDS
    clock_skew_seconds: int = 30


@dataclass(frozen=True, slots=True)
class IssuedToken:
    token: str
    jti: str
    expires_at: int


class TokenService:
    """Issues and verifies access tokens against the key store."""

    def __init__(
        self,
        keys: JwtKeyStore,
        config: TokenConfig,
        revocations: RevocationStore | None = None,
    ) -> None:
        self._keys = keys
        self._config = config
        self._revocations = revocations if revocations is not None else NullRevocationStore()

    # -- issuing -------------------------------------------------------------------------

    def issue(
        self, user_id: str, roles: list[str], *, ttl_seconds: int | None = None
    ) -> IssuedToken:
        """Mint a token signed by the newest active key.

        A dev convenience: a real deployment plugs in an external OAuth 2.1 authorization
        server and the gateway only verifies. See docs/threat-model.md.
        """
        if not user_id:
            raise ValueError("user_id must not be empty")
        if not roles:
            raise ValueError("a token with no roles could never call anything; give it a role")
        ttl = ttl_seconds if ttl_seconds is not None else self._config.default_ttl_seconds
        if not 1 <= ttl <= MAX_TTL_SECONDS:
            raise ValueError(f"ttl must be between 1 and {MAX_TTL_SECONDS} seconds")
        kid = self._keys.read_state().signing_kid
        now = int(time.time())
        jti = secrets.token_urlsafe(16)
        claims: dict[str, Any] = {
            "iss": self._config.issuer,
            "aud": self._config.audience,
            "sub": user_id,
            "roles": list(roles),
            "iat": now,
            "nbf": now,
            "exp": now + ttl,
            "jti": jti,
        }
        token = jwt.encode(
            claims,
            self._keys.private_key_pem(kid).decode("ascii"),
            algorithm=ALGORITHM,
            headers={"kid": kid, "typ": "JWT"},
        )
        return IssuedToken(token=token, jti=jti, expires_at=now + ttl)

    # -- verifying -----------------------------------------------------------------------

    async def verify(self, token: str) -> Principal:
        """Return the principal a token proves, or raise `InvalidToken`."""
        try:
            header = jwt.get_unverified_header(token)
        except PyJWTError as exc:
            raise InvalidToken("malformed token") from exc

        # Refuse on the header's own claim before touching any key material: this is what
        # makes "alg=none" and the HS256-with-the-public-key trick dead on arrival.
        if header.get("alg") != ALGORITHM:
            raise InvalidToken(f"unsupported algorithm; only {ALGORITHM} is accepted")
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid:
            raise InvalidToken("token has no key id")

        try:
            state = self._keys.read_state()
        except KeyStoreError as exc:  # pragma: no cover - a misconfigured deployment
            raise InvalidToken("no verification keys are available") from exc
        if kid not in state.active:
            raise InvalidToken("unknown or retired key id")

        try:
            claims = jwt.decode(
                token,
                self._keys.public_key_pem(kid).decode("ascii"),
                algorithms=[ALGORITHM],
                audience=self._config.audience,
                issuer=self._config.issuer,
                leeway=self._config.clock_skew_seconds,
                options={
                    "require": ["iss", "aud", "sub", "exp", "iat", "nbf", "jti"],
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_nbf": True,
                    "verify_iat": True,
                    "verify_aud": True,
                    "verify_iss": True,
                },
            )
        except jwt.ExpiredSignatureError as exc:
            raise InvalidToken("token has expired") from exc
        except jwt.ImmatureSignatureError as exc:
            raise InvalidToken("token is not valid yet") from exc
        except jwt.InvalidAudienceError as exc:
            raise InvalidToken("token is for a different resource") from exc
        except jwt.InvalidIssuerError as exc:
            raise InvalidToken("token is from an unknown issuer") from exc
        except jwt.MissingRequiredClaimError as exc:
            raise InvalidToken(f"token is missing the {exc.claim} claim") from exc
        except PyJWTError as exc:
            raise InvalidToken("token signature is not valid") from exc

        jti = str(claims["jti"])
        if await self._revocations.is_revoked(jti):
            raise InvalidToken("token has been revoked")

        roles = claims.get("roles")
        if not isinstance(roles, list) or not all(isinstance(role, str) for role in roles):
            raise InvalidToken("token has no usable roles claim")
        subject = claims["sub"]
        if not isinstance(subject, str) or not subject:
            raise InvalidToken("token has an empty subject")

        return Principal(
            user_id=subject,
            roles=tuple(roles),
            auth_method=AUTH_METHOD,
            credential_id=jti,
        )

    async def revoke(self, token: str) -> str:
        """Revoke a token by its `jti`, for as long as it would otherwise have lived."""
        try:
            claims = jwt.decode(token, options={"verify_signature": False})
        except PyJWTError as exc:
            raise InvalidToken("malformed token") from exc
        jti = str(claims.get("jti", ""))
        if not jti:
            raise InvalidToken("token has no jti to revoke")
        remaining = int(claims.get("exp", 0)) - int(time.time())
        await self._revocations.revoke(jti, max(remaining, 1))
        return jti


def looks_like_jwt(credential: str) -> bool:
    """Three base64url segments separated by dots."""
    parts = credential.split(".")
    return len(parts) == 3 and all(parts)


__all__ = [
    "AUTH_METHOD",
    "InvalidToken",
    "IssuedToken",
    "NullRevocationStore",
    "RedisRevocationStore",
    "RevocationStore",
    "TokenConfig",
    "TokenService",
    "looks_like_jwt",
]
