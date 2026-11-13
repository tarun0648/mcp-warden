"""API keys: `wdn_` plus 32 url-safe random characters.

The database stores a SHA-256 hash and an 8-character prefix. The prefix narrows the lookup to
(normally) one row and gives operators a name to use in `warden keys revoke`; the hash is what
actually authenticates. Comparison is `hmac.compare_digest`, so a wrong key takes the same time
as a right one.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from typing import Final

from sqlalchemy import select

from warden.db.base import utcnow
from warden.db.engine import Database
from warden.db.models import ApiKey
from warden.logging import get_logger
from warden.pipeline import Principal

logger = get_logger(__name__)

KEY_PREFIX: Final = "wdn_"
#: 32 url-safe characters is 192 bits of entropy, well past anything brute-forceable.
KEY_RANDOM_CHARS: Final = 32
PREFIX_LENGTH: Final = 8
AUTH_METHOD: Final = "api_key"

_ALPHABET: Final = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"


class InvalidApiKey(Exception):
    """The presented credential is not a usable API key."""


@dataclass(frozen=True, slots=True)
class GeneratedKey:
    """A freshly minted key. `secret` is shown once and never stored."""

    secret: str
    prefix: str
    sha256: str


def generate_key() -> GeneratedKey:
    """Mint a new key: `wdn_` plus 32 random url-safe characters."""
    body = "".join(secrets.choice(_ALPHABET) for _ in range(KEY_RANDOM_CHARS))
    secret = f"{KEY_PREFIX}{body}"
    return GeneratedKey(secret=secret, prefix=key_prefix(secret), sha256=hash_key(secret))


def hash_key(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def key_prefix(secret: str) -> str:
    """The first 8 characters of the random part, used only to find candidate rows."""
    body = secret[len(KEY_PREFIX) :] if secret.startswith(KEY_PREFIX) else secret
    return body[:PREFIX_LENGTH]


def looks_like_api_key(credential: str) -> bool:
    """Cheap shape test, so a JWT is not pointlessly hashed and looked up."""
    return credential.startswith(KEY_PREFIX)


class ApiKeyStore:
    """Creates, lists, revokes and verifies API keys."""

    def __init__(self, database: Database) -> None:
        self._db = database

    async def create(
        self, user_id: str, roles: list[str], *, label: str | None = None
    ) -> GeneratedKey:
        """Mint a key, store its hash, and return the secret for the one time it is shown."""
        if not user_id:
            raise ValueError("user_id must not be empty")
        if not roles:
            raise ValueError("a key with no roles could never call anything; give it a role")
        generated = generate_key()
        async with self._db.session() as session:
            session.add(
                ApiKey(
                    key_sha256=generated.sha256,
                    key_prefix=generated.prefix,
                    user_id=user_id,
                    roles=list(roles),
                    label=label,
                )
            )
        logger.info(
            "api key created",
            extra={"warden": {"prefix": generated.prefix, "user_id": user_id, "roles": roles}},
        )
        return generated

    async def list_keys(self, *, include_revoked: bool = True) -> list[ApiKey]:
        async with self._db.session() as session:
            statement = select(ApiKey).order_by(ApiKey.created_at.desc())
            if not include_revoked:
                statement = statement.where(ApiKey.revoked_at.is_(None))
            return list((await session.execute(statement)).scalars())

    async def revoke(self, prefix: str) -> int:
        """Revoke every key with this prefix. Returns how many rows changed."""
        async with self._db.session() as session:
            rows = list(
                (
                    await session.execute(
                        select(ApiKey).where(
                            ApiKey.key_prefix == prefix, ApiKey.revoked_at.is_(None)
                        )
                    )
                ).scalars()
            )
            for row in rows:
                row.revoked_at = utcnow()
        if rows:
            logger.info(
                "api keys revoked", extra={"warden": {"prefix": prefix, "count": len(rows)}}
            )
        return len(rows)

    async def verify(self, credential: str) -> Principal:
        """Return the principal for a valid key, or raise `InvalidApiKey`.

        A prefix collision is handled by comparing the full hash of every candidate row, so two
        keys that happen to share a prefix cannot authenticate as each other.
        """
        if not looks_like_api_key(credential):
            raise InvalidApiKey("not an API key")
        presented_hash = hash_key(credential)
        prefix = key_prefix(credential)
        async with self._db.session() as session:
            candidates = list(
                (await session.execute(select(ApiKey).where(ApiKey.key_prefix == prefix))).scalars()
            )
            matched: ApiKey | None = None
            for row in candidates:
                if hmac.compare_digest(row.key_sha256, presented_hash):
                    matched = row
                    break
            if matched is None:
                raise InvalidApiKey("unknown API key")
            if matched.is_revoked:
                raise InvalidApiKey("this API key has been revoked")
            matched.last_used_at = utcnow()
            return Principal(
                user_id=matched.user_id,
                roles=tuple(matched.roles),
                auth_method=AUTH_METHOD,
                credential_id=matched.key_prefix,
            )


__all__ = [
    "AUTH_METHOD",
    "KEY_PREFIX",
    "ApiKeyStore",
    "GeneratedKey",
    "InvalidApiKey",
    "generate_key",
    "hash_key",
    "key_prefix",
    "looks_like_api_key",
]
