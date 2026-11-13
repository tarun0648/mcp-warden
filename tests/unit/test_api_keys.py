"""API keys: shape, hashing, revocation, prefix collisions, and no secret at rest."""

from __future__ import annotations

from typing import Any

import pytest
from sqlalchemy import select, text

from warden.auth.api_keys import (
    KEY_PREFIX,
    ApiKeyStore,
    InvalidApiKey,
    generate_key,
    hash_key,
    key_prefix,
    looks_like_api_key,
)
from warden.db.models import ApiKey

pytestmark = pytest.mark.unit


def test_generated_key_shape() -> None:
    generated = generate_key()
    assert generated.secret.startswith(KEY_PREFIX)
    assert len(generated.secret) == len(KEY_PREFIX) + 32
    assert generated.prefix == generated.secret[len(KEY_PREFIX) :][:8]
    assert generated.sha256 == hash_key(generated.secret)
    assert len(generated.sha256) == 64


def test_generated_keys_are_unique() -> None:
    secrets_seen = {generate_key().secret for _ in range(200)}
    assert len(secrets_seen) == 200


@pytest.mark.parametrize("value", ["wdn_abc", "wdn_"])
def test_looks_like_api_key(value: str) -> None:
    assert looks_like_api_key(value)


@pytest.mark.parametrize("value", ["eyJhbGciOi.abc.def", "Bearer wdn_x", "", "wdn-abc"])
def test_does_not_look_like_api_key(value: str) -> None:
    assert not looks_like_api_key(value)


async def test_create_then_verify(api_keys: ApiKeyStore) -> None:
    generated = await api_keys.create("alice", ["reader", "editor"], label="laptop")
    principal = await api_keys.verify(generated.secret)
    assert principal.user_id == "alice"
    assert principal.roles == ("reader", "editor")
    assert principal.auth_method == "api_key"
    assert principal.credential_id == generated.prefix


async def test_verify_records_last_used(api_keys: ApiKeyStore) -> None:
    generated = await api_keys.create("alice", ["reader"])
    assert (await api_keys.list_keys())[0].last_used_at is None
    await api_keys.verify(generated.secret)
    assert (await api_keys.list_keys())[0].last_used_at is not None


async def test_wrong_key_is_rejected(api_keys: ApiKeyStore) -> None:
    await api_keys.create("alice", ["reader"])
    with pytest.raises(InvalidApiKey, match="unknown"):
        await api_keys.verify(generate_key().secret)


async def test_revoked_key_is_rejected(api_keys: ApiKeyStore) -> None:
    generated = await api_keys.create("alice", ["reader"])
    assert await api_keys.verify(generated.secret)
    assert await api_keys.revoke(generated.prefix) == 1
    with pytest.raises(InvalidApiKey, match="revoked"):
        await api_keys.verify(generated.secret)


async def test_revoking_an_unknown_prefix_changes_nothing(api_keys: ApiKeyStore) -> None:
    assert await api_keys.revoke("nosuch01") == 0


async def test_prefix_collision_does_not_let_one_key_pass_as_another(
    api_keys: ApiKeyStore, database: Any
) -> None:
    """Two keys that genuinely share a prefix must each authenticate only as themselves.

    The prefix only narrows the lookup. If it decided anything, the holder of one key could
    authenticate as the owner of the other.
    """
    shared = "SAMEPRFX"
    alice_secret = f"{KEY_PREFIX}{shared}" + "a" * 24
    bob_secret = f"{KEY_PREFIX}{shared}" + "b" * 24
    assert key_prefix(alice_secret) == key_prefix(bob_secret) == shared
    assert hash_key(alice_secret) != hash_key(bob_secret)

    async with database.session() as session:
        session.add(
            ApiKey(
                key_sha256=hash_key(alice_secret),
                key_prefix=shared,
                user_id="alice",
                roles=["reader"],
            )
        )
        session.add(
            ApiKey(
                key_sha256=hash_key(bob_secret),
                key_prefix=shared,
                user_id="bob",
                roles=["admin"],
            )
        )

    alice = await api_keys.verify(alice_secret)
    bob = await api_keys.verify(bob_secret)
    assert (alice.user_id, alice.roles) == ("alice", ("reader",))
    assert (bob.user_id, bob.roles) == ("bob", ("admin",))

    # A third key with the same prefix but an unknown body is still refused.
    with pytest.raises(InvalidApiKey, match="unknown"):
        await api_keys.verify(f"{KEY_PREFIX}{shared}" + "c" * 24)


async def test_revoking_a_shared_prefix_revokes_both(api_keys: ApiKeyStore, database: Any) -> None:
    """`revoke <prefix>` is prefix-scoped, so an operator must know it affects every match."""
    shared = "SAMEPRFX"
    first = f"{KEY_PREFIX}{shared}" + "a" * 24
    second = f"{KEY_PREFIX}{shared}" + "b" * 24
    async with database.session() as session:
        for user, secret in (("alice", first), ("bob", second)):
            session.add(
                ApiKey(
                    key_sha256=hash_key(secret),
                    key_prefix=shared,
                    user_id=user,
                    roles=["reader"],
                )
            )
    assert await api_keys.revoke(shared) == 2
    for secret in (first, second):
        with pytest.raises(InvalidApiKey, match="revoked"):
            await api_keys.verify(secret)


async def test_the_raw_key_is_never_stored(api_keys: ApiKeyStore, database: Any) -> None:
    """Hard rule 2: no column anywhere may contain the secret."""
    generated = await api_keys.create("alice", ["reader"])
    async with database.session() as session:
        rows = (await session.execute(text("SELECT * FROM api_keys"))).mappings().all()
    serialised = repr([dict(row) for row in rows])
    assert generated.secret not in serialised
    assert generated.sha256 in serialised, "the hash is what we do store"


async def test_as_dict_never_exposes_the_hash(api_keys: ApiKeyStore) -> None:
    """The hash is still a verifier, so it must not reach a CLI table or an API response."""
    generated = await api_keys.create("alice", ["reader"])
    summary = (await api_keys.list_keys())[0].as_dict()
    assert generated.sha256 not in repr(summary)
    assert generated.secret not in repr(summary)
    assert summary["prefix"] == generated.prefix


async def test_list_can_hide_revoked_keys(api_keys: ApiKeyStore) -> None:
    kept = await api_keys.create("alice", ["reader"])
    dropped = await api_keys.create("bob", ["reader"])
    await api_keys.revoke(dropped.prefix)
    active = await api_keys.list_keys(include_revoked=False)
    assert [key.key_prefix for key in active] == [kept.prefix]
    assert len(await api_keys.list_keys()) == 2


async def test_a_key_must_have_a_user_and_a_role(api_keys: ApiKeyStore) -> None:
    with pytest.raises(ValueError, match="user_id"):
        await api_keys.create("", ["reader"])
    with pytest.raises(ValueError, match="role"):
        await api_keys.create("alice", [])


async def test_verify_rejects_something_that_is_not_a_key(api_keys: ApiKeyStore) -> None:
    with pytest.raises(InvalidApiKey, match="not an API key"):
        await api_keys.verify("eyJhbGci.abc.def")


def test_key_prefix_handles_a_value_without_the_marker() -> None:
    assert key_prefix("abcdefghijkl") == "abcdefgh"


async def test_unique_hash_constraint(api_keys: ApiKeyStore, database: Any) -> None:
    """The same secret can never be registered twice."""
    from sqlalchemy.exc import IntegrityError

    generated = await api_keys.create("alice", ["reader"])
    with pytest.raises(IntegrityError):
        async with database.session() as session:
            session.add(
                ApiKey(
                    key_sha256=generated.sha256,
                    key_prefix=generated.prefix,
                    user_id="bob",
                    roles=["admin"],
                )
            )
    async with database.session() as session:
        count = len((await session.execute(select(ApiKey))).scalars().all())
    assert count == 1
