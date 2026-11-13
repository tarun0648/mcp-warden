"""ES256 tokens: every rejection path, plus key rotation and revocation."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from pathlib import Path
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from warden.auth.jwt_keys import ALGORITHM, JwtKeyStore, KeyStoreError
from warden.auth.tokens import (
    InvalidToken,
    NullRevocationStore,
    RedisRevocationStore,
    TokenConfig,
    TokenService,
    looks_like_jwt,
)

pytestmark = pytest.mark.unit


def claims_for(config: TokenConfig, **overrides: Any) -> dict[str, Any]:
    now = int(time.time())
    base = {
        "iss": config.issuer,
        "aud": config.audience,
        "sub": "alice",
        "roles": ["editor"],
        "iat": now,
        "nbf": now,
        "exp": now + 900,
        "jti": "jti-1",
    }
    base.update(overrides)
    return base


def sign_with(store: JwtKeyStore, kid: str, claims: dict[str, Any], **kwargs: Any) -> str:
    return jwt.encode(
        claims,
        store.private_key_pem(kid).decode("ascii"),
        algorithm=ALGORITHM,
        headers={"kid": kid, **kwargs.pop("headers", {})},
        **kwargs,
    )


# -- the happy path ----------------------------------------------------------------------------


async def test_issue_then_verify(tokens: TokenService) -> None:
    issued = tokens.issue("alice", ["reader", "editor"])
    principal = await tokens.verify(issued.token)
    assert principal.user_id == "alice"
    assert principal.roles == ("reader", "editor")
    assert principal.auth_method == "jwt"
    assert principal.credential_id == issued.jti


async def test_issued_token_carries_the_expected_header_and_claims(
    tokens: TokenService, jwt_store: JwtKeyStore
) -> None:
    issued = tokens.issue("alice", ["editor"], ttl_seconds=60)
    header = jwt.get_unverified_header(issued.token)
    assert header["alg"] == "ES256"
    assert header["kid"] == jwt_store.read_state().signing_kid
    body = jwt.decode(issued.token, options={"verify_signature": False})
    assert set(body) >= {"iss", "aud", "sub", "roles", "iat", "nbf", "exp", "jti"}
    assert body["exp"] - body["iat"] == 60


@pytest.mark.parametrize("ttl", [0, -1, 100_000])
def test_unreasonable_ttl_is_refused(tokens: TokenService, ttl: int) -> None:
    with pytest.raises(ValueError, match="ttl"):
        tokens.issue("alice", ["editor"], ttl_seconds=ttl)


def test_a_token_needs_a_subject_and_a_role(tokens: TokenService) -> None:
    with pytest.raises(ValueError, match="user_id"):
        tokens.issue("", ["editor"])
    with pytest.raises(ValueError, match="role"):
        tokens.issue("alice", [])


# -- rejection paths ---------------------------------------------------------------------------


async def test_expired_token_is_rejected(
    tokens: TokenService, jwt_store: JwtKeyStore, token_config: TokenConfig
) -> None:
    kid = jwt_store.read_state().signing_kid
    now = int(time.time())
    token = sign_with(
        jwt_store, kid, claims_for(token_config, iat=now - 7200, nbf=now - 7200, exp=now - 3600)
    )
    with pytest.raises(InvalidToken, match="expired"):
        await tokens.verify(token)


async def test_not_yet_valid_token_is_rejected(
    tokens: TokenService, jwt_store: JwtKeyStore, token_config: TokenConfig
) -> None:
    kid = jwt_store.read_state().signing_kid
    now = int(time.time())
    token = sign_with(jwt_store, kid, claims_for(token_config, nbf=now + 600, exp=now + 1200))
    with pytest.raises(InvalidToken, match="not valid yet"):
        await tokens.verify(token)


async def test_clock_skew_allowance_accepts_a_slightly_early_token(
    tokens: TokenService, jwt_store: JwtKeyStore, token_config: TokenConfig
) -> None:
    """30 seconds of skew is allowed, so a client with a fast clock still works."""
    kid = jwt_store.read_state().signing_kid
    now = int(time.time())
    token = sign_with(jwt_store, kid, claims_for(token_config, nbf=now + 10, iat=now + 10))
    assert (await tokens.verify(token)).user_id == "alice"


async def test_clock_skew_allowance_does_not_accept_a_long_expired_token(
    tokens: TokenService, jwt_store: JwtKeyStore, token_config: TokenConfig
) -> None:
    kid = jwt_store.read_state().signing_kid
    now = int(time.time())
    token = sign_with(jwt_store, kid, claims_for(token_config, exp=now - 60))
    with pytest.raises(InvalidToken, match="expired"):
        await tokens.verify(token)


async def test_wrong_audience_is_rejected(
    tokens: TokenService, jwt_store: JwtKeyStore, token_config: TokenConfig
) -> None:
    """A token minted for another MCP server must not work here."""
    kid = jwt_store.read_state().signing_kid
    token = sign_with(jwt_store, kid, claims_for(token_config, aud="http://other.example/mcp"))
    with pytest.raises(InvalidToken, match="different resource"):
        await tokens.verify(token)


async def test_wrong_issuer_is_rejected(
    tokens: TokenService, jwt_store: JwtKeyStore, token_config: TokenConfig
) -> None:
    kid = jwt_store.read_state().signing_kid
    token = sign_with(jwt_store, kid, claims_for(token_config, iss="http://evil.example"))
    with pytest.raises(InvalidToken, match="unknown issuer"):
        await tokens.verify(token)


async def test_bad_signature_is_rejected(
    tokens: TokenService, jwt_store: JwtKeyStore, token_config: TokenConfig
) -> None:
    """Signed by a key we never issued: right algorithm, right kid, wrong signer."""
    kid = jwt_store.read_state().signing_kid
    attacker_key = ec.generate_private_key(ec.SECP256R1())
    token = jwt.encode(
        claims_for(token_config), attacker_key, algorithm=ALGORITHM, headers={"kid": kid}
    )
    with pytest.raises(InvalidToken, match="signature"):
        await tokens.verify(token)


async def test_unknown_kid_is_rejected(
    tokens: TokenService, jwt_store: JwtKeyStore, token_config: TokenConfig
) -> None:
    kid = jwt_store.read_state().signing_kid
    token = sign_with(jwt_store, kid, claims_for(token_config))
    _, payload, signature = token.split(".")
    tampered_header = _b64url_json({"alg": "ES256", "kid": "deadbeef", "typ": "JWT"})
    with pytest.raises(InvalidToken, match="unknown or retired key id"):
        await tokens.verify(f"{tampered_header}.{payload}.{signature}")


async def test_missing_kid_is_rejected(
    tokens: TokenService, jwt_store: JwtKeyStore, token_config: TokenConfig
) -> None:
    kid = jwt_store.read_state().signing_kid
    token = jwt.encode(
        claims_for(token_config),
        jwt_store.private_key_pem(kid).decode("ascii"),
        algorithm=ALGORITHM,
    )
    with pytest.raises(InvalidToken, match="no key id"):
        await tokens.verify(token)


async def test_alg_none_is_rejected(tokens: TokenService, token_config: TokenConfig) -> None:
    """The oldest JWT attack: claim there is no signature and hope nobody checks."""
    header = _b64url_json({"alg": "none", "kid": "whatever", "typ": "JWT"})
    payload = _b64url_json(claims_for(token_config))
    with pytest.raises(InvalidToken, match="unsupported algorithm"):
        await tokens.verify(f"{header}.{payload}.")


async def test_hs256_signed_with_the_public_key_is_rejected(
    tokens: TokenService, jwt_store: JwtKeyStore, token_config: TokenConfig
) -> None:
    """Algorithm confusion: the public key is published, so if HS256 were accepted,
    anyone who read /.well-known/jwks.json could mint an admin token."""
    kid = jwt_store.read_state().signing_kid
    public_pem = jwt_store.public_key_pem(kid)
    # Hand-rolled, because PyJWT refuses to *encode* HS256 with a PEM key. An attacker has no
    # such guardrail, so the token has to be built the way they would build it.
    header = _b64url_json({"alg": "HS256", "kid": kid, "typ": "JWT"})
    payload = _b64url_json(claims_for(token_config))
    signing_input = f"{header}.{payload}".encode("ascii")
    signature = (
        base64.urlsafe_b64encode(hmac.new(public_pem, signing_input, hashlib.sha256).digest())
        .rstrip(b"=")
        .decode()
    )
    forged = f"{header}.{payload}.{signature}"
    with pytest.raises(InvalidToken, match="unsupported algorithm"):
        await tokens.verify(forged)


async def test_rs256_is_rejected(
    tokens: TokenService, jwt_store: JwtKeyStore, token_config: TokenConfig
) -> None:
    from cryptography.hazmat.primitives.asymmetric import rsa

    kid = jwt_store.read_state().signing_kid
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    token = jwt.encode(claims_for(token_config), rsa_key, algorithm="RS256", headers={"kid": kid})
    with pytest.raises(InvalidToken, match="unsupported algorithm"):
        await tokens.verify(token)


@pytest.mark.parametrize("claim", ["iss", "aud", "sub", "exp", "iat", "nbf", "jti"])
async def test_missing_required_claim_is_rejected(
    tokens: TokenService, jwt_store: JwtKeyStore, token_config: TokenConfig, claim: str
) -> None:
    kid = jwt_store.read_state().signing_kid
    claims = claims_for(token_config)
    del claims[claim]
    token = sign_with(jwt_store, kid, claims)
    with pytest.raises(InvalidToken):
        await tokens.verify(token)


async def test_missing_roles_claim_is_rejected(
    tokens: TokenService, jwt_store: JwtKeyStore, token_config: TokenConfig
) -> None:
    kid = jwt_store.read_state().signing_kid
    claims = claims_for(token_config)
    del claims["roles"]
    with pytest.raises(InvalidToken, match="roles"):
        await tokens.verify(sign_with(jwt_store, kid, claims))


@pytest.mark.parametrize("roles", ["editor", [1, 2], {"a": 1}])
async def test_malformed_roles_claim_is_rejected(
    tokens: TokenService, jwt_store: JwtKeyStore, token_config: TokenConfig, roles: Any
) -> None:
    kid = jwt_store.read_state().signing_kid
    token = sign_with(jwt_store, kid, claims_for(token_config, roles=roles))
    with pytest.raises(InvalidToken, match="roles"):
        await tokens.verify(token)


async def test_empty_subject_is_rejected(
    tokens: TokenService, jwt_store: JwtKeyStore, token_config: TokenConfig
) -> None:
    kid = jwt_store.read_state().signing_kid
    token = sign_with(jwt_store, kid, claims_for(token_config, sub=""))
    with pytest.raises(InvalidToken):
        await tokens.verify(token)


@pytest.mark.parametrize("garbage", ["", "not-a-token", "a.b", "a.b.c.d", "...", "x" * 100])
async def test_malformed_tokens_are_rejected(tokens: TokenService, garbage: str) -> None:
    with pytest.raises(InvalidToken):
        await tokens.verify(garbage)


# -- revocation --------------------------------------------------------------------------------


async def test_revoked_jti_is_rejected(tokens: TokenService) -> None:
    issued = tokens.issue("alice", ["editor"])
    assert (await tokens.verify(issued.token)).user_id == "alice"
    assert await tokens.revoke(issued.token) == issued.jti
    with pytest.raises(InvalidToken, match="revoked"):
        await tokens.verify(issued.token)


async def test_revocation_entry_expires_with_the_token(
    tokens: TokenService, fake_redis: Any
) -> None:
    """The entry's TTL is the token's remaining lifetime; after that it is pointless."""
    issued = tokens.issue("alice", ["editor"], ttl_seconds=120)
    await tokens.revoke(issued.token)
    ttl = await fake_redis.ttl(f"warden:jwt:revoked:{issued.jti}")
    assert 0 < ttl <= 120


async def test_revoking_another_token_does_not_affect_this_one(tokens: TokenService) -> None:
    keep = tokens.issue("alice", ["editor"])
    drop = tokens.issue("bob", ["editor"])
    await tokens.revoke(drop.token)
    assert (await tokens.verify(keep.token)).user_id == "alice"


async def test_revoking_a_malformed_token_is_an_error(tokens: TokenService) -> None:
    with pytest.raises(InvalidToken):
        await tokens.revoke("nonsense")


async def test_null_revocation_store_is_explicit_about_doing_nothing(
    jwt_store: JwtKeyStore, token_config: TokenConfig
) -> None:
    service = TokenService(jwt_store, token_config, NullRevocationStore())
    issued = service.issue("alice", ["editor"])
    await service.revoke(issued.token)
    assert (await service.verify(issued.token)).user_id == "alice"


async def test_a_failing_revocation_store_fails_closed(
    jwt_store: JwtKeyStore, token_config: TokenConfig
) -> None:
    """If we cannot tell whether a token was revoked, we must not accept it."""

    class BrokenStore:
        async def is_revoked(self, jti: str) -> bool:
            raise ConnectionError("redis is down")

        async def revoke(self, jti: str, ttl_seconds: int) -> None:  # pragma: no cover
            raise ConnectionError("redis is down")

    service = TokenService(jwt_store, token_config, BrokenStore())
    issued = service.issue("alice", ["editor"])
    with pytest.raises(ConnectionError):
        await service.verify(issued.token)


# -- rotation ----------------------------------------------------------------------------------


async def test_both_active_kids_verify_after_rotation(
    jwt_store: JwtKeyStore, token_config: TokenConfig, fake_redis: Any
) -> None:
    service = TokenService(jwt_store, token_config, RedisRevocationStore(fake_redis))
    old_token = service.issue("alice", ["editor"]).token
    jwt_store.rotate()
    new_token = service.issue("bob", ["editor"]).token

    state = jwt_store.read_state()
    assert len(state.active) == 2
    assert (await service.verify(old_token)).user_id == "alice"
    assert (await service.verify(new_token)).user_id == "bob"


async def test_a_retired_kid_is_rejected(
    jwt_store: JwtKeyStore, token_config: TokenConfig, fake_redis: Any
) -> None:
    service = TokenService(jwt_store, token_config, RedisRevocationStore(fake_redis))
    first_token = service.issue("alice", ["editor"]).token
    jwt_store.rotate()
    jwt_store.rotate()  # the first key is now retired
    state = jwt_store.read_state()
    assert len(state.active) == 2
    assert len(state.retired) == 1
    with pytest.raises(InvalidToken, match="unknown or retired key id"):
        await service.verify(first_token)


def test_rotation_keeps_at_most_two_active_keys(jwt_store: JwtKeyStore) -> None:
    for _ in range(5):
        jwt_store.rotate()
    state = jwt_store.read_state()
    assert len(state.active) == 2
    assert len(state.retired) == 4
    assert not set(state.active) & set(state.retired)


def test_jwks_publishes_only_active_public_keys(jwt_store: JwtKeyStore) -> None:
    jwt_store.rotate()
    document = jwt_store.jwks()
    state = jwt_store.read_state()
    assert [key["kid"] for key in document["keys"]] == list(state.active)
    for key in document["keys"]:
        assert key["kty"] == "EC" and key["crv"] == "P-256" and key["alg"] == "ES256"
        assert set(key) == {"kty", "crv", "kid", "use", "alg", "x", "y"}
        assert "d" not in key, "the private scalar must never be published"


def test_jwks_document_contains_no_private_key_material(jwt_store: JwtKeyStore) -> None:
    serialised = json.dumps(jwt_store.jwks())
    assert "PRIVATE" not in serialised
    assert "BEGIN" not in serialised


def test_private_keys_are_written_with_restrictive_permissions(tmp_path: Path) -> None:
    store = JwtKeyStore(tmp_path / "keys")
    kid = store.initialise()
    mode = store.private_key_path(kid).stat().st_mode & 0o777
    assert mode == 0o600, f"private key is mode {oct(mode)}"


def test_reading_state_before_init_is_a_clear_error(tmp_path: Path) -> None:
    store = JwtKeyStore(tmp_path / "missing")
    with pytest.raises(KeyStoreError, match="init-jwt"):
        store.read_state()


def test_initialise_is_idempotent(tmp_path: Path) -> None:
    store = JwtKeyStore(tmp_path / "keys")
    assert store.initialise() == store.initialise()


@pytest.mark.parametrize("value", ["a.b.c", "eyJ.eyJ.sig"])
def test_looks_like_jwt(value: str) -> None:
    assert looks_like_jwt(value)


@pytest.mark.parametrize("value", ["wdn_abc", "a.b", "a..c", "", "a.b.c.d"])
def test_does_not_look_like_jwt(value: str) -> None:
    assert not looks_like_jwt(value)


def _b64url_json(data: dict[str, Any]) -> str:
    raw = json.dumps(data, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
