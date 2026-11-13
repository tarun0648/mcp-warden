"""HTTP authentication for the MCP endpoint and the admin surface.

A missing or bad credential is a *protocol* problem, so it answers HTTP 401 with a
`WWW-Authenticate` header pointing at the protected-resource metadata, per the MCP
authorization spec. Only decisions about an authenticated caller's *permissions* come back as
MCP tool results with a `WARDEN_DENIED:*` code.

The verified principal is attached to the ASGI scope. The MCP layer reads it from there, so a
credential is verified exactly once per HTTP request and the raw credential never travels
further into the gateway.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Final

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from warden.auth.api_keys import ApiKeyStore, InvalidApiKey, looks_like_api_key
from warden.auth.tokens import InvalidToken, TokenService, looks_like_jwt
from warden.logging import get_logger, principal_id_var
from warden.pipeline import Principal

logger = get_logger(__name__)

#: Where the verified principal lives on the ASGI scope.
SCOPE_PRINCIPAL_KEY: Final = "warden.principal"
BEARER_PREFIX: Final = "bearer "
MAX_CREDENTIAL_LENGTH: Final = 8192


class AuthenticationFailed(Exception):
    """The credential could not be verified. The message is safe to return to the client."""


@dataclass(slots=True)
class Authenticator:
    """Verifies either credential type and returns the principal it proves.

    The credential's *shape* picks the verifier; it is never used to decide trust. A string
    that looks like neither is refused without a database lookup.
    """

    api_keys: ApiKeyStore | None = None
    tokens: TokenService | None = None

    async def authenticate(self, credential: str) -> Principal:
        if not credential or len(credential) > MAX_CREDENTIAL_LENGTH:
            raise AuthenticationFailed("credential is missing or too long")
        if looks_like_api_key(credential):
            if self.api_keys is None:
                raise AuthenticationFailed("API keys are not enabled on this gateway")
            try:
                return await self.api_keys.verify(credential)
            except InvalidApiKey as exc:
                raise AuthenticationFailed(str(exc)) from exc
        if looks_like_jwt(credential):
            if self.tokens is None:
                raise AuthenticationFailed("bearer tokens are not enabled on this gateway")
            try:
                return await self.tokens.verify(credential)
            except InvalidToken as exc:
                raise AuthenticationFailed(str(exc)) from exc
        raise AuthenticationFailed("credential is not a recognised format")


def extract_bearer(headers: Sequence[tuple[bytes, bytes]]) -> str | None:
    """The credential from an `Authorization: Bearer <value>` header, or None.

    Any other scheme - Basic, Digest - returns None, which becomes a 401 naming Bearer.
    """
    for key, value in headers:
        if bytes(key).lower() != b"authorization":
            continue
        raw = bytes(value).decode("latin-1").strip()
        if raw.lower().startswith(BEARER_PREFIX):
            candidate = raw[len(BEARER_PREFIX) :].strip()
            return candidate or None
        return None
    return None


class AuthMiddleware:
    """Requires a valid credential on the protected path prefixes."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        authenticator: Authenticator,
        protected_prefixes: Sequence[str],
        resource_metadata_url: str,
        realm: str = "mcp-warden",
    ) -> None:
        self.app = app
        self._authenticator = authenticator
        self._prefixes = tuple(protected_prefixes)
        self._resource_metadata_url = resource_metadata_url
        self._realm = realm

    def _is_protected(self, path: str) -> bool:
        return any(path == prefix or path.startswith(f"{prefix}/") for prefix in self._prefixes)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not self._is_protected(scope.get("path", "")):
            await self.app(scope, receive, send)
            return

        credential = extract_bearer(scope.get("headers", []))
        if credential is None:
            await self._unauthorized(scope, receive, send, "a Bearer credential is required")
            return
        try:
            principal = await self._authenticator.authenticate(credential)
        except AuthenticationFailed as exc:
            # The reason is deliberately coarse and never echoes the credential.
            logger.info(
                "authentication failed",
                extra={"warden": {"path": scope.get("path"), "reason": str(exc)}},
            )
            await self._unauthorized(scope, receive, send, str(exc))
            return
        except Exception:
            logger.exception("authentication backend failed")
            await self._unauthorized(scope, receive, send, "authentication is unavailable")
            return

        scope[SCOPE_PRINCIPAL_KEY] = principal
        token = principal_id_var.set(principal.user_id)
        try:
            await self.app(scope, receive, send)
        finally:
            principal_id_var.reset(token)

    async def _unauthorized(self, scope: Scope, receive: Receive, send: Send, reason: str) -> None:
        response = JSONResponse(
            {"error": "unauthorized", "error_description": reason},
            status_code=401,
            headers={
                "WWW-Authenticate": (
                    f'Bearer realm="{self._realm}", '
                    f'resource_metadata="{self._resource_metadata_url}"'
                )
            },
        )
        await response(scope, receive, send)


def principal_from_scope(scope: Scope | None) -> Principal | None:
    """Read the verified principal the middleware attached, if any."""
    if not scope:
        return None
    value = scope.get(SCOPE_PRINCIPAL_KEY)
    return value if isinstance(value, Principal) else None


def principal_from_request(request: Any) -> Principal | None:
    """Read the principal from a Starlette request, as MCP handlers receive it."""
    if request is None:
        return None
    scope = getattr(request, "scope", None)
    return principal_from_scope(scope)


__all__ = [
    "SCOPE_PRINCIPAL_KEY",
    "AuthMiddleware",
    "AuthenticationFailed",
    "Authenticator",
    "extract_bearer",
    "principal_from_request",
    "principal_from_scope",
]
