"""The Authenticate pipeline stage.

HTTP authentication already happened in the middleware; this stage is the pipeline's assertion
that it did. If no principal reached the context - a transport without the middleware, a
misconfigured mount, a bug - the call is denied rather than run as an anonymous caller
(hard rule 1).
"""

from __future__ import annotations

from warden.errors import ReasonCode
from warden.pipeline import RequestContext


class Authenticate:
    """Refuse any request that arrived without a verified principal."""

    name = "authenticate"

    async def run(self, ctx: RequestContext) -> None:
        if ctx.principal is None:
            ctx.deny(ReasonCode.DENIED_AUTH, "the caller is not authenticated")
            return
        if not ctx.principal.roles:
            ctx.deny(
                ReasonCode.DENIED_AUTH,
                "the credential carries no roles, so no tool could be allowed",
            )


__all__ = ["Authenticate"]
