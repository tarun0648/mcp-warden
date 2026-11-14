"""A ten-case slice of the red-team suite, inside `make test`.

The full suite takes minutes and starts a dozen gateways, so it is `make redteam`. This slice
runs on every commit: one case from each attack category plus two benign ones, against one
gateway. Its job is to catch "the suite no longer runs at all" long before someone discovers it
at release time.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from redteam.credentials import CredentialForge
from redteam.model import load_cases
from redteam.runner import CASES_DIR, CaseRunner, redteam_gateway

pytestmark = pytest.mark.integration

#: One per attack category that needs no special gateway profile, plus two benign cases. Cases
#: with their own gateway overrides are left to the full run: the point here is breadth of
#: category, not breadth of configuration.
SMOKE_IDS = (
    "tp-001-poisoned-tool-quarantined",
    "sh-001-shadow-tool-refused",
    "ij-001-plain-injection-in-output-blocked",
    "dlp-002-ssh-private-key-refused",
    "pe-001-reader-cannot-delete-a-file",
    "cb-001-path-traversal-in-a-write",
    "af-008-alg-confusion-hs256",
    "rs-003-a-slow-upstream-hits-the-timeout",
    "bn-list-notes-editor",
    "cb-014-ordinary-relative-paths-still-work",
)


def smoke_cases() -> list:
    by_id = {case.id: case for case in load_cases(CASES_DIR)}
    missing = [case_id for case_id in SMOKE_IDS if case_id not in by_id]
    assert not missing, f"the smoke subset names cases that no longer exist: {missing}"
    return [by_id[case_id] for case_id in SMOKE_IDS]


def test_the_smoke_subset_covers_both_outcomes() -> None:
    cases = smoke_cases()
    assert sum(1 for c in cases if c.attack) >= 8
    assert sum(1 for c in cases if not c.attack) >= 2
    assert len({c.category for c in cases}) >= 7


def test_every_smoke_case_shares_the_default_gateway_profile() -> None:
    """So the slice runs against one gateway and stays fast enough for every commit."""
    assert all(not c.gateway for c in smoke_cases())
    assert all(c.evil_variant == "plain" for c in smoke_cases())


async def test_the_red_team_smoke_subset_passes(tmp_path: Path) -> None:
    from warden.config import Settings

    cases = smoke_cases()
    with redteam_gateway(tmp_path, {}, classifier=False) as gateway:
        settings: Settings = gateway.app.state.settings
        forge = CredentialForge(
            key_dir=settings.jwt_key_dir,
            issuer=settings.jwt_issuer,
            audience=settings.jwt_audience,
        )
        runner = CaseRunner(gateway, forge)
        results = [await runner.run(case) for case in cases]

    failures = [
        f"{r.case_id}: {r.outcome} - {r.detail} ({'; '.join(r.evidence)})"
        for r in results
        if not r.passed
    ]
    assert not failures, "\n".join(failures)
    assert sum(1 for r in results if r.outcome == "blocked") >= 8
    assert sum(1 for r in results if r.outcome == "allowed") >= 2
