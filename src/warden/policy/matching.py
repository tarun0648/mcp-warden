"""Glob matching over namespaced tool names.

A pattern is matched part by part: the server name and the tool name are globbed separately, so
`*` can never cross the `__` separator. Without that, one careless `*` in a policy file would
grant every tool on every upstream.
"""

from __future__ import annotations

import fnmatch
import re
from functools import lru_cache

from warden.config import NAMESPACE_SEP


@lru_cache(maxsize=4096)
def _compiled(pattern: str) -> re.Pattern[str]:
    """fnmatch's translation, compiled and cached. Patterns come from config, never from input."""
    return re.compile(fnmatch.translate(pattern))


def matches(pattern: str, tool_name: str) -> bool:
    """True if `pattern` matches the namespaced `tool_name`.

    Both sides are split on the first `__`. A pattern without a separator matches nothing;
    config validation rejects such patterns, so this is only a safety net.
    """
    pattern_server, pattern_sep, pattern_tool = pattern.partition(NAMESPACE_SEP)
    if not pattern_sep:
        return False
    name_server, name_sep, name_tool = tool_name.partition(NAMESPACE_SEP)
    if not name_sep:
        return False
    return bool(
        _compiled(pattern_server).match(name_server) and _compiled(pattern_tool).match(name_tool)
    )


def matches_any(patterns: list[str], tool_name: str) -> bool:
    return any(matches(pattern, tool_name) for pattern in patterns)


__all__ = ["matches", "matches_any"]
