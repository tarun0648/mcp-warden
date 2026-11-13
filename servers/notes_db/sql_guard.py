"""Make `run_sql` safe: one read-only SELECT, enforced three different ways.

Defence in depth, because any single layer can be worked around:

1. `validate_read_only_sql` rejects the statement before SQLite ever sees it (one statement,
   starts with SELECT or WITH, no ATTACH/PRAGMA, no stray semicolons).
2. The connection is opened `file:...?mode=ro`, so the SQLite engine itself refuses writes.
3. An authorizer callback denies every action except reading, so a write that somehow parsed
   is still refused at execution time.
"""

from __future__ import annotations

import re
import sqlite3
from typing import Final

MAX_SQL_LENGTH: Final = 4000
MAX_ROWS: Final = 500

#: Scalar and aggregate functions a read-only query may use. Anything else - notably
#: load_extension, readfile and writefile - is denied by the authorizer.
ALLOWED_SQL_FUNCTIONS: Final[frozenset[str]] = frozenset(
    {
        "abs",
        "avg",
        "coalesce",
        "count",
        "date",
        "datetime",
        "format",
        "group_concat",
        "ifnull",
        "iif",
        "instr",
        "julianday",
        "length",
        "like",
        "lower",
        "ltrim",
        "max",
        "min",
        "nullif",
        "printf",
        "quote",
        "random",
        "replace",
        "round",
        "rtrim",
        "strftime",
        "substr",
        "substring",
        "sum",
        "time",
        "total",
        "trim",
        "typeof",
        "unicode",
        "upper",
    }
)

#: Keywords that must not appear anywhere, even inside an otherwise valid-looking SELECT.
#: Matched on word boundaries, so "(DELETE" and "load_extension(" are caught while the column
#: name "created" is not mistaken for CREATE.
FORBIDDEN_KEYWORDS: Final[tuple[str, ...]] = (
    "attach",
    "detach",
    "pragma",
    "insert",
    "update",
    "delete",
    "replace into",
    "drop",
    "create",
    "alter",
    "vacuum",
    "reindex",
    "begin",
    "commit",
    "rollback",
    "savepoint",
    "load_extension",
    "writefile",
    "readfile",
    "fts3_tokenizer",
)

_FORBIDDEN_RES: Final[tuple[tuple[str, re.Pattern[str]], ...]] = tuple(
    (keyword, re.compile(r"\b" + r"\s+".join(re.escape(w) for w in keyword.split()) + r"\b"))
    for keyword in FORBIDDEN_KEYWORDS
)


class SqlNotAllowed(ValueError):
    """The submitted SQL is not a single read-only SELECT."""


def strip_sql_noise(sql: str) -> str:
    """Return `sql` with comments removed and string literals blanked out.

    Blanking literals (rather than removing them) keeps character offsets stable and stops a
    keyword inside `'... drop ...'` from tripping the keyword check, while a real `DROP`
    outside a literal still does.
    """
    out: list[str] = []
    index = 0
    length = len(sql)
    while index < length:
        char = sql[index]
        pair = sql[index : index + 2]
        if pair == "--":
            newline = sql.find("\n", index)
            index = length if newline == -1 else newline
            continue
        if pair == "/*":
            end = sql.find("*/", index + 2)
            index = length if end == -1 else end + 2
            continue
        if char in "'\"`":
            quote = char
            out.append(" ")
            index += 1
            while index < length:
                if sql[index] == quote:
                    if sql[index : index + 2] == quote * 2:
                        out.append(" ")
                        index += 2
                        continue
                    index += 1
                    break
                out.append(" ")
                index += 1
            continue
        if char == "[":
            end = sql.find("]", index)
            if end == -1:
                raise SqlNotAllowed("unterminated [identifier]")
            out.append(" " * (end - index + 1))
            index = end + 1
            continue
        out.append(char)
        index += 1
    return "".join(out)


def _without_parenthesised_groups(text: str) -> str:
    """Return `text` with every balanced (...) group blanked out.

    Used to find the statement's own top-level SELECT: the SELECT inside a CTE body does not
    make `WITH t AS (SELECT 1)` a complete statement.
    """
    out: list[str] = []
    depth = 0
    for char in text:
        if char == "(":
            depth += 1
            out.append(" ")
        elif char == ")":
            depth = max(0, depth - 1)
            out.append(" ")
        else:
            out.append(" " if depth else char)
    return "".join(out)


def validate_read_only_sql(sql: str) -> str:
    """Return the statement to execute, or raise `SqlNotAllowed` with a clear reason."""
    if not sql or not sql.strip():
        raise SqlNotAllowed("query is empty")
    if len(sql) > MAX_SQL_LENGTH:
        raise SqlNotAllowed(f"query longer than {MAX_SQL_LENGTH} characters")
    if "\x00" in sql:
        raise SqlNotAllowed("query contains a NUL byte")

    bare = strip_sql_noise(sql).strip()
    if bare.endswith(";"):
        bare = bare[:-1].rstrip()
    if ";" in bare:
        raise SqlNotAllowed("only one statement is allowed; remove the ';'")
    if not bare:
        raise SqlNotAllowed("query contains no statement")

    lowered = " ".join(bare.lower().split())
    for keyword, pattern in _FORBIDDEN_RES:
        if pattern.search(lowered):
            raise SqlNotAllowed(f"'{keyword}' is not allowed in a read-only query")

    first = lowered.split()[0] if lowered.split() else ""
    if first not in ("select", "with"):
        raise SqlNotAllowed("query must be a single SELECT (a WITH ... SELECT is fine)")
    if first == "with" and not re.search(r"\bselect\b", _without_parenthesised_groups(lowered)):
        raise SqlNotAllowed("a WITH clause must end in a SELECT")

    # Hand SQLite the original text: literals and comments are harmless to it, and we have
    # already proved the statement's shape using the blanked copy.
    return sql.strip().rstrip(";").strip()


def read_only_authorizer(
    action: int, arg1: str | None, arg2: str | None, _db: str | None, _trigger: str | None
) -> int:
    """SQLite authorizer that permits reading and nothing else."""
    if action in (sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ, sqlite3.SQLITE_RECURSIVE):
        return sqlite3.SQLITE_OK
    if action == sqlite3.SQLITE_FUNCTION:
        name = (arg2 or arg1 or "").lower()
        return sqlite3.SQLITE_OK if name in ALLOWED_SQL_FUNCTIONS else sqlite3.SQLITE_DENY
    return sqlite3.SQLITE_DENY
