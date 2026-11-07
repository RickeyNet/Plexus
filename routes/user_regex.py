"""Compile regular expressions typed by users.

Config backup search, compliance ``regex_match`` rules and path-trace sweep
filters all take a pattern from a user and run it against device configs or
names. Python's ``re`` backtracks, so a crafted pattern such as
``(a+)+b`` or ``a*a*a*a*b`` can take exponential or polynomial time and stall
the event loop (ReDoS). These patterns go through RE2 instead, which matches
in time linear in the input for every pattern.

RE2 does not support lookarounds (``(?=``, ``(?!``, ``(?<=``, ``(?<!``) or
backreferences (``\\1``); such patterns are rejected as invalid.
"""

from __future__ import annotations

from typing import Protocol

import re2


class UserRegex(Protocol):
    """The part of a compiled pattern callers use (``re.Pattern`` fits too)."""

    def search(self, text: str) -> object: ...


def compile_user_regex(pattern: str, *, ignore_case: bool = True, multiline: bool = False) -> UserRegex:
    """Compile a user-supplied ``pattern`` with RE2.

    ``multiline`` makes ``^`` and ``$`` match at line boundaries, like
    ``re.MULTILINE``. Raises ``ValueError`` carrying RE2's reason when the
    pattern is invalid or uses syntax RE2 does not support.
    """
    options = re2.Options()
    options.case_sensitive = not ignore_case
    # RE2 otherwise writes every rejected pattern to stderr.
    options.log_errors = False
    try:
        return re2.compile(f"(?m){pattern}" if multiline else pattern, options)
    except re2.error as exc:
        reason = exc.args[0] if exc.args else ""
        if isinstance(reason, bytes):
            reason = reason.decode("utf-8", errors="replace")
        raise ValueError(str(reason) or "invalid regular expression") from exc
