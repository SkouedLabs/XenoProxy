"""Password breach check by k-anonymity against the Pwned Passwords range API.

The password is hashed here with SHA-1. Only the first five hex characters of the hash are
sent upstream; the rest is compared locally against the returned suffixes. Padding is
requested so the response size does not reveal how many suffixes matched.

Nothing is stored or logged: not the password, not the hash, not the prefix. The check is
off unless `BACKEND_HIBP_PASSWORDS_ENABLED` is set, because it is the one outbound call in
this codebase that carries a derived piece of a secret.
"""

from __future__ import annotations

import hashlib

from app.core import http_client
from app.core.errors import AppError

RANGE_URL = "https://api.pwnedpasswords.com/range/{prefix}"
_TIMEOUT = 15


class PasswordCheckUnavailable(AppError):
    status_code = 502
    code = "UPSTREAM_UNAVAILABLE"


def split_hash(password: str) -> tuple[str, str]:
    """Return (prefix sent upstream, suffix kept locally) for a password."""
    digest = hashlib.sha1(password.encode("utf-8"), usedforsecurity=False).hexdigest().upper()
    return digest[:5], digest[5:]


def occurrences(range_body: str, suffix: str) -> int:
    """Count the breach occurrences of a suffix in a range response; padding rows count 0."""
    for line in range_body.splitlines():
        candidate, _, count = line.strip().partition(":")
        if candidate.upper() == suffix and count.isdigit():
            return int(count)
    return 0


async def breach_count(password: str) -> int:
    prefix, suffix = split_hash(password)
    response = await http_client.get(
        RANGE_URL.format(prefix=prefix),
        headers={"Add-Padding": "true", "User-Agent": "XenoProxy"},
        timeout=_TIMEOUT,
    )
    if not response.ok:
        raise PasswordCheckUnavailable(
            f"The breach range service answered HTTP {response.status_code}."
        )
    return occurrences(response.text, suffix)
