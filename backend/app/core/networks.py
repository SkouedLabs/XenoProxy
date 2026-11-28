"""Address allow-lists: an empty list admits everyone."""

from __future__ import annotations

import ipaddress


def address_allowed(allowed: str, address: str | None) -> bool:
    """True when the allow-list is empty or the address falls in one of its networks."""
    tokens = allowed.replace(",", " ").split()
    if not tokens:
        return True
    if address is None:
        return False
    try:
        candidate = ipaddress.ip_address(address)
    except ValueError:
        return False
    for token in tokens:
        try:
            network = ipaddress.ip_network(token, strict=False)
        except ValueError:
            continue
        if candidate.version == network.version and candidate in network:
            return True
    return False
