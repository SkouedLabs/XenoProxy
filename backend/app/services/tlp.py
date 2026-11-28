"""Traffic Light Protocol policy.

The level chosen for a job caps which analyzers may run on it. Each analyzer
declares the highest level it tolerates:

- `CLEAR`  the source publishes, indexes or shares the observable (URLScan
           submission, sandbox submission, anything that creates a public record).
- `AMBER`  the source receives the observable privately (most reputation APIs).
- `RED`    the analyzer never sends the observable anywhere outside the
           deployment (a local resolver, an internal reference set).

A job at RED therefore runs only RED-capable analyzers, GREEN runs GREEN and
below, and so on. This is the same ordering IntelOwl uses.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from urllib.parse import urlsplit

from app.models.job import Tlp

# Ascending restriction: a job may use an analyzer whose maximum is at least as
# restrictive as the job's level.
_ORDER: dict[Tlp, int] = {
    Tlp.CLEAR: 0,
    Tlp.GREEN: 1,
    Tlp.AMBER: 2,
    Tlp.RED: 3,
}

DESCRIPTIONS: dict[Tlp, str] = {
    Tlp.CLEAR: "No restriction. Every source may run, including those that publish the observable.",
    Tlp.GREEN: "Sources that publish, index or retain the observable are excluded.",
    Tlp.AMBER: "Also limits who can see the job to the submitter's groups.",
    Tlp.RED: "Also excludes every external source; only local analyzers run.",
}


def rank(level: Tlp) -> int:
    return _ORDER[level]


def allows(job_tlp: Tlp, analyzer_max_tlp: Tlp) -> bool:
    """Report whether an analyzer may run on a job at this level."""
    return _ORDER[analyzer_max_tlp] >= _ORDER[job_tlp]


def restricts_visibility(level: Tlp) -> bool:
    """AMBER and above limit a job to the submitter's groups."""
    return _ORDER[level] >= _ORDER[Tlp.AMBER]


def describe(level: Tlp) -> str:
    return DESCRIPTIONS[level]


def refusal_reason(job_tlp: Tlp, analyzer_max_tlp: Tlp) -> str:
    return (
        f"not allowed at TLP:{job_tlp.value.upper()} "
        f"(the source is capped at TLP:{analyzer_max_tlp.value.upper()})"
    )


TRUSTED_OPTION = "trusted_internal"


def _addresses(host: str) -> list[str]:
    try:
        return sorted({info[4][0] for info in socket.getaddrinfo(host, None)})
    except (socket.gaierror, UnicodeError):
        return []


def _is_internal_address(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value.split("%", 1)[0])
    except ValueError:
        return False
    return address.is_private or address.is_loopback or address.is_link_local


async def endpoint_is_internal(url: str) -> bool:
    """Whether every address behind this URL is on a private network.

    A hosted gateway resolves to public addresses, so it is not internal. A name
    that does not resolve, or that resolves to a mix, is treated as not internal:
    the question is whether data may leave, and doubt answers no.
    """
    host = urlsplit(url).hostname
    if not host:
        return False
    found = await asyncio.to_thread(_addresses, host)
    return bool(found) and all(_is_internal_address(item) for item in found)


def effective_cap(declared: Tlp, trusted_max: Tlp | None, options: dict) -> Tlp:
    """The cap a plugin runs under, once an administrator's trust choice is applied.

    A plugin may declare a higher cap (`trusted_max`) that only an administrator can
    switch on, with the `trusted_internal` option. Planning uses it; the plugin then
    re-checks its own destination when it runs, so a switch never widens what
    actually leaves the deployment.
    """
    if trusted_max is not None and bool(options.get(TRUSTED_OPTION)):
        return trusted_max
    return declared


async def inference_refusal(job_tlp: Tlp, base_url: str) -> str | None:
    """Why a job at this level may not be sent to this inference server, if it may not.

    TLP:RED means nothing leaves the deployment. A model server on a private
    network is part of the deployment; a hosted one is not.
    """
    if job_tlp is not Tlp.RED:
        return None
    if await endpoint_is_internal(base_url):
        return None
    return (
        "not allowed at TLP:RED: the inference server is not on a private network, "
        "and a RED job never leaves the deployment"
    )
