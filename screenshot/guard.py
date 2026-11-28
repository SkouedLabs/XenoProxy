"""Destination checks for every request the browser makes.

This module is shared by nobody: the screenshot service is its own image and
imports nothing from the backend. The rules mirror `app.core.http_client`, so a
URL refused by the worker is refused here too, and a page that redirects or
loads a sub-resource from a private address is stopped one request at a time.
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable
from urllib.parse import urlsplit

BLOCKED_PORTS = frozenset({22, 23, 25, 110, 135, 137, 138, 139, 445, 3389})
METADATA_HOSTS = frozenset({"169.254.169.254", "fd00:ec2::254", "metadata.google.internal"})

Resolver = Callable[[str], list[str]]


class Refused(ValueError):
    """A destination the browser must not contact."""


def is_private_address(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    )


def system_resolve(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise Refused(f"host {host} could not be resolved") from exc
    return sorted({info[4][0] for info in infos})


def check(
    url: str,
    *,
    allow_plain_http: bool = False,
    resolve: Resolver = system_resolve,
) -> None:
    """Raise `Refused` unless the browser may contact this URL."""
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"}:
        raise Refused("only http and https destinations are allowed")
    if parts.scheme == "http" and not allow_plain_http:
        raise Refused("plain http destinations are refused")
    if parts.username or parts.password:
        raise Refused("credentials in a URL are not allowed")
    host = parts.hostname
    if not host:
        raise Refused("destination has no host")
    if parts.port and parts.port in BLOCKED_PORTS:
        raise Refused(f"port {parts.port} is not allowed")
    if host.lower() in METADATA_HOSTS:
        raise Refused("cloud metadata endpoints are not allowed")

    addresses = [host] if is_private_address(host) else resolve(host)
    for address in addresses:
        if address in METADATA_HOSTS:
            raise Refused("cloud metadata endpoints are not allowed")
        if is_private_address(address):
            raise Refused(f"destination resolves to the non-routable address {address}")
