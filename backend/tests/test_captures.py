"""Browser screenshots: request checks, proxy choice, the reply, and the screenshot service.

The browser itself is never started here. The service's pure parts (request
parsing, token check, proxy fields, the destination guard) are tested directly,
and the worker's reply handling is tested on a reply built the way the service
builds one.
"""

from __future__ import annotations

import base64
import importlib.util
import struct
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

from app.core import http_client
from app.core.config import Settings
from app.core.errors import ValidationFailedError
from app.models.job import Tlp
from app.services import captures

SCREENSHOT_DIR = Path(__file__).resolve().parents[2] / "screenshot"


def _load(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, SCREENSHOT_DIR / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


guard = _load("guard")


def _png(width: int = 640, height: int = 480) -> bytes:
    return (
        b"\x89PNG\r\n\x1a\n"
        + b"\x00\x00\x00\x0dIHDR"
        + struct.pack(">II", width, height)
        + b"\x08\x06\x00\x00\x00"
        + b"\x00" * 16
    )


# --------------------------------------------------------------------------
# The request
# --------------------------------------------------------------------------


def test_captures_are_off_by_default() -> None:
    assert Settings.model_fields["capture_enabled"].default is False


@pytest.mark.parametrize("url", ["https://example.com/", "http://example.com/login?x=1"])
def test_a_web_address_is_accepted(url: str) -> None:
    assert captures.check_submitted_url(url) == url


@pytest.mark.parametrize(
    "url",
    [
        "",
        "ftp://example.com/",
        "file:///etc/passwd",
        "javascript:alert(1)",
        "https:///nohost",
        "https://user:secret@example.com/",
        "https://" + "a" * 2100 + ".example.com/",
    ],
)
def test_other_addresses_are_refused_before_queueing(url: str) -> None:
    with pytest.raises(ValidationFailedError):
        captures.check_submitted_url(url)


# --------------------------------------------------------------------------
# Proxy choice
# --------------------------------------------------------------------------


@pytest.fixture
def profiles():
    def install(*items: SimpleNamespace, assignments=None, default=""):
        http_client._install_profiles(
            SimpleNamespace(
                proxy_profiles=list(items),
                proxy_passwords={},
                proxy_assignments=assignments or {},
                proxy_default=default,
            )
        )

    yield install
    http_client._install_profiles(None)


def test_red_with_no_approved_proxy_is_refused(profiles) -> None:
    profiles(
        SimpleNamespace(
            name="office", url="socks5://198.51.100.9:1080", username="", red_approved=False
        ),
        default="office",
    )
    with pytest.raises(http_client.OutboundRequestError):
        http_client.capture_proxy(Tlp.RED)


def test_red_goes_through_a_profile_approved_for_red(profiles) -> None:
    profiles(
        SimpleNamespace(
            name="vault", url="socks5://198.51.100.9:1080", username="", red_approved=True
        ),
        assignments={"screenshot": "vault"},
    )
    assert http_client.capture_proxy(Tlp.RED) == "socks5://198.51.100.9:1080"


def test_the_screenshot_assignment_wins_over_the_default(profiles) -> None:
    profiles(
        SimpleNamespace(name="a", url="http://198.51.100.1:3128", username="", red_approved=False),
        SimpleNamespace(
            name="b", url="socks5://198.51.100.2:1080", username="", red_approved=False
        ),
        assignments={"screenshot": "b"},
        default="a",
    )
    assert http_client.capture_proxy(Tlp.AMBER) == "socks5://198.51.100.2:1080"


def test_socks5_credentials_are_split_out_for_the_service(profiles) -> None:
    profiles(
        SimpleNamespace(
            name="p", url="socks5://198.51.100.9:1080", username="ana", red_approved=False
        ),
        assignments={"screenshot": "p"},
    )
    # The profile holds the credentials in its URL; the fields are derived from it.
    url = http_client.capture_proxy(Tlp.AMBER)
    assert url is not None
    fields = captures.playwright_proxy_fields(url)
    assert fields == {"server": "socks5://198.51.100.9:1080", "username": "ana", "password": ""}


def test_socks5h_is_sent_as_socks5() -> None:
    fields = captures.playwright_proxy_fields("socks5h://198.51.100.9:1080")
    assert fields == {"server": "socks5://198.51.100.9:1080"}


@pytest.mark.parametrize("url", ["socks4://198.51.100.9:1080", "socks4a://198.51.100.9:1080"])
def test_socks4_is_refused_for_screenshots(url: str) -> None:
    with pytest.raises(captures.CaptureError):
        captures.playwright_proxy_fields(url)


def test_no_proxy_means_no_proxy_fields() -> None:
    assert captures.playwright_proxy_fields(None) is None


# --------------------------------------------------------------------------
# The reply
# --------------------------------------------------------------------------


def test_a_png_reply_is_read_with_its_size() -> None:
    reply = captures.parse_service_reply(
        {
            "png_base64": base64.b64encode(_png(800, 600)).decode(),
            "final_url": "https://example.com/home",
            "title": "Example",
            "blocked_requests": 3,
        }
    )
    assert (reply["width"], reply["height"]) == (800, 600)
    assert reply["final_url"] == "https://example.com/home"
    assert reply["blocked_requests"] == 3


def test_a_reply_that_is_not_a_png_is_refused() -> None:
    payload = {"png_base64": base64.b64encode(b"<html>not an image</html>").decode()}
    with pytest.raises(captures.CaptureError):
        captures.parse_service_reply(payload)


def test_a_reply_without_an_image_is_refused() -> None:
    with pytest.raises(captures.CaptureError):
        captures.parse_service_reply({"final_url": "https://example.com/"})


def test_an_oversized_image_is_refused() -> None:
    big = _png() + b"\x00" * (captures.MAX_PNG_BYTES + 1)
    with pytest.raises(captures.CaptureError):
        captures.parse_service_reply({"png_base64": base64.b64encode(big).decode()})


def test_a_bad_base64_reply_is_refused() -> None:
    with pytest.raises(captures.CaptureError):
        captures.parse_service_reply({"png_base64": "!!not base64!!"})


def test_the_view_points_at_the_image_only_when_it_is_done() -> None:
    from app.models.capture import Capture, CaptureStatus

    capture = Capture(
        id=__import__("uuid").uuid4(),
        url="https://example.com/",
        tlp="amber",
        status=CaptureStatus.QUEUED,
        requested_by="ana",
        final_url="",
        title="",
        blocked_requests=0,
        error="",
        image_sha256="",
    )
    assert captures.view(capture)["image_url"] is None
    capture.status = CaptureStatus.DONE
    assert captures.view(capture)["image_url"].endswith("/image")


# --------------------------------------------------------------------------
# The destination guard, shared by the service's browser
# --------------------------------------------------------------------------


def _no_dns(host: str) -> list[str]:
    raise AssertionError(f"unexpected lookup for {host}")


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/",
        "https://10.0.0.5/admin",
        "https://192.168.1.10/",
        "https://[::1]/",
        "https://169.254.169.254/latest/meta-data/",
        "https://metadata.google.internal/",
        "https://example.com:445/",
        "https://user:pw@example.com/",
        "ftp://example.com/",
    ],
)
def test_the_guard_refuses_private_and_unsafe_destinations(url: str) -> None:
    with pytest.raises(guard.Refused):
        guard.check(url, allow_plain_http=True, resolve=_no_dns)


def test_a_host_resolving_to_a_private_address_is_refused() -> None:
    with pytest.raises(guard.Refused):
        guard.check("https://internal.example.com/", resolve=lambda _host: ["10.1.2.3"])


def test_a_public_destination_is_allowed() -> None:
    guard.check("https://93.184.216.34/", resolve=lambda host: [host])
    guard.check("https://example.com/", resolve=lambda _host: ["93.184.216.34"])


def test_plain_http_is_refused_unless_allowed() -> None:
    with pytest.raises(guard.Refused):
        guard.check("http://93.184.216.34/", resolve=lambda host: [host])


# --------------------------------------------------------------------------
# The service's request handling and token check
# --------------------------------------------------------------------------


@pytest.fixture(scope="module")
def service():
    sys.path.insert(0, str(SCREENSHOT_DIR))
    try:
        return _load("service")
    finally:
        sys.path.remove(str(SCREENSHOT_DIR))


def test_the_service_requires_its_own_bearer_token(service) -> None:
    assert service.authorized("Bearer s3cret", "s3cret")
    assert not service.authorized("Bearer wrong", "s3cret")
    assert not service.authorized(None, "s3cret")
    assert not service.authorized("s3cret", "s3cret")
    # An empty configured token never matches anything.
    assert not service.authorized("Bearer ", "")


def test_the_service_parses_a_request_and_refuses_bad_ones(service) -> None:
    ok = service.parse_request(b'{"url": "https://example.com/", "proxy": null}')
    assert ok == {"url": "https://example.com/", "proxy": None}
    with pytest.raises(service.RequestError):
        service.parse_request(b"not json")
    with pytest.raises(service.RequestError):
        service.parse_request(b'{"url": 7}')
    with pytest.raises(service.RequestError):
        service.parse_request(b'{"url": "https://example.com/", "proxy": {"username": "a"}}')
    with pytest.raises(service.RequestError):
        service.parse_request(b"x" * (service.MAX_BODY_BYTES + 1))


def test_the_service_builds_playwright_proxy_fields(service) -> None:
    fields = service.playwright_proxy(
        {"server": "socks5://198.51.100.9:1080", "username": "a b", "password": "p"}
    )
    assert fields == {"server": "socks5://198.51.100.9:1080", "username": "a b", "password": "p"}
    with pytest.raises(service.CaptureError):
        service.playwright_proxy({"server": "socks4://198.51.100.9:1080"})
