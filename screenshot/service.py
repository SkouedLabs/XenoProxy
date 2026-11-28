"""Headless Chromium behind a small HTTP interface, for the worker only.

One request is one browser context: no cookies, no storage and no service
workers carry over from an earlier capture. Every request the page makes is
checked by `guard.check` before it leaves, and a refused one is aborted, so a
redirect or an embedded frame cannot reach a private address either.

The service has no database, no secret but its own bearer token, and no route
except the one the compose file gives it. It never returns HTML: the reply is
the PNG as base64 in JSON, and the worker decides what to store.
"""

from __future__ import annotations

import base64
import hmac
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import unquote, urlsplit

import guard

MAX_BODY_BYTES = 16 * 1024
MAX_URL_LENGTH = 2048
MAX_PNG_BYTES = 4 * 1024 * 1024
NAVIGATION_TIMEOUT_MS = 30_000
SETTLE_TIMEOUT_MS = 5_000
VIEWPORT = {"width": 1280, "height": 800}
USER_AGENT = "XenoProxy-Capture/0.1"
# Playwright takes SOCKS5 with or without remote name resolution the same way,
# and it has no SOCKS4 mode at all, so SOCKS4 is refused rather than downgraded.
PROXY_SCHEMES = {"http": "http", "https": "https", "socks5": "socks5", "socks5h": "socks5"}


class RequestError(ValueError):
    """The request is malformed or not allowed; answered with 400."""


class CaptureError(RuntimeError):
    """The capture could not be made; answered with 502."""


def parse_request(body: bytes) -> dict[str, Any]:
    if len(body) > MAX_BODY_BYTES:
        raise RequestError("the request is too large")
    try:
        data = json.loads(body or b"{}")
    except json.JSONDecodeError as exc:
        raise RequestError("the request is not JSON") from exc
    if not isinstance(data, dict):
        raise RequestError("the request must be an object")

    url = data.get("url")
    if not isinstance(url, str) or not url or len(url) > MAX_URL_LENGTH:
        raise RequestError("url must be a string of at most 2048 characters")

    proxy = data.get("proxy")
    if proxy is not None:
        if not isinstance(proxy, dict) or not isinstance(proxy.get("server"), str):
            raise RequestError("proxy must carry a server")
        for key in ("username", "password"):
            if not isinstance(proxy.get(key, ""), str):
                raise RequestError("proxy credentials must be strings")
    return {"url": url, "proxy": proxy}


def authorized(header: str | None, expected: str) -> bool:
    if not expected or not header or not header.startswith("Bearer "):
        return False
    return hmac.compare_digest(header[len("Bearer ") :].encode(), expected.encode())


def playwright_proxy(request_proxy: dict[str, Any]) -> dict[str, str]:
    """Turn the proxy the worker sent into the server, username and password Playwright takes."""
    server = str(request_proxy["server"])
    parts = urlsplit(server)
    scheme = PROXY_SCHEMES.get(parts.scheme)
    if scheme is None or not parts.hostname or not parts.port:
        raise CaptureError("the proxy must be http, https or socks5 with a host and port")
    host = f"[{parts.hostname}]" if ":" in parts.hostname else parts.hostname
    proxy = {"server": f"{scheme}://{host}:{parts.port}"}
    username = str(request_proxy.get("username") or "")
    if username:
        proxy["username"] = username
        proxy["password"] = str(request_proxy.get("password") or "")
    return proxy


def capture(url: str, proxy: dict[str, Any] | None, *, allow_plain_http: bool) -> dict[str, Any]:
    """Load one page and return its PNG. Runs in its own browser for this call."""
    from playwright.sync_api import TimeoutError as PlaywrightTimeout
    from playwright.sync_api import sync_playwright

    try:
        guard.check(url, allow_plain_http=allow_plain_http)
    except guard.Refused as exc:
        raise CaptureError(f"the address is refused: {exc}") from exc

    blocked: list[str] = []

    def route(request_route: Any) -> None:
        target = request_route.request.url
        if urlsplit(target).scheme in {"data", "blob"}:
            request_route.continue_()
            return
        try:
            guard.check(target, allow_plain_http=allow_plain_http)
        except guard.Refused:
            blocked.append(target)
            request_route.abort("blockedbyclient")
            return
        request_route.continue_()

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(
            headless=True,
            # The container is the sandbox here: no capability, no secret, no route
            # to internal networks. Chromium's own sandbox needs user namespaces,
            # which the container's seccomp profile does not allow.
            chromium_sandbox=False,
            args=["--disable-dev-shm-usage", "--disable-gpu", "--no-zygote"],
        )
        try:
            context_options: dict[str, Any] = {
                "viewport": VIEWPORT,
                "user_agent": USER_AGENT,
                "accept_downloads": False,
                "service_workers": "block",
                "permissions": [],
            }
            if proxy is not None:
                context_options["proxy"] = playwright_proxy(proxy)
            context = browser.new_context(**context_options)
            context.route("**/*", route)
            page = context.new_page()
            page.on("dialog", lambda dialog: dialog.dismiss())
            try:
                page.goto(url, wait_until="load", timeout=NAVIGATION_TIMEOUT_MS)
            except PlaywrightTimeout as exc:
                raise CaptureError("the page did not finish loading in time") from exc
            except Exception as exc:
                raise CaptureError(f"the page could not be loaded: {type(exc).__name__}") from exc
            try:
                page.wait_for_load_state("networkidle", timeout=SETTLE_TIMEOUT_MS)
            except PlaywrightTimeout:
                pass

            final_url = page.url
            try:
                guard.check(final_url, allow_plain_http=allow_plain_http)
            except guard.Refused as exc:
                raise CaptureError(f"the final address is refused: {exc}") from exc

            png = page.screenshot(type="png", full_page=False)
            title = page.title()[:200]
        finally:
            browser.close()

    if len(png) > MAX_PNG_BYTES:
        raise CaptureError("the screenshot is larger than the allowed size")
    return {
        "png_base64": base64.b64encode(png).decode("ascii"),
        "final_url": final_url,
        "title": title,
        "blocked_requests": len(blocked),
    }


_slots = threading.BoundedSemaphore(int(os.environ.get("CAPTURE_CONCURRENCY", "2")))


def make_handler(token: str, allow_plain_http: bool) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "XenoProxyCapture"
        sys_version = ""

        def _send(self, status: int, payload: dict[str, Any]) -> None:
            body = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format: str, *_args: Any) -> None:
            # The default line carries the client address and the path; neither is needed.
            return

        def do_GET(self) -> None:
            if self.path == "/healthz":
                self._send(200, {"status": "ok"})
            else:
                self._send(404, {"error": "not found"})

        def do_POST(self) -> None:
            if self.path != "/capture":
                self._send(404, {"error": "not found"})
                return
            if not authorized(self.headers.get("Authorization"), token):
                self._send(401, {"error": "unauthorized"})
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                self._send(400, {"error": "invalid length"})
                return
            if length > MAX_BODY_BYTES:
                self._send(400, {"error": "the request is too large"})
                return
            try:
                request = parse_request(self.rfile.read(length))
            except RequestError as exc:
                self._send(400, {"error": str(exc)})
                return
            if not _slots.acquire(blocking=False):
                self._send(503, {"error": "the service is busy, retry shortly"})
                return
            try:
                result = capture(
                    request["url"], request["proxy"], allow_plain_http=allow_plain_http
                )
            except (CaptureError, RequestError) as exc:
                self._send(502, {"error": str(exc)})
                return
            finally:
                _slots.release()
            self._send(200, result)

    return Handler


def main() -> None:
    token_file = os.environ.get("CAPTURE_TOKEN_FILE", "")
    token = ""
    if token_file and os.path.isfile(token_file):
        with open(token_file, encoding="utf-8") as handle:
            token = handle.read().strip()
    if not token:
        raise SystemExit("CAPTURE_TOKEN_FILE must name a file holding the shared token")
    allow_plain_http = os.environ.get("CAPTURE_ALLOW_PLAIN_HTTP", "false").lower() == "true"
    server = ThreadingHTTPServer(
        ("0.0.0.0", int(os.environ.get("CAPTURE_PORT", "8080"))),
        make_handler(token, allow_plain_http),
    )
    server.serve_forever()


if __name__ == "__main__":
    main()
