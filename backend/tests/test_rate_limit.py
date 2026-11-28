"""The fixed-window counter behind anonymous submissions and their quota report."""

from __future__ import annotations

from app.core.rate_limit import FixedWindowLimiter


def test_hits_are_allowed_until_the_limit_then_refused_with_a_wait() -> None:
    limiter = FixedWindowLimiter()
    key = ("/api/v1/public/submissions", "203.0.113.7")
    for _ in range(3):
        assert limiter.consume(key, 3, 3600) is None
    wait = limiter.consume(key, 3, 3600)
    assert wait is not None and 0 < wait <= 3600


def test_peek_reports_what_is_left_without_spending_anything() -> None:
    limiter = FixedWindowLimiter()
    key = ("/api/v1/public/submissions", "198.51.100.4")
    assert limiter.peek(key, 10, 3600) == (10, 0)
    limiter.consume(key, 10, 3600)
    limiter.consume(key, 10, 3600)
    remaining, reset = limiter.peek(key, 10, 3600)
    assert remaining == 8
    assert 0 < reset <= 3601
    # Peeking twice does not count as a hit.
    assert limiter.peek(key, 10, 3600)[0] == 8


def test_callers_do_not_share_a_bucket() -> None:
    limiter = FixedWindowLimiter()
    first = ("/api/v1/public/submissions", "192.0.2.1")
    second = ("/api/v1/public/submissions", "192.0.2.2")
    limiter.consume(first, 1, 3600)
    assert limiter.consume(second, 1, 3600) is None
