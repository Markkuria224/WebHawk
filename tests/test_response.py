from datetime import datetime, timezone

import httpx
import pytest

from webhawk.core.models import HTTPResponseMetadata
from webhawk.core.response import build_response_metadata


@pytest.fixture
def response():
    request = httpx.Request(
        "GET",
        "https://example.com/",
    )

    return httpx.Response(
        200,
        request=request,
        headers=[
            (b"content-type", b"text/html"),
            (b"set-cookie", b"session=first"),
            (b"set-cookie", b"session=second"),
            (b"x-frame-options", b"DENY"),
            (b"x-description", b"caf\xe9"),
        ],
        extensions={
            "http_version": b"HTTP/2",
        },
        content=b"This response body must not enter metadata.",
    )


def test_extracts_response_metadata(response, monkeypatch):
    monkeypatch.setattr(
        "webhawk.core.response.perf_counter_ns",
        lambda: 1_125_000_000,
    )

    received_at = datetime(2026, 11, 20, 18, 30, tzinfo=timezone.utc)

    metadata = build_response_metadata(
        requested_url="https://example.com",
        response=response,
        started_at_ns=1_000_000_000,
        received_at=received_at,
    )

    assert isinstance(metadata, HTTPResponseMetadata)
    assert str(metadata.requested_url) == "https://example.com/"
    assert str(metadata.response_url) == "https://example.com/"
    assert metadata.status_code == 200
    assert metadata.http_version == "HTTP/2"
    assert metadata.elapsed_ms == 125
    assert metadata.received_at == received_at


def test_preserves_duplicate_headers(response):
    metadata = build_response_metadata(
        requested_url="https://example.com",
        response=response,
        started_at_ns=0,
    )

    cookies = [
        header
        for header in metadata.headers
        if header.name.casefold() == "set-cookie"
    ]

    assert len(cookies) == 2
    assert all(cookie.value == "[REDACTED]" for cookie in cookies)


def test_preserves_non_sensitive_headers(response):
    metadata = build_response_metadata(
        requested_url="https://example.com",
        response=response,
        started_at_ns=0,
    )

    headers = {
        header.name.casefold(): header.value
        for header in metadata.headers
    }

    assert headers["content-type"] == "text/html"
    assert headers["x-frame-options"] == "DENY"
    assert headers["x-description"] == "café"


def test_does_not_store_response_body(response):
    metadata = build_response_metadata(
        requested_url="https://example.com",
        response=response,
        started_at_ns=0,
    )

    serialized = metadata.model_dump_json()

    assert "This response body must not enter metadata." not in serialized
    assert "body" not in type(metadata).model_fields


def test_uses_response_url_separately_from_requested_url(response):
    metadata = build_response_metadata(
        requested_url="https://example.com/original",
        response=response,
        started_at_ns=0,
    )

    assert str(metadata.requested_url) == "https://example.com/original"
    assert str(metadata.response_url) == "https://example.com/"


def test_rejects_missing_http_version(response):
    response.extensions.clear()

    with pytest.raises(ValueError, match="HTTP version"):
        build_response_metadata(
            requested_url="https://example.com",
            response=response,
            started_at_ns=0,
        )


@pytest.mark.parametrize(
    "http_version",
    [
        None,
        2,
        b"",
        b"FTP/1.0",
        "not-a-protocol",
    ],
)
def test_rejects_invalid_http_version(response, http_version):
    response.extensions["http_version"] = http_version

    with pytest.raises(ValueError):
        build_response_metadata(
            requested_url="https://example.com",
            response=response,
            started_at_ns=0,
        )


def test_rejects_non_httpx_response():
    with pytest.raises(TypeError):
        build_response_metadata(
            requested_url="https://example.com",
            response="not a response",
            started_at_ns=0,
        )


@pytest.mark.parametrize(
    "started_at_ns",
    [
        -1,
        1.5,
        True,
        "1000",
        None,
    ],
)
def test_rejects_invalid_start_time(response, started_at_ns):
    with pytest.raises(ValueError):
        build_response_metadata(
            requested_url="https://example.com",
            response=response,
            started_at_ns=started_at_ns,
        )


def test_rejects_elapsed_time_from_invalid_clock(response, monkeypatch):
    monkeypatch.setattr(
        "webhawk.core.response.perf_counter_ns",
        lambda: 100,
    )

    with pytest.raises(ValueError, match="monotonic clock"):
        build_response_metadata(
            requested_url="https://example.com",
            response=response,
            started_at_ns=200,
        )


def test_metadata_elapsed_time_uses_monotonic_clock(response, monkeypatch):
    monkeypatch.setattr(
        "webhawk.core.response.perf_counter_ns",
        lambda: 1_000_000,
    )

    metadata = build_response_metadata(
        requested_url="https://example.com",
        response=response,
        started_at_ns=1_000_000,
    )

    assert metadata.elapsed_ms == 0


@pytest.mark.parametrize(
    "http_version",
    [
        b"HTTP/0.9",
        b"HTTP/1.0",
        b"HTTP/1.1",
        b"HTTP/2",
        b"HTTP/3",
    ],
)
def test_accepts_supported_http_versions(response, http_version):
    response.extensions["http_version"] = http_version

    metadata = build_response_metadata(
        requested_url="https://example.com",
        response=response,
        started_at_ns=0,
    )

    assert metadata.http_version == http_version.decode("ascii")


@pytest.mark.parametrize(
    "http_version",
    [
        b"HTTP/garbage",
        b"HTTP/99",
        b"HTTP/1.2",
        b"HTTP/",
        b"HTTP/2.0",
        b"HTTP/1.1 extra",
    ],
)
def test_rejects_malformed_http_versions(response, http_version):
    response.extensions["http_version"] = http_version

    with pytest.raises(ValueError, match="unsupported HTTP version"):
        build_response_metadata(
            requested_url="https://example.com",
            response=response,
            started_at_ns=0,
        )


def test_default_timestamp_is_captured_at_function_entry(response, monkeypatch):
    captured_at = datetime(2026, 11, 20, 18, 45, tzinfo=timezone.utc)
    calls = []

    def fake_utc_now():
        calls.append("called")
        return captured_at

    monkeypatch.setattr("webhawk.core.response.utc_now", fake_utc_now)

    metadata = build_response_metadata(
        requested_url="https://example.com",
        response=response,
        started_at_ns=0,
    )

    assert metadata.received_at == captured_at
    assert len(calls) == 1
