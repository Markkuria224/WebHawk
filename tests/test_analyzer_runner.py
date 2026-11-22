import pytest

from webhawk.analyzers import runner
from webhawk.core.models import HTTPResponseMetadata


@pytest.fixture
def metadata():
    return HTTPResponseMetadata(
        requested_url="https://example.com/",
        response_url="https://example.com/final",
        status_code=200,
        http_version="HTTP/2",
        elapsed_ms=125,
    )


def test_runs_all_analyzers_in_deterministic_order(
    metadata,
    monkeypatch,
):
    calls = []

    hsts_findings = [object()]
    cookie_findings = [object()]
    cors_findings = [object()]

    def fake_hsts(received_metadata):
        calls.append(("hsts", received_metadata))
        return hsts_findings

    def fake_cookies(*, response_url, raw_headers):
        calls.append(("cookies", response_url, raw_headers))
        return cookie_findings

    def fake_cors(
        received_metadata,
        *,
        request_origin=None,
        request_method=None,
    ):
        calls.append(
            (
                "cors",
                received_metadata,
                request_origin,
                request_method,
            )
        )
        return cors_findings

    monkeypatch.setattr(runner, "analyze_hsts", fake_hsts)
    monkeypatch.setattr(runner, "analyze_cookies", fake_cookies)
    monkeypatch.setattr(runner, "analyze_cors", fake_cors)

    raw_headers = [
        (b"content-type", b"text/html"),
        (b"set-cookie", b"session=secret-value"),
    ]

    findings = runner.analyze_response(
        metadata,
        raw_headers=raw_headers,
        request_origin="https://client.example",
        request_method="GET",
    )

    assert findings == (
        hsts_findings
        + cookie_findings
        + cors_findings
    )

    assert [call[0] for call in calls] == [
        "hsts",
        "cookies",
        "cors",
    ]

    assert calls[0] == ("hsts", metadata)

    assert calls[1] == (
        "cookies",
        str(metadata.response_url),
        raw_headers,
    )

    assert calls[2] == (
        "cors",
        metadata,
        "https://client.example",
        "GET",
    )


def test_passes_optional_cors_context_as_none(
    metadata,
    monkeypatch,
):
    received_context = {}

    monkeypatch.setattr(
        runner,
        "analyze_hsts",
        lambda received_metadata: [],
    )

    monkeypatch.setattr(
        runner,
        "analyze_cookies",
        lambda **kwargs: [],
    )

    def fake_cors(
        received_metadata,
        *,
        request_origin=None,
        request_method=None,
    ):
        received_context["origin"] = request_origin
        received_context["method"] = request_method
        return []

    monkeypatch.setattr(runner, "analyze_cors", fake_cors)

    runner.analyze_response(
        metadata,
        raw_headers=[],
    )

    assert received_context == {
        "origin": None,
        "method": None,
    }


def test_returns_empty_list_when_no_analyzer_finds_anything(
    metadata,
    monkeypatch,
):
    monkeypatch.setattr(
        runner,
        "analyze_hsts",
        lambda received_metadata: [],
    )

    monkeypatch.setattr(
        runner,
        "analyze_cookies",
        lambda **kwargs: [],
    )

    monkeypatch.setattr(
        runner,
        "analyze_cors",
        lambda received_metadata, **kwargs: [],
    )

    findings = runner.analyze_response(
        metadata,
        raw_headers=[],
    )

    assert findings == []


def test_hsts_exception_propagates_and_stops_execution(
    metadata,
    monkeypatch,
):
    calls = []

    def failing_hsts(received_metadata):
        calls.append("hsts")
        raise RuntimeError("HSTS analyzer failed")

    def fake_cookies(**kwargs):
        calls.append("cookies")
        return []

    def fake_cors(received_metadata, **kwargs):
        calls.append("cors")
        return []

    monkeypatch.setattr(runner, "analyze_hsts", failing_hsts)
    monkeypatch.setattr(runner, "analyze_cookies", fake_cookies)
    monkeypatch.setattr(runner, "analyze_cors", fake_cors)

    with pytest.raises(RuntimeError, match="HSTS analyzer failed"):
        runner.analyze_response(
            metadata,
            raw_headers=[],
        )

    assert calls == ["hsts"]


def test_cookie_exception_propagates_and_stops_cors(
    metadata,
    monkeypatch,
):
    calls = []

    def fake_hsts(received_metadata):
        calls.append("hsts")
        return []

    def failing_cookies(**kwargs):
        calls.append("cookies")
        raise RuntimeError("Cookie analyzer failed")

    def fake_cors(received_metadata, **kwargs):
        calls.append("cors")
        return []

    monkeypatch.setattr(runner, "analyze_hsts", fake_hsts)
    monkeypatch.setattr(runner, "analyze_cookies", failing_cookies)
    monkeypatch.setattr(runner, "analyze_cors", fake_cors)

    with pytest.raises(RuntimeError, match="Cookie analyzer failed"):
        runner.analyze_response(
            metadata,
            raw_headers=[],
        )

    assert calls == ["hsts", "cookies"]


def test_raw_cookie_value_does_not_leak_into_findings(metadata):
    secret_value = "highly-sensitive-session-value"

    findings = runner.analyze_response(
        metadata,
        raw_headers=[
            (
                b"set-cookie",
                f"session={secret_value}; Path=/; HttpOnly".encode(),
            ),
        ],
    )

    serialized_findings = repr(findings)

    assert secret_value not in serialized_findings
    assert all(
        secret_value not in finding.model_dump_json()
        for finding in findings
    )
