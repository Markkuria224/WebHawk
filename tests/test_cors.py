import pytest

from webhawk.analyzers.cors import (
    ANALYZER_NAME,
    CORS_HEADER_NAMES,
    collect_cors_header_values,
    normalize_header_value,
    parse_cors_origin,
)

from webhawk.core.models import (
    HTTPHeader,
    HTTPResponseMetadata,
)


@pytest.fixture
def metadata():
    return HTTPResponseMetadata(
        requested_url="https://example.com",
        response_url="https://example.com/",
        status_code=200,
        http_version="HTTP/2",
        elapsed_ms=100,
        headers=(
            HTTPHeader(
                name="Access-Control-Allow-Origin",
                value="https://trusted.example",
            ),
            HTTPHeader(
                name="access-control-allow-credentials",
                value="true",
            ),
            HTTPHeader(
                name="ACCESS-CONTROL-ALLOW-ORIGIN",
                value="https://second.example",
            ),
            HTTPHeader(
                name="Content-Type",
                value="text/html",
            ),
            HTTPHeader(
                name="Vary",
                value="Origin",
            ),
        ),
    )


def test_analyzer_name():
    assert ANALYZER_NAME == "cors"


def test_cors_header_names_are_normalized():
    assert "access-control-allow-origin" in CORS_HEADER_NAMES
    assert "access-control-allow-credentials" in CORS_HEADER_NAMES
    assert "access-control-allow-methods" in CORS_HEADER_NAMES
    assert "access-control-allow-headers" in CORS_HEADER_NAMES
    assert "access-control-expose-headers" in CORS_HEADER_NAMES
    assert "access-control-max-age" in CORS_HEADER_NAMES
    assert "vary" in CORS_HEADER_NAMES


def test_collects_cors_headers_case_insensitively(metadata):
    headers = collect_cors_header_values(metadata)

    assert headers["access-control-allow-origin"] == (
        "https://trusted.example",
        "https://second.example",
    )

    assert headers["access-control-allow-credentials"] == (
        "true",
    )


def test_preserves_duplicate_header_values(metadata):
    headers = collect_cors_header_values(metadata)

    assert len(headers["access-control-allow-origin"]) == 2


def test_preserves_duplicate_header_order(metadata):
    headers = collect_cors_header_values(metadata)

    assert headers["access-control-allow-origin"][0] == (
        "https://trusted.example"
    )

    assert headers["access-control-allow-origin"][1] == (
        "https://second.example"
    )


def test_ignores_unrelated_headers(metadata):
    headers = collect_cors_header_values(metadata)

    assert "content-type" not in headers
    assert "access-control-allow-origin" in headers


def test_empty_metadata_returns_empty_dictionary():
    empty_metadata = HTTPResponseMetadata(
        requested_url="https://example.com",
        response_url="https://example.com/",
        status_code=204,
        http_version="HTTP/2",
        elapsed_ms=10,
    )

    assert collect_cors_header_values(empty_metadata) == {}


def test_normalizes_optional_whitespace():
    assert normalize_header_value(
        " \thttps://example.com \t"
    ) == "https://example.com"


def test_preserves_internal_whitespace():
    value = "https://example.com  https://other.example"

    assert normalize_header_value(value) == value


def test_header_collection_does_not_mutate_metadata(metadata):
    original_headers = metadata.headers

    collect_cors_header_values(metadata)

    assert metadata.headers == original_headers


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("*", "*"),
        ("null", "null"),
        ("https://example.com", "https://example.com"),
        ("http://example.com", "http://example.com"),
        ("HTTPS://EXAMPLE.COM", "https://example.com"),
        ("https://example.com:443", "https://example.com"),
        ("http://example.com:80", "http://example.com"),
        ("https://example.com:8443", "https://example.com:8443"),
        ("http://192.168.1.10", "http://192.168.1.10"),
        ("https://[2001:db8::1]", "https://[2001:db8::1]"),
        ("https://[2001:db8::1]:8443", "https://[2001:db8::1]:8443"),
        ("https://example.com.", "https://example.com"),
        ("https://bücher.example", "https://xn--bcher-kva.example"),
    ],
)
def test_accepts_and_normalizes_valid_origins(value, expected):
    assert parse_cors_origin(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        "",
        " ",
        "* ",
        "NULL",
        "null.example",
        "ftp://example.com",
        "javascript://example.com",
        "example.com",
        "//example.com",
        "https://",
        "https://example.com/",
        "https://example.com/path",
        "https://example.com?query=1",
        "https://example.com#fragment",
        "https://user@example.com",
        "https://user:password@example.com",
        "https://example.com:",
        "https://example.com:0",
        "https://example.com:65536",
        "https://example.com:abc",
        "https://example.com:443/path",
        "https://example.com\\path",
        "https://example.com evil",
        "https://example.com\n",
        "https://example.com\t",
        "https://example.com@evil.example",
        "https://exa_mple.com",
        "https://-invalid.example",
        "https://invalid-.example",
        "https://[2001:db8::1",
        "https://2001:db8::1",
        "https://[invalid]",
    ],
)
def test_rejects_invalid_origins(value):
    assert parse_cors_origin(value) is None


@pytest.mark.parametrize(
    "value",
    [
        None,
        123,
        [],
        {},
    ],
)
def test_rejects_non_string_origin_values(value):
    assert parse_cors_origin(value) is None

# ---------------------------------------------------------------------------
# CORS detection behaviour
# ---------------------------------------------------------------------------

def _cors_test_metadata(*headers):
    return HTTPResponseMetadata(
        requested_url="https://example.com",
        response_url="https://example.com/",
        status_code=200,
        http_version="HTTP/2",
        elapsed_ms=50,
        headers=tuple(
            HTTPHeader(name=name, value=value)
            for name, value in headers
        ),
    )


def _analyze_cors_test_response(
    *headers,
    request_origin=None,
    request_method=None,
):
    from webhawk.analyzers.cors import analyze_cors

    metadata = _cors_test_metadata(*headers)

    return analyze_cors(
        metadata,
        request_origin=request_origin,
        request_method=request_method,
    )


def test_wildcard_origin_is_informational_by_default():
    from webhawk.core.models import (
        FindingClassification,
        Severity,
    )

    findings = _analyze_cors_test_response(
        ("Access-Control-Allow-Origin", "*"),
    )

    assert len(findings) == 1
    assert findings[0].classification == FindingClassification.OBSERVATION
    assert findings[0].severity == Severity.INFO
    assert "Wildcard" in findings[0].title


def test_wildcard_origin_with_credentials_is_confirmed_misconfiguration():
    from webhawk.core.models import (
        FindingClassification,
        Severity,
    )

    findings = _analyze_cors_test_response(
        ("Access-Control-Allow-Origin", "*"),
        ("Access-Control-Allow-Credentials", "true"),
    )

    assert len(findings) == 1
    assert (
        findings[0].classification
        == FindingClassification.CONFIRMED_MISCONFIGURATION
    )
    assert findings[0].severity == Severity.LOW
    assert "credentials" in findings[0].title.lower()
    assert "does not establish credentialed data exposure" in (
        findings[0].description
    )


def test_duplicate_acao_headers_produce_one_misconfiguration_finding():
    from webhawk.core.models import (
        FindingClassification,
        Severity,
    )

    findings = _analyze_cors_test_response(
        ("Access-Control-Allow-Origin", "https://one.example"),
        ("Access-Control-Allow-Origin", "https://two.example"),
    )

    assert len(findings) == 1
    assert (
        findings[0].classification
        == FindingClassification.CONFIRMED_MISCONFIGURATION
    )
    assert findings[0].severity == Severity.MEDIUM
    assert "Multiple" in findings[0].title


def test_invalid_acao_value_is_confirmed_misconfiguration():
    from webhawk.core.models import (
        FindingClassification,
        Severity,
    )

    findings = _analyze_cors_test_response(
        ("Access-Control-Allow-Origin", "https://example.com/path"),
    )

    assert len(findings) == 1
    assert (
        findings[0].classification
        == FindingClassification.CONFIRMED_MISCONFIGURATION
    )
    assert findings[0].severity == Severity.LOW
    assert "Invalid" in findings[0].title


def test_null_origin_is_reported_as_potential_weakness():
    from webhawk.core.models import (
        FindingClassification,
        Severity,
    )

    findings = _analyze_cors_test_response(
        ("Access-Control-Allow-Origin", "null"),
    )

    assert len(findings) == 1
    assert (
        findings[0].classification
        == FindingClassification.POTENTIAL_WEAKNESS
    )
    assert findings[0].severity == Severity.MEDIUM


def test_matching_supplied_request_origin_is_potential_weakness():
    from webhawk.core.models import (
        FindingClassification,
        Severity,
    )

    findings = _analyze_cors_test_response(
        ("Access-Control-Allow-Origin", "https://trusted.example"),
        request_origin="HTTPS://TRUSTED.EXAMPLE:443",
    )

    assert len(findings) == 1
    assert (
        findings[0].classification
        == FindingClassification.POTENTIAL_WEAKNESS
    )
    assert findings[0].severity == Severity.LOW
    assert "does not establish" in findings[0].description
    assert findings[0].evidence[0].details[
        "supplied_request_origin"
    ] == "https://trusted.example"


def test_non_matching_request_origin_does_not_produce_finding():
    findings = _analyze_cors_test_response(
        ("Access-Control-Allow-Origin", "https://trusted.example"),
        request_origin="https://untrusted.example",
    )

    assert findings == []


def test_invalid_supplied_request_origin_does_not_produce_finding():
    findings = _analyze_cors_test_response(
        ("Access-Control-Allow-Origin", "https://trusted.example"),
        request_origin="not-an-origin",
    )

    assert findings == []


def test_credentials_permission_alone_is_informational():
    from webhawk.core.models import (
        FindingClassification,
        Severity,
    )

    findings = _analyze_cors_test_response(
        ("Access-Control-Allow-Credentials", "true"),
    )

    assert len(findings) == 1
    assert findings[0].classification == FindingClassification.OBSERVATION
    assert findings[0].severity == Severity.INFO


def test_credentials_permission_is_case_sensitive():
    findings = _analyze_cors_test_response(
        ("Access-Control-Allow-Origin", "*"),
        ("Access-Control-Allow-Credentials", "TRUE"),
    )

    assert len(findings) == 1
    assert findings[0].title == "Wildcard CORS origin"


def test_options_response_preflight_headers_are_observations():
    from webhawk.core.models import (
        FindingClassification,
        Severity,
    )

    findings = _analyze_cors_test_response(
        ("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE"),
        ("Access-Control-Allow-Headers", "Authorization, Content-Type"),
        request_method="OPTIONS",
    )

    assert len(findings) == 1
    assert findings[0].classification == FindingClassification.OBSERVATION
    assert findings[0].severity == Severity.INFO
    assert "preflight" in findings[0].title.lower()


def test_preflight_headers_are_not_analyzed_without_options_context():
    findings = _analyze_cors_test_response(
        ("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE"),
        ("Access-Control-Allow-Headers", "Authorization, Content-Type"),
    )

    assert findings == []


def test_preflight_headers_are_not_analyzed_for_non_options_method():
    findings = _analyze_cors_test_response(
        ("Access-Control-Allow-Methods", "GET, POST"),
        request_method="GET",
    )

    assert findings == []


def test_broad_allowed_methods_are_not_classified_as_vulnerability():
    from webhawk.core.models import FindingClassification

    findings = _analyze_cors_test_response(
        ("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE"),
        request_method="OPTIONS",
    )

    assert len(findings) == 1
    assert findings[0].classification == FindingClassification.OBSERVATION


def test_missing_vary_origin_does_not_produce_finding():
    findings = _analyze_cors_test_response(
        ("Access-Control-Allow-Origin", "https://trusted.example"),
    )

    assert findings == []


def test_wildcard_credentials_finding_contains_observed_header_evidence():
    findings = _analyze_cors_test_response(
        ("Access-Control-Allow-Origin", "*"),
        ("Access-Control-Allow-Credentials", "true"),
    )

    evidence = findings[0].evidence[0]

    assert evidence.evidence_type == "http_response_headers"
    assert evidence.source == "cors"
    assert evidence.details["observed_headers"] == {
        "access-control-allow-origin": ["*"],
        "access-control-allow-credentials": ["true"],
    }


def test_analysis_does_not_mutate_response_metadata():
    metadata = _cors_test_metadata(
        ("Access-Control-Allow-Origin", "*"),
        ("Access-Control-Allow-Credentials", "true"),
    )
    original_headers = metadata.headers

    from webhawk.analyzers.cors import analyze_cors

    analyze_cors(metadata)

    assert metadata.headers == original_headers


def test_duplicate_acao_suppresses_separate_credentials_observation():
    findings = _analyze_cors_test_response(
        ("Access-Control-Allow-Origin", "https://one.example"),
        ("Access-Control-Allow-Origin", "https://two.example"),
        ("Access-Control-Allow-Credentials", "true"),
    )

    assert len(findings) == 1
    assert findings[0].title == (
        "Multiple Access-Control-Allow-Origin headers"
    )
