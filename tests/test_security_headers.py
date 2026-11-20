import pytest

from webhawk.analyzers.security_headers import (
    ANALYZER_NAME,
    build_header_evidence,
    collect_header_values,
)
from webhawk.core.models import HTTPResponseMetadata


@pytest.fixture
def metadata():
    return HTTPResponseMetadata(
        requested_url="https://example.com",
        response_url="https://example.com/",
        status_code=200,
        http_version="HTTP/2",
        elapsed_ms=125,
        headers=(
            {"name": "Content-Type", "value": "text/html"},
            {"name": "X-Frame-Options", "value": "DENY"},
            {"name": "x-frame-options", "value": "SAMEORIGIN"},
            HTTPHeader(name="Strict-Transport-Security", value="max-age=31536000"),
        ),
    )


def test_collects_headers_case_insensitively(metadata):
    headers = collect_header_values(metadata)

    assert headers["content-type"] == ("text/html",)
    assert headers["strict-transport-security"] == (
        "max-age=31536000",
    )


def test_preserves_duplicate_header_values(metadata):
    headers = collect_header_values(metadata)

    assert headers["x-frame-options"] == (
        "DENY",
        "SAMEORIGIN",
    )


def test_preserves_duplicate_header_order(metadata):
    headers = collect_header_values(metadata)

    assert headers["x-frame-options"][0] == "DENY"
    assert headers["x-frame-options"][1] == "SAMEORIGIN"


def test_empty_metadata_returns_empty_header_index():
    empty_metadata = HTTPResponseMetadata(
        requested_url="https://example.com",
        response_url="https://example.com/",
        status_code=204,
        http_version="HTTP/2",
        elapsed_ms=10,
    )

    assert collect_header_values(empty_metadata) == {}


def test_builds_evidence_for_observed_header(metadata):
    evidence = build_header_evidence(
        metadata=metadata,
        header_name="X-Frame-Options",
        description="The response supplied an X-Frame-Options policy.",
    )

    assert evidence.evidence_type == "http_response_header"
    assert evidence.source == ANALYZER_NAME
    assert evidence.details["header_name"] == "x-frame-options"
    assert evidence.details["observed_values"] == [
        "DENY",
        "SAMEORIGIN",
    ]
    assert evidence.details["status_code"] == 200
    assert evidence.details["response_url"] == "https://example.com/"


def test_evidence_preserves_duplicate_values(metadata):
    evidence = build_header_evidence(
        metadata=metadata,
        header_name="x-frame-options",
        description="Duplicate header test.",
    )

    assert len(evidence.details["observed_values"]) == 2


def test_evidence_header_lookup_is_case_insensitive(metadata):
    evidence = build_header_evidence(
        metadata=metadata,
        header_name="STRICT-TRANSPORT-SECURITY",
        description="HSTS was observed.",
    )

    assert evidence.details["observed_values"] == [
        "max-age=31536000",
    ]


def test_rejects_evidence_for_missing_header(metadata):
    with pytest.raises(ValueError, match="was not present"):
        build_header_evidence(
            metadata=metadata,
            header_name="permissions-policy",
            description="Missing policy.",
        )


def test_header_collection_does_not_mutate_metadata(metadata):
    original_headers = metadata.headers

    collect_header_values(metadata)

    assert metadata.headers == original_headers

# ---------------------------------------------------------------------------
# HSTS analysis tests
# ---------------------------------------------------------------------------

from webhawk.analyzers.security_headers import analyze_hsts
from webhawk.core.models import FindingClassification, HTTPHeader, Severity


def make_hsts_metadata(value=None, url="https://example.com/"):
    headers = ()

    if value is not None:
        headers = (
            {"name": "Strict-Transport-Security", "value": value},
        )

    return HTTPResponseMetadata(
        requested_url=url,
        response_url=url,
        status_code=200,
        http_version="HTTP/2",
        elapsed_ms=100,
        headers=headers,
    )


def test_hsts_missing_on_https_is_potential_weakness():
    findings = analyze_hsts(make_hsts_metadata())

    assert len(findings) == 1
    assert findings[0].title == "HSTS header not observed"
    assert findings[0].severity == Severity.LOW
    assert findings[0].classification == (
        FindingClassification.POTENTIAL_WEAKNESS
    )


def test_hsts_missing_on_http_is_not_reported():
    findings = analyze_hsts(
        make_hsts_metadata(url="http://example.com/")
    )

    assert findings == []


def test_hsts_with_one_year_max_age_is_accepted():
    findings = analyze_hsts(
        make_hsts_metadata("max-age=31536000")
    )

    assert findings == []


def test_hsts_with_longer_max_age_is_accepted():
    findings = analyze_hsts(
        make_hsts_metadata(
            "max-age=63072000; includeSubDomains; preload"
        )
    )

    assert findings == []


def test_hsts_max_age_zero_is_reported():
    findings = analyze_hsts(
        make_hsts_metadata("max-age=0")
    )

    assert len(findings) == 1
    assert findings[0].title == "HSTS explicitly disabled"
    assert findings[0].severity == Severity.MEDIUM


def test_hsts_short_max_age_is_reported():
    findings = analyze_hsts(
        make_hsts_metadata("max-age=86400")
    )

    assert len(findings) == 1
    assert findings[0].title == "Short HSTS policy duration"
    assert findings[0].severity == Severity.LOW


@pytest.mark.parametrize(
    "value",
    [
        "includeSubDomains",
        "max-age",
        "max-age=",
        "max-age=abc",
        "max-age=-1",
        "max-age=31536000; max-age=86400",
        "max-age=31536000; includeSubDomains=true",
        "max-age=31536000; =invalid",
    ],
)
def test_invalid_hsts_policies_are_reported(value):
    findings = analyze_hsts(make_hsts_metadata(value))

    assert len(findings) == 1
    assert findings[0].title == "Invalid HSTS policy"
    assert findings[0].classification == (
        FindingClassification.CONFIRMED_MISCONFIGURATION
    )


def test_duplicate_hsts_header_fields_are_reported():
    metadata = make_hsts_metadata()

    metadata = metadata.model_copy(
        update={
            "headers": (
                HTTPHeader(name="Strict-Transport-Security", value="max-age=31536000"),
                HTTPHeader(name="strict-transport-security", value="max-age=0"),
            )
        }
    )

    findings = analyze_hsts(metadata)

    assert len(findings) == 1
    assert findings[0].title == "Duplicate HSTS headers"
    assert len(
        findings[0].evidence[0].details["observed_values"]
    ) == 2


def test_hsts_header_lookup_is_case_insensitive():
    findings = analyze_hsts(
        make_hsts_metadata("max-age=31536000")
        .model_copy(
            update={
                "headers": (
                    HTTPHeader(
                        name="STRICT-TRANSPORT-SECURITY",
                        value="max-age=31536000",
                    ),
                )
            }
        )
    )

    assert findings == []


def test_hsts_evidence_contains_observed_policy():
    findings = analyze_hsts(
        make_hsts_metadata("max-age=86400")
    )

    evidence = findings[0].evidence[0]

    assert evidence.details["header_name"] == "strict-transport-security"
    assert evidence.details["observed_values"] == ["max-age=86400"]
    assert evidence.details["status_code"] == 200


def test_hsts_analysis_does_not_modify_metadata():
    metadata = make_hsts_metadata("max-age=86400")
    original_headers = metadata.headers

    analyze_hsts(metadata)

    assert metadata.headers == original_headers

def test_hsts_trailing_semicolon_is_accepted():
    findings = analyze_hsts(
        make_hsts_metadata("max-age=31536000;")
    )

    assert findings == []


def test_hsts_empty_directive_segments_are_ignored():
    findings = analyze_hsts(
        make_hsts_metadata("max-age=31536000;;")
    )

    assert findings == []


def test_hsts_unknown_directive_is_tolerated():
    findings = analyze_hsts(
        make_hsts_metadata(
            "max-age=31536000; unknownDirective=value"
        )
    )

    assert findings == []


def test_hsts_very_large_max_age_does_not_crash():
    findings = analyze_hsts(
        make_hsts_metadata("max-age=" + ("9" * 5000))
    )

    assert findings == []


def test_hsts_max_age_with_leading_zeroes_is_parsed():
    findings = analyze_hsts(
        make_hsts_metadata("max-age=00031536000")
    )

    assert findings == []

# HSTS quoted-string regression tests

def test_hsts_quoted_one_year_max_age_is_accepted():
    findings = analyze_hsts(
        make_hsts_metadata('max-age="31536000"')
    )

    assert findings == []


def test_hsts_quoted_zero_max_age_is_reported():
    findings = analyze_hsts(
        make_hsts_metadata('max-age="0"')
    )

    assert len(findings) == 1
    assert findings[0].title == "HSTS explicitly disabled"


def test_hsts_quoted_short_max_age_is_reported():
    findings = analyze_hsts(
        make_hsts_metadata('max-age="86400"')
    )

    assert len(findings) == 1
    assert findings[0].title == "Short HSTS policy duration"


@pytest.mark.parametrize(
    "value",
    [
        'max-age="abc"',
        'max-age="31536000',
        'max-age=""',
        'max-age="31536000"junk',
        'max-age="3153603\\q"',
    ],
)
def test_malformed_quoted_hsts_values_are_reported(value):
    findings = analyze_hsts(make_hsts_metadata(value))

    assert len(findings) == 1
    assert findings[0].title == "Invalid HSTS policy"


def test_hsts_quoted_unknown_directive_can_contain_semicolon():
    findings = analyze_hsts(
        make_hsts_metadata(
            'unknown="a;b"; max-age=31536000'
        )
    )

    assert findings == []


def test_hsts_escaped_quote_does_not_split_directives():
    findings = analyze_hsts(
        make_hsts_metadata(
            r'unknown="a\";b"; max-age=31536000'
        )
    )

    assert findings == []


# HSTS unquoted token validation tests

def test_hsts_accepts_valid_unquoted_unknown_directive():
    findings = analyze_hsts(
        make_hsts_metadata(
            "unknown=valid-token; max-age=31536000"
        )
    )
    assert findings == []


def test_hsts_rejects_unquoted_value_containing_spaces():
    findings = analyze_hsts(
        make_hsts_metadata(
            "unknown=invalid value; max-age=31536000"
        )
    )
    assert len(findings) == 1
    assert findings[0].title == "Invalid HSTS policy"


def test_hsts_rejects_unquoted_value_containing_quotes():
    findings = analyze_hsts(
        make_hsts_metadata(
            'unknown=invalid"value; max-age=31536000'
        )
    )
    assert len(findings) == 1
    assert findings[0].title == "Invalid HSTS policy"


def test_hsts_accepts_quoted_unknown_directive_with_spaces():
    findings = analyze_hsts(
        make_hsts_metadata(
            'unknown="valid quoted value"; max-age=31536000'
        )
    )
    assert findings == []
