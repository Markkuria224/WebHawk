from datetime import datetime, timezone
from uuid import UUID

import pytest
from pydantic import ValidationError

from webhawk.core.models import (
    Evidence,
    Finding,
    FindingClassification,
    HTTPHeader,
    HTTPResponseMetadata,
    ScanError,
    ScanErrorCode,
    ScanResult,
    ScanStatus,
    ScanTarget,
    Severity,
)


def make_evidence():
    return Evidence(
        evidence_type="http_header",
        description="Test evidence",
        source="headers_analyzer",
    )


def make_finding():
    return Finding(
        title="Missing security header",
        description="A security header was not observed.",
        severity=Severity.MEDIUM,
        classification=FindingClassification.POTENTIAL_WEAKNESS,
        confidence=80,
        analyzer="headers",
        evidence=[make_evidence()],
    )


def test_valid_scan_target():
    target = ScanTarget(url="https://example.com")
    assert str(target.url) == "https://example.com/"


def test_invalid_scan_target():
    with pytest.raises(ValidationError):
        ScanTarget(url="not-a-url")


def test_evidence_has_unique_uuid():
    first = make_evidence()
    second = make_evidence()
    assert isinstance(first.evidence_id, UUID)
    assert first.evidence_id != second.evidence_id


def test_evidence_rejects_naive_timestamp():
    with pytest.raises(ValidationError):
        Evidence(
            evidence_type="header",
            description="Test",
            source="headers",
            observed_at=datetime.now(),
        )


def test_finding_requires_evidence():
    with pytest.raises(ValidationError):
        Finding(
            title="Test",
            description="Test finding",
            severity=Severity.LOW,
            classification=FindingClassification.OBSERVATION,
            confidence=50,
            analyzer="test",
            evidence=[],
        )


def test_finding_rejects_invalid_confidence():
    with pytest.raises(ValidationError):
        Finding(
            title="Test",
            description="Test finding",
            severity=Severity.LOW,
            classification=FindingClassification.OBSERVATION,
            confidence=110,
            analyzer="test",
            evidence=[make_evidence()],
        )


def test_scan_result_defaults():
    result = ScanResult(
        target=ScanTarget(url="https://example.com")
    )
    assert result.status == ScanStatus.PENDING
    assert result.findings == []
    assert result.completed_at is None


def test_scan_result_rejects_completion_before_start():
    with pytest.raises(ValidationError):
        ScanResult(
            target=ScanTarget(url="https://example.com"),
            status=ScanStatus.COMPLETED,
            started_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
            completed_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )


def test_finding_is_immutable():
    finding = make_finding()

    with pytest.raises(ValidationError):
        finding.title = "Modified title"


def make_response_metadata(**overrides):
    values = {
        "requested_url": "https://example.com",
        "response_url": "https://example.com/",
        "status_code": 200,
        "http_version": "HTTP/1.1",
        "headers": (
            HTTPHeader(name="Content-Type", value="text/html"),
            HTTPHeader(name="X-Frame-Options", value="DENY"),
        ),
        "elapsed_ms": 125.5,
    }
    values.update(overrides)
    return HTTPResponseMetadata(**values)


def test_response_metadata_accepts_valid_response():
    metadata = make_response_metadata()

    assert metadata.status_code == 200
    assert metadata.http_version == "HTTP/1.1"
    assert metadata.elapsed_ms == 125.5
    assert metadata.received_at.tzinfo is not None


def test_response_metadata_preserves_duplicate_headers():
    metadata = make_response_metadata(
        headers=(
            HTTPHeader(name="Set-Cookie", value="session=first"),
            HTTPHeader(name="Set-Cookie", value="session=second"),
        )
    )

    assert len(metadata.headers) == 2
    assert metadata.headers[0].name == "Set-Cookie"
    assert metadata.headers[1].name == "Set-Cookie"


@pytest.mark.parametrize(
    "name",
    [
        "Cookie",
        "Set-Cookie",
        "Authorization",
        "Proxy-Authorization",
        "authorization",
        "SET-COOKIE",
    ],
)
def test_sensitive_header_values_are_redacted(name):
    header = HTTPHeader(name=name, value="sensitive-secret")

    assert header.value == "[REDACTED]"


def test_non_sensitive_header_values_are_preserved():
    header = HTTPHeader(
        name="Content-Type",
        value="text/html; charset=utf-8",
    )

    assert header.value == "text/html; charset=utf-8"


@pytest.mark.parametrize(
    "value",
    ["bad" + chr(13) + "value", "bad" + chr(10) + "value"],
)
def test_header_rejects_newline_characters(value):
    with pytest.raises(ValidationError):
        HTTPHeader(name="X-Test", value=value)


def test_response_metadata_rejects_invalid_status_code():
    with pytest.raises(ValidationError):
        make_response_metadata(status_code=99)


def test_response_metadata_rejects_negative_elapsed_time():
    with pytest.raises(ValidationError):
        make_response_metadata(elapsed_ms=-1)


def test_response_metadata_rejects_naive_timestamp():
    with pytest.raises(ValidationError):
        make_response_metadata(received_at=datetime(2026, 1, 1))


def test_response_metadata_rejects_too_many_headers():
    headers = tuple(
        HTTPHeader(name=f"X-Test-{index}", value="value")
        for index in range(201)
    )

    with pytest.raises(ValidationError):
        make_response_metadata(headers=headers)


def test_response_metadata_is_immutable():
    metadata = make_response_metadata()

    with pytest.raises(ValidationError):
        metadata.status_code = 404


def test_response_headers_are_immutable_collection():
    metadata = make_response_metadata()

    assert isinstance(metadata.headers, tuple)

    with pytest.raises(ValidationError):
        metadata.headers = ()


def test_response_metadata_rejects_unknown_fields():
    with pytest.raises(ValidationError):
        make_response_metadata(unexpected_field="value")



@pytest.mark.parametrize(
    "name",
    [
        "X Test",
        "X@Test",
        "X:Test",
        "X/Test",
        "X\\Test",
        "X_Test\\n",
        "X-T?st",
    ],
)
def test_header_rejects_invalid_names(name):
    with pytest.raises(ValidationError):
        HTTPHeader(name=name, value="value")


@pytest.mark.parametrize(
    "name",
    [
        "X-Test",
        "Content-Type",
        "X_Custom",
        "ETag",
        "WWW-Authenticate",
    ],
)
def test_header_accepts_valid_names(name):
    header = HTTPHeader(name=name, value="value")
    assert header.name == name


@pytest.mark.parametrize(
    "value",
    [
        "bad" + chr(0) + "value",
        "bad" + chr(8) + "value",
        "bad" + chr(10) + "value",
        "bad" + chr(13) + "value",
        "bad" + chr(127) + "value",
    ],
)
def test_header_rejects_prohibited_control_characters(value):
    with pytest.raises(ValidationError):
        HTTPHeader(name="X-Test", value=value)


def test_header_allows_horizontal_tab():
    header = HTTPHeader(name="X-Test", value="first\tsecond")
    assert header.value == "first\tsecond"


def test_sensitive_headers_remain_redacted_in_dictionary_serialization():
    metadata = make_response_metadata(
        headers=(
            HTTPHeader(name="Set-Cookie", value="session=secret"),
            HTTPHeader(name="Authorization", value="Bearer secret"),
        )
    )

    serialized = metadata.model_dump()

    assert serialized["headers"][0]["value"] == "[REDACTED]"
    assert serialized["headers"][1]["value"] == "[REDACTED]"
    assert "session=secret" not in str(serialized)
    assert "Bearer secret" not in str(serialized)


def test_sensitive_headers_remain_redacted_in_json_serialization():
    metadata = make_response_metadata(
        headers=(
            HTTPHeader(name="Set-Cookie", value="session=secret"),
            HTTPHeader(name="Cookie", value="account=secret"),
        )
    )

    serialized = metadata.model_dump_json()

    assert "session=secret" not in serialized
    assert "account=secret" not in serialized
    assert "[REDACTED]" in serialized

@pytest.mark.parametrize(
    "url",
    [
        "https://admin:secret@example.com/",
        "https://admin@example.com/",
        "https://:secret@example.com/",
    ],
)
@pytest.mark.parametrize(
    "field_name",
    [
        "requested_url",
        "response_url",
    ],
)
def test_response_metadata_rejects_embedded_url_credentials(
    url,
    field_name,
):
    with pytest.raises(ValidationError, match="embedded credentials"):
        make_response_metadata(**{field_name: url})

@pytest.mark.parametrize(
    "url",
    [
        "https://example.com/account?api_key=SECRET123",
        "https://example.com/account?session=ABC#profile",
        "https://example.com/path?token=secret&user=mark",
        "https://example.com/path#sensitive-fragment",
    ],
)
@pytest.mark.parametrize(
    "field_name",
    [
        "requested_url",
        "response_url",
    ],
)
def test_response_metadata_removes_query_and_fragment(url, field_name):
    metadata = make_response_metadata(**{field_name: url})

    stored_url = str(getattr(metadata, field_name))

    assert "?" not in stored_url
    assert "#" not in stored_url
    assert "SECRET123" not in stored_url
    assert "session=ABC" not in stored_url
    assert "token=secret" not in stored_url


def test_response_metadata_preserves_url_path_and_port():
    metadata = make_response_metadata(
        requested_url="https://example.com:8443/admin/dashboard?token=secret",
    )

    assert str(metadata.requested_url) == (
        "https://example.com:8443/admin/dashboard"
    )


def test_response_metadata_does_not_store_query_secrets_in_json():
    metadata = make_response_metadata(
        requested_url="https://example.com/?api_key=SUPERSECRET",
        response_url="https://example.com/?session=PRIVATE",
    )

    serialized = metadata.model_dump_json()

    assert "SUPERSECRET" not in serialized
    assert "PRIVATE" not in serialized
    assert "api_key" not in serialized
    assert "session" not in serialized



# ---------------------------------------------------------------------------
# Structured scan error tests
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("code", list(ScanErrorCode))
def test_scan_error_uses_predefined_safe_message(code):
    error = ScanError(code=code)

    assert error.code == code
    assert error.message
    assert len(error.message) <= 300


def test_scan_error_rejects_arbitrary_message():
    with pytest.raises(ValidationError):
        ScanError(
            code=ScanErrorCode.CONNECTION_FAILED,
            message="Connection failed: secret internal exception details",
        )


def test_scan_error_rejects_unknown_code():
    with pytest.raises(ValidationError):
        ScanError(code="arbitrary_error")


def test_scan_error_is_immutable():
    error = ScanError(code=ScanErrorCode.TLS_FAILED)

    with pytest.raises(ValidationError):
        error.message = "Modified error"


def test_scan_error_json_contains_safe_message():
    error = ScanError(code=ScanErrorCode.REQUEST_TIMEOUT)

    serialized = error.model_dump_json()

    assert error.message in serialized
    assert "internal exception" not in serialized


# ---------------------------------------------------------------------------
# Scan lifecycle tests
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "status",
    [
        ScanStatus.PENDING,
        ScanStatus.RUNNING,
    ],
)
def test_scan_result_accepts_in_progress_statuses(status):
    result = ScanResult(
        target=ScanTarget(url="https://example.com"),
        status=status,
    )

    assert result.status == status
    assert result.completed_at is None
    assert result.error is None
    assert result.findings == []


def test_scan_result_accepts_completed_scan_with_findings():
    started_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
    completed_at = datetime(2026, 1, 2, tzinfo=timezone.utc)

    result = ScanResult(
        target=ScanTarget(url="https://example.com"),
        status=ScanStatus.COMPLETED,
        started_at=started_at,
        completed_at=completed_at,
        findings=[make_finding()],
    )

    assert result.status == ScanStatus.COMPLETED
    assert len(result.findings) == 1
    assert result.error is None

def test_scan_result_accepts_completed_scan_without_findings():
    result = ScanResult(
        target=ScanTarget(url="https://example.com"),
        status=ScanStatus.COMPLETED,
        started_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            completed_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
    )

    assert result.status == ScanStatus.COMPLETED
    assert result.findings == []


def test_scan_result_accepts_failed_scan_with_structured_error():
    result = ScanResult(
        target=ScanTarget(url="https://example.com"),
        status=ScanStatus.FAILED,
        started_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            completed_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
        error=ScanError(code=ScanErrorCode.CONNECTION_FAILED),
    )

    assert result.status == ScanStatus.FAILED
    assert result.error.code == ScanErrorCode.CONNECTION_FAILED
    assert result.findings == []


def test_scan_result_accepts_cancelled_scan():
    result = ScanResult(
        target=ScanTarget(url="https://example.com"),
        status=ScanStatus.CANCELLED,
        started_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            completed_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
    )

    assert result.status == ScanStatus.CANCELLED
    assert result.error is None
    assert result.findings == []


@pytest.mark.parametrize(
    "status",
    [
        ScanStatus.PENDING,
        ScanStatus.RUNNING,
    ],
)
def test_scan_result_rejects_completion_timestamp_for_in_progress_scan(status):
    with pytest.raises(ValidationError):
        ScanResult(
            target=ScanTarget(url="https://example.com"),
            status=status,
            started_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            completed_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
        )


@pytest.mark.parametrize(
    "status",
    [
        ScanStatus.PENDING,
        ScanStatus.RUNNING,
    ],
)
def test_scan_result_rejects_error_for_in_progress_scan(status):
    with pytest.raises(ValidationError):
        ScanResult(
            target=ScanTarget(url="https://example.com"),
            status=status,
            error=ScanError(code=ScanErrorCode.CONNECTION_FAILED),
        )


@pytest.mark.parametrize(
    "status",
    [
        ScanStatus.PENDING,
        ScanStatus.RUNNING,
    ],
)
def test_scan_result_rejects_findings_for_in_progress_scan(status):
    with pytest.raises(ValidationError):
        ScanResult(
            target=ScanTarget(url="https://example.com"),
            status=status,
            findings=[make_finding()],
        )


def test_scan_result_rejects_completed_without_timestamp():
    with pytest.raises(ValidationError):
        ScanResult(
            target=ScanTarget(url="https://example.com"),
            status=ScanStatus.COMPLETED,
        )


def test_scan_result_rejects_completed_with_error():
    with pytest.raises(ValidationError):
        ScanResult(
            target=ScanTarget(url="https://example.com"),
            status=ScanStatus.COMPLETED,
            started_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            completed_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
            error=ScanError(code=ScanErrorCode.CONNECTION_FAILED),
        )


def test_scan_result_rejects_failed_without_timestamp():
    with pytest.raises(ValidationError):
        ScanResult(
            target=ScanTarget(url="https://example.com"),
            status=ScanStatus.FAILED,
            error=ScanError(code=ScanErrorCode.CONNECTION_FAILED),
        )


def test_scan_result_rejects_failed_without_error():
    with pytest.raises(ValidationError):
        ScanResult(
            target=ScanTarget(url="https://example.com"),
            status=ScanStatus.FAILED,
            started_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            completed_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
        )


def test_scan_result_rejects_failed_with_partial_findings():
    with pytest.raises(ValidationError):
        ScanResult(
            target=ScanTarget(url="https://example.com"),
            status=ScanStatus.FAILED,
            started_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            completed_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
            error=ScanError(code=ScanErrorCode.ANALYSIS_FAILED),
            findings=[make_finding()],
        )


def test_scan_result_rejects_cancelled_without_timestamp():
    with pytest.raises(ValidationError):
        ScanResult(
            target=ScanTarget(url="https://example.com"),
            status=ScanStatus.CANCELLED,
        )


def test_scan_result_rejects_cancelled_with_error():
    with pytest.raises(ValidationError):
        ScanResult(
            target=ScanTarget(url="https://example.com"),
            status=ScanStatus.CANCELLED,
            started_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            completed_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
            error=ScanError(code=ScanErrorCode.CONNECTION_FAILED),
        )


def test_scan_result_rejects_cancelled_with_partial_findings():
    with pytest.raises(ValidationError):
        ScanResult(
            target=ScanTarget(url="https://example.com"),
            status=ScanStatus.CANCELLED,
            started_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            completed_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
            findings=[make_finding()],
        )


def test_scan_result_rejects_completion_before_start_for_completed_status():
    with pytest.raises(ValidationError, match="Completion cannot precede scan start"):
        ScanResult(
            target=ScanTarget(url="https://example.com"),
            status=ScanStatus.COMPLETED,
            started_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
            completed_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )


def test_failed_scan_serialization_contains_safe_error_only():
    result = ScanResult(
        target=ScanTarget(url="https://example.com"),
        status=ScanStatus.FAILED,
        started_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            completed_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
        error=ScanError(code=ScanErrorCode.CONNECTION_FAILED),
    )

    serialized = result.model_dump_json()

    assert "connection_failed" in serialized
    assert "A connection to the target could not be established." in serialized
    assert "Traceback" not in serialized
