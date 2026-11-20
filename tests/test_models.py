from datetime import datetime, timezone
from uuid import UUID

import pytest
from pydantic import ValidationError

from webhawk.core.models import (
    Evidence,
    Finding,
    FindingClassification,
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
            started_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
            completed_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )


def test_finding_is_immutable():
    finding = make_finding()

    with pytest.raises(ValidationError):
        finding.title = "Modified title"
