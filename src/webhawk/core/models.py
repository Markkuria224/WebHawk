from datetime import datetime, timezone
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from pydantic import (
    AnyHttpUrl,
    BaseModel,
    ConfigDict,
    Field,
    model_validator,
)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Severity(StrEnum):
    INFO = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingClassification(StrEnum):
    OBSERVATION = "observation"
    POTENTIAL_WEAKNESS = "potential_weakness"
    CONFIRMED_MISCONFIGURATION = "confirmed_misconfiguration"


class ScanStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Evidence(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    evidence_id: UUID = Field(default_factory=uuid4)
    evidence_type: str = Field(min_length=1, max_length=100)
    description: str = Field(min_length=1, max_length=2000)
    source: str = Field(min_length=1, max_length=100)
    observed_at: datetime = Field(default_factory=utc_now)
    details: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_timestamp(self):
        if self.observed_at.tzinfo is None:
            raise ValueError("Evidence timestamp must include a timezone.")
        return self


class ScanTarget(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    url: AnyHttpUrl
    display_name: str | None = Field(default=None, max_length=200)


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    finding_id: UUID = Field(default_factory=uuid4)
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(min_length=1, max_length=4000)
    severity: Severity
    classification: FindingClassification
    confidence: int = Field(ge=0, le=100)
    analyzer: str = Field(min_length=1, max_length=100)
    evidence: list[Evidence] = Field(min_length=1)
    remediation: str | None = Field(default=None, max_length=4000)
    observed_at: datetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def validate_timestamp(self):
        if self.observed_at.tzinfo is None:
            raise ValueError("Finding timestamp must include a timezone.")
        return self


class ScanResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scan_id: UUID = Field(default_factory=uuid4)
    target: ScanTarget
    status: ScanStatus = ScanStatus.PENDING
    tool_version: str = "0.1.0"
    started_at: datetime = Field(default_factory=utc_now)
    completed_at: datetime | None = None
    findings: list[Finding] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_timestamps(self):
        if self.started_at.tzinfo is None:
            raise ValueError("Start timestamp must include a timezone.")

        if self.completed_at is not None:
            if self.completed_at.tzinfo is None:
                raise ValueError("Completion timestamp must include a timezone.")

            if self.completed_at < self.started_at:
                raise ValueError("Completion cannot precede scan start.")

        return self
