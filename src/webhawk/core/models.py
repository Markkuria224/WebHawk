from datetime import datetime, timezone
from enum import StrEnum
from typing import Any
from urllib.parse import urlsplit, urlunsplit
from uuid import UUID, uuid4

from pydantic import (
    AnyHttpUrl,
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
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


class HTTPHeader(BaseModel):
    """A safely stored HTTP response header."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(min_length=1, max_length=256)
    value: str = Field(max_length=16384)

    @model_validator(mode="after")
    def validate_and_redact(self):
        # RFC 9110 token characters used by HTTP field names.
        allowed_name_characters = (
            "!#$%&'*+-.^_`|~"
            "0123456789"
            "abcdefghijklmnopqrstuvwxyz"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        )

        if not self.name or any(
            character not in allowed_name_characters
            for character in self.name
        ):
            raise ValueError("Invalid HTTP header name.")

        # HTAB is permitted in field values. Other C0 controls and DEL
        # are rejected to prevent unsafe or ambiguous header storage.
        if any(
            (ord(character) < 32 and character != "\t")
            or ord(character) == 127
            for character in self.value
        ):
            raise ValueError("HTTP header values contain prohibited control characters.")

        sensitive_headers = {
            "cookie",
            "set-cookie",
            "authorization",
            "proxy-authorization",
        }

        if self.name.casefold() in sensitive_headers:
            object.__setattr__(self, "value", "[REDACTED]")

        return self


def sanitize_metadata_url(value: Any) -> str:
    """Remove query strings and fragments from stored response URLs."""
    parsed = urlsplit(str(value))

    return urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            "",
            "",
        )
    )


class HTTPResponseMetadata(BaseModel):
    """Security-conscious metadata describing an HTTP response."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    requested_url: AnyHttpUrl
    response_url: AnyHttpUrl
    status_code: int = Field(ge=100, le=599)
    http_version: str = Field(min_length=1, max_length=20)

    headers: tuple[HTTPHeader, ...] = Field(
        default=(),
        max_length=200,
    )

    elapsed_ms: float = Field(ge=0)
    received_at: datetime = Field(default_factory=utc_now)

    @field_validator("requested_url", "response_url", mode="before")
    @classmethod
    def sanitize_urls(cls, value):
        return sanitize_metadata_url(value)

    @model_validator(mode="after")
    def validate_urls_and_timestamp(self):
        for field_name, url in (
            ("requested_url", self.requested_url),
            ("response_url", self.response_url),
        ):
            if url.username is not None or url.password is not None:
                raise ValueError(
                    f"{field_name} must not contain embedded credentials."
                )

        if self.received_at.tzinfo is None:
            raise ValueError("Response timestamp must include a timezone.")

        return self


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
