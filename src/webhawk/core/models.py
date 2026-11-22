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


class ScanErrorCode(StrEnum):
    INVALID_TARGET = "invalid_target"
    TARGET_NOT_AUTHORIZED = "target_not_authorized"
    UNSAFE_ADDRESS = "unsafe_address"
    DNS_RESOLUTION_FAILED = "dns_resolution_failed"
    TLS_FAILED = "tls_failed"
    CONNECTION_FAILED = "connection_failed"
    REQUEST_TIMEOUT = "request_timeout"
    RESPONSE_TOO_LARGE = "response_too_large"
    CONFIGURATION_ERROR = "configuration_error"
    ANALYSIS_FAILED = "analysis_failed"
    UNEXPECTED_ERROR = "unexpected_error"


SCAN_ERROR_MESSAGES = {
    ScanErrorCode.INVALID_TARGET: "The supplied target URL is invalid.",
    ScanErrorCode.TARGET_NOT_AUTHORIZED: "The target is not authorized for assessment.",
    ScanErrorCode.UNSAFE_ADDRESS: "The target resolved to an address that violates the safety policy.",
    ScanErrorCode.DNS_RESOLUTION_FAILED: "The target hostname could not be resolved.",
    ScanErrorCode.TLS_FAILED: "A secure TLS connection could not be established.",
    ScanErrorCode.CONNECTION_FAILED: "A connection to the target could not be established.",
    ScanErrorCode.REQUEST_TIMEOUT: "The request exceeded its configured time limit.",
    ScanErrorCode.RESPONSE_TOO_LARGE: "The target response exceeded the configured size limit.",
    ScanErrorCode.CONFIGURATION_ERROR: "The assessment configuration is invalid or unsupported.",
    ScanErrorCode.ANALYSIS_FAILED: "The response could not be analyzed successfully.",
    ScanErrorCode.UNEXPECTED_ERROR: "The assessment failed because of an unexpected internal error.",
}


class ScanError(BaseModel):
    """A safe, structured assessment failure."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: ScanErrorCode
    message: str = Field(min_length=1, max_length=300)

    @model_validator(mode="before")
    @classmethod
    def enforce_safe_message(cls, data):
        if not isinstance(data, dict):
            return data

        try:
            code = ScanErrorCode(data.get("code"))
        except (ValueError, TypeError):
            return data

        expected_message = SCAN_ERROR_MESSAGES[code]
        supplied_message = data.get("message")

        if supplied_message is not None and supplied_message != expected_message:
            raise ValueError(
                "Scan error messages must use their predefined safe description."
            )

        data = dict(data)
        data["message"] = expected_message

        return data


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

        if any(
            (ord(character) < 32 and character != "\t")
            or ord(character) == 127
            for character in self.value
        ):
            raise ValueError(
                "HTTP header values contain prohibited control characters."
            )

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
    error: ScanError | None = None

    @model_validator(mode="after")
    def validate_scan_lifecycle(self):
        if self.started_at.tzinfo is None:
            raise ValueError("Start timestamp must include a timezone.")

        if self.completed_at is not None:
            if self.completed_at.tzinfo is None:
                raise ValueError("Completion timestamp must include a timezone.")

            if self.completed_at < self.started_at:
                raise ValueError("Completion cannot precede scan start.")

        if self.status in {ScanStatus.PENDING, ScanStatus.RUNNING}:
            if self.completed_at is not None:
                raise ValueError(
                    "Pending or running scans cannot have a completion timestamp."
                )

            if self.error is not None:
                raise ValueError(
                    "Pending or running scans cannot contain an error."
                )

            if self.findings:
                raise ValueError(
                    "Pending or running scans cannot contain findings."
                )

        elif self.status == ScanStatus.COMPLETED:
            if self.completed_at is None:
                raise ValueError(
                    "Completed scans must have a completion timestamp."
                )

            if self.error is not None:
                raise ValueError(
                    "Completed scans cannot contain an error."
                )

        elif self.status == ScanStatus.FAILED:
            if self.completed_at is None:
                raise ValueError(
                    "Failed scans must have a completion timestamp."
                )

            if self.error is None:
                raise ValueError(
                    "Failed scans must contain a structured error."
                )

            if self.findings:
                raise ValueError(
                    "Failed scans cannot retain partial findings."
                )

        elif self.status == ScanStatus.CANCELLED:
            if self.completed_at is None:
                raise ValueError(
                    "Cancelled scans must have a completion timestamp."
                )

            if self.error is not None:
                raise ValueError(
                    "Cancelled scans cannot contain an error."
                )

            if self.findings:
                raise ValueError(
                    "Cancelled scans cannot retain partial findings."
                )

        return self
