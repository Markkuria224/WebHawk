"""Passive HTTP security-header analysis utilities."""

import re
from urllib.parse import urlsplit

from webhawk.core.models import (
    Evidence,
    Finding,
    FindingClassification,
    HTTPResponseMetadata,
    Severity,
)






ANALYZER_NAME = "security_headers"


def collect_header_values(
    metadata: HTTPResponseMetadata,
) -> dict[str, tuple[str, ...]]:
    """Collect response headers using case-insensitive names.

    Duplicate values and their original order are preserved.
    Header values are not modified.
    """

    collected: dict[str, list[str]] = {}

    for header in metadata.headers:
        normalized_name = header.name.casefold()
        collected.setdefault(normalized_name, []).append(header.value)

    return {
        name: tuple(values)
        for name, values in collected.items()
    }


def build_header_evidence(
    *,
    metadata: HTTPResponseMetadata,
    header_name: str,
    description: str,
) -> Evidence:
    """Build evidence for an observed HTTP response header.

    This helper only accepts headers actually present in metadata.
    Missing-header evidence will be handled separately by policy rules.
    """

    normalized_name = header_name.casefold()

    observed_values = collect_header_values(metadata).get(
        normalized_name,
        (),
    )

    if not observed_values:
        raise ValueError(
            f"Cannot create observed-header evidence: "
            f"{header_name!r} was not present."
        )

    return Evidence(
        evidence_type="http_response_header",
        description=description,
        source=ANALYZER_NAME,
        details={
            "header_name": normalized_name,
            "observed_values": list(observed_values),
            "response_url": str(metadata.response_url),
            "status_code": metadata.status_code,
        },
    )

# ---------------------------------------------------------------------------
# HTTP Strict Transport Security (HSTS)
# ---------------------------------------------------------------------------



HSTS_HEADER = "strict-transport-security"
HSTS_RECOMMENDED_MAX_AGE = 31_536_000

_HSTS_DIRECTIVE_NAME = re.compile(
    r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$"
)

_HSTS_TOKEN = re.compile(
    r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$"
)


def _hsts_finding(
    *,
    title: str,
    description: str,
    severity: Severity,
    classification: FindingClassification,
    confidence: int,
    evidence: Evidence,
    remediation: str,
) -> Finding:
    """Create a consistently structured HSTS finding."""

    return Finding(
        title=title,
        description=description,
        severity=severity,
        classification=classification,
        confidence=confidence,
        analyzer=ANALYZER_NAME,
        evidence=[evidence],
        remediation=remediation,
    )


def _split_hsts_segments(value: str) -> tuple[list[str], list[str]]:
    """Split HSTS directives on semicolons outside quoted strings."""

    segments = []
    errors = []
    start = 0
    quoted = False
    escaped = False

    for index, character in enumerate(value):
        if quoted:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                quoted = False
        elif character == '"':
            quoted = True
        elif character == ";":
            segments.append(value[start:index])
            start = index + 1

    segments.append(value[start:])

    if quoted:
        errors.append("The policy contains an unterminated quoted string.")

    return segments, errors


def _unquote_hsts_value(value: str) -> tuple[str | None, bool]:
    """Validate and unescape a quoted-string directive value."""

    if not value.startswith('"'):
        if not _HSTS_TOKEN.fullmatch(value):
            return None, False
        return value, True

    if len(value) < 2 or not value.endswith('"'):
        return None, False

    inner = value[1:-1]
    result = []
    index = 0

    while index < len(inner):
        character = inner[index]
        codepoint = ord(character)

        if character == "\\":
            index += 1

            if index >= len(inner):
                return None, False

            escaped_character = inner[index]
            escaped_codepoint = ord(escaped_character)

            if not (
                escaped_codepoint in (0x09, 0x20)
                or 0x21 <= escaped_codepoint <= 0x7E
                or 0x80 <= escaped_codepoint <= 0xFF
            ):
                return None, False

            result.append(escaped_character)

        else:
            if not (
                codepoint in (0x09, 0x20, 0x21)
                or 0x23 <= codepoint <= 0x5B
                or 0x5D <= codepoint <= 0x7E
                or 0x80 <= codepoint <= 0xFF
            ):
                return None, False

            result.append(character)

        index += 1

    return "".join(result), True


def _parse_hsts_policy(
    value: str,
) -> tuple[dict[str, str | None], list[str]]:
    """Parse an HSTS policy and return directives and syntax errors."""

    directives: dict[str, str | None] = {}
    segments, errors = _split_hsts_segments(value)

    for segment in segments:
        segment = segment.strip()

        if not segment:
            continue

        name, separator, raw_value = segment.partition("=")
        name = name.strip().casefold()

        if not name or not _HSTS_DIRECTIVE_NAME.fullmatch(name):
            errors.append("The policy contains an invalid directive name.")
            continue

        if name in directives:
            errors.append(f"The directive {name!r} appears more than once.")
            continue

        if separator:
            raw_value = raw_value.strip()

            if not raw_value:
                errors.append(f"The directive {name!r} has an empty value.")
                continue

            directive_value, valid_value = _unquote_hsts_value(raw_value)

            if not valid_value:
                errors.append(
                    f"The directive {name!r} has a malformed quoted value."
                )
                directives[name] = None
                continue

            if directive_value == "":
                errors.append(f"The directive {name!r} has an empty value.")
                directives[name] = None
                continue

            directives[name] = directive_value
        else:
            directives[name] = None

    if "max-age" not in directives:
        errors.append("The required max-age directive is missing.")
    elif directives["max-age"] is not None:
        if not re.fullmatch(r"[0-9]+", directives["max-age"]):
            errors.append(
                "The max-age directive must contain decimal digits."
            )
    else:
        errors.append("The max-age directive requires a value.")

    for flag in ("includesubdomains", "preload"):
        if flag in directives and directives[flag] is not None:
            errors.append(
                f"The {flag} directive must not have a value."
            )

    return directives, errors


def analyze_hsts(
    metadata: HTTPResponseMetadata,
) -> list[Finding]:
    """Passively analyze the Strict-Transport-Security response header."""

    scheme = urlsplit(str(metadata.response_url)).scheme.casefold()

    # Browsers ignore HSTS received over insecure HTTP.
    if scheme != "https":
        return []

    headers = collect_header_values(metadata)
    values = headers.get(HSTS_HEADER, ())

    if not values:
        evidence = Evidence(
            evidence_type="http_response_header_absence",
            description=(
                "No Strict-Transport-Security header was observed "
                "on the HTTPS response."
            ),
            source=ANALYZER_NAME,
            details={
                "header_name": HSTS_HEADER,
                "response_url": str(metadata.response_url),
                "status_code": metadata.status_code,
            },
        )

        return [
            _hsts_finding(
                title="HSTS header not observed",
                description=(
                    "The HTTPS response did not include a "
                    "Strict-Transport-Security header. Browsers that "
                    "have not previously learned an HSTS policy may "
                    "remain vulnerable to certain HTTPS downgrade scenarios."
                ),
                severity=Severity.LOW,
                classification=FindingClassification.POTENTIAL_WEAKNESS,
                confidence=75,
                evidence=evidence,
                remediation=(
                    "Consider deploying Strict-Transport-Security with "
                    "an appropriate max-age after verifying that HTTPS "
                    "works correctly across the intended domain."
                ),
            )
        ]

    evidence = build_header_evidence(
        metadata=metadata,
        header_name=HSTS_HEADER,
        description="The response supplied a Strict-Transport-Security policy.",
    )

    if len(values) > 1:
        evidence = Evidence(
            evidence_type="http_response_header",
            description=(
                "Multiple Strict-Transport-Security header fields "
                "were observed."
            ),
            source=ANALYZER_NAME,
            details={
                "header_name": HSTS_HEADER,
                "observed_values": list(values),
                "response_url": str(metadata.response_url),
                "status_code": metadata.status_code,
            },
        )

        return [
            _hsts_finding(
                title="Duplicate HSTS headers",
                description=(
                    "The response contains multiple Strict-Transport-Security "
                    "header fields. RFC 6797 requires servers to emit only one "
                    "STS header field, and browsers process only the first "
                    "field received. Later policies may therefore be ignored."
                ),
                severity=Severity.MEDIUM,
                classification=FindingClassification.CONFIRMED_MISCONFIGURATION,
                confidence=95,
                evidence=evidence,
                remediation=(
                    "Configure the server or reverse proxy to emit exactly "
                    "one intentional Strict-Transport-Security policy."
                ),
            )
        ]

    directives, errors = _parse_hsts_policy(values[0])

    if errors:
        evidence = Evidence(
            evidence_type="http_response_header",
            description="The HSTS header contains invalid policy syntax.",
            source=ANALYZER_NAME,
            details={
                "header_name": HSTS_HEADER,
                "observed_values": list(values),
                "validation_errors": errors,
                "response_url": str(metadata.response_url),
                "status_code": metadata.status_code,
            },
        )

        return [
            _hsts_finding(
                title="Invalid HSTS policy",
                description=(
                    "The observed Strict-Transport-Security policy "
                    "contains invalid or incomplete directives: "
                    + " ".join(errors)
                ),
                severity=Severity.MEDIUM,
                classification=FindingClassification.CONFIRMED_MISCONFIGURATION,
                confidence=95,
                evidence=evidence,
                remediation=(
                    "Correct the HSTS syntax and provide a valid decimal "
                    "max-age directive. Remove duplicate directives and "
                    "ensure flag directives have no assigned values."
                ),
            )
        ]

    max_age_value = directives["max-age"]

    # Avoid converting arbitrarily long attacker-controlled integers.
    # Values above the recommendation are equivalent for this analyzer.
    normalized_max_age = max_age_value.lstrip("0") or "0"

    if len(normalized_max_age) > len(str(HSTS_RECOMMENDED_MAX_AGE)):
        max_age = HSTS_RECOMMENDED_MAX_AGE
    else:
        max_age = int(normalized_max_age)

    if max_age == 0:
        return [
            _hsts_finding(
                title="HSTS explicitly disabled",
                description=(
                    "The HSTS policy sets max-age to zero, instructing "
                    "browsers to delete their previously stored HSTS policy "
                    "for this host."
                ),
                severity=Severity.MEDIUM,
                classification=FindingClassification.POTENTIAL_WEAKNESS,
                confidence=95,
                evidence=evidence,
                remediation=(
                    "If HSTS protection is intended, configure a positive "
                    "max-age appropriate for the deployment."
                ),
            )
        ]

    if max_age < HSTS_RECOMMENDED_MAX_AGE:
        return [
            _hsts_finding(
                title="Short HSTS policy duration",
                description=(
                    f"The HSTS policy has a max-age of {max_age} seconds, "
                    "which is shorter than the recommended one-year "
                    "baseline used by this analyzer."
                ),
                severity=Severity.LOW,
                classification=FindingClassification.POTENTIAL_WEAKNESS,
                confidence=90,
                evidence=evidence,
                remediation=(
                    "Consider increasing max-age to at least 31,536,000 "
                    "seconds after validating the HTTPS deployment."
                ),
            )
        ]

    return []
