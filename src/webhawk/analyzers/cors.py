"""Passive and privacy-preserving HTTP CORS analysis."""

from urllib.parse import urlsplit

from webhawk.core.models import (
    Evidence,
    Finding,
    FindingClassification,
    HTTPResponseMetadata,
    Severity,
)
from webhawk.core.normalizer import NormalizationError, normalize_url


ANALYZER_NAME = "cors"

CORS_HEADER_NAMES = frozenset({
    "access-control-allow-origin",
    "access-control-allow-credentials",
    "access-control-allow-methods",
    "access-control-allow-headers",
    "access-control-expose-headers",
    "access-control-max-age",
    "vary",
})

ACAO_HEADER = "access-control-allow-origin"
ACAC_HEADER = "access-control-allow-credentials"
ACAM_HEADER = "access-control-allow-methods"
ACAH_HEADER = "access-control-allow-headers"


def collect_cors_header_values(
    metadata: HTTPResponseMetadata,
) -> dict[str, tuple[str, ...]]:
    """Collect CORS-related response headers.

    Header names are matched case-insensitively.
    Duplicate values and their original order are preserved.
    Original header values are not modified.
    """

    collected: dict[str, list[str]] = {}

    for header in metadata.headers:
        normalized_name = header.name.casefold()

        if normalized_name not in CORS_HEADER_NAMES:
            continue

        collected.setdefault(normalized_name, []).append(header.value)

    return {
        name: tuple(values)
        for name, values in collected.items()
    }


def normalize_header_value(value: str) -> str:
    """Remove HTTP optional whitespace surrounding a header value."""

    return value.strip(" \t")


def parse_cors_origin(value: str) -> str | None:
    """Validate and normalize a serialized CORS origin.

    Special values:
    - "*" represents the wildcard origin.
    - "null" represents an opaque origin.

    Network origins must use HTTP or HTTPS and contain no credentials,
    paths, queries, fragments, whitespace or control characters.

    Invalid values return None.
    """

    if not isinstance(value, str) or not value:
        return None

    if value in {"*", "null"}:
        return value

    if any(
        character.isspace() or ord(character) < 32
        for character in value
    ):
        return None

    if "\\" in value or "?" in value or "#" in value:
        return None

    try:
        parsed = urlsplit(value)

        if parsed.scheme.lower() not in {"http", "https"}:
            return None

        if not parsed.netloc:
            return None

        if parsed.path or parsed.query or parsed.fragment:
            return None

        if parsed.username is not None or parsed.password is not None:
            return None

        parsed.port

        if parsed.netloc.endswith(":"):
            return None

        normalized_url = normalize_url(value)

        if normalized_url.endswith("/"):
            normalized_url = normalized_url[:-1]

        return normalized_url

    except (ValueError, NormalizationError):
        return None


def _build_cors_finding(
    *,
    metadata: HTTPResponseMetadata,
    title: str,
    description: str,
    severity: Severity,
    classification: FindingClassification,
    confidence: int,
    header_names: tuple[str, ...],
    remediation: str,
    additional_details: dict | None = None,
) -> Finding:
    """Create a CORS finding with evidence from observed response headers."""

    headers = collect_cors_header_values(metadata)

    observed_headers = {
        name: list(headers[name])
        for name in header_names
        if name in headers
    }

    details = {
        "response_url": str(metadata.response_url),
        "status_code": metadata.status_code,
        "observed_headers": observed_headers,
    }

    if additional_details:
        details.update(additional_details)

    evidence = Evidence(
        evidence_type="http_response_headers",
        description=(
            "The finding is based on CORS-related headers observed "
            "in the supplied HTTP response metadata."
        ),
        source=ANALYZER_NAME,
        details=details,
    )

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


def analyze_cors(
    metadata: HTTPResponseMetadata,
    *,
    request_origin: str | None = None,
    request_method: str | None = None,
) -> list[Finding]:
    """Passively analyze CORS response headers.

    No additional network requests are performed.

    request_origin is optional caller-supplied request context.
    request_method is optional caller-supplied HTTP method context.

    A matching ACAO value is reported as a potential weakness,
    not proof of arbitrary-origin reflection.
    """

    headers = collect_cors_header_values(metadata)
    findings: list[Finding] = []

    acao_values = headers.get(ACAO_HEADER, ())
    acac_values = headers.get(ACAC_HEADER, ())

    credentials_enabled = any(
        normalize_header_value(value) == "true"
        for value in acac_values
    )

    if len(acao_values) > 1:
        findings.append(
            _build_cors_finding(
                metadata=metadata,
                title="Multiple Access-Control-Allow-Origin headers",
                description=(
                    "The response contains multiple "
                    "Access-Control-Allow-Origin header fields. "
                    "Multiple origin values make the CORS policy "
                    "ambiguous and do not form a valid single "
                    "serialized Access-Control-Allow-Origin value."
                ),
                severity=Severity.MEDIUM,
                classification=(
                    FindingClassification.CONFIRMED_MISCONFIGURATION
                ),
                confidence=95,
                header_names=(ACAO_HEADER,),
                remediation=(
                    "Configure the application or reverse proxy to emit "
                    "exactly one valid Access-Control-Allow-Origin value."
                ),
            )
        )

    elif len(acao_values) == 1:
        raw_origin = normalize_header_value(acao_values[0])
        parsed_origin = parse_cors_origin(raw_origin)

        if parsed_origin is None:
            findings.append(
                _build_cors_finding(
                    metadata=metadata,
                    title="Invalid CORS allowed-origin value",
                    description=(
                        "The Access-Control-Allow-Origin response header "
                        "contains a value that is not a valid serialized "
                        "CORS origin or supported special token."
                    ),
                    severity=Severity.LOW,
                    classification=(
                        FindingClassification.CONFIRMED_MISCONFIGURATION
                    ),
                    confidence=95,
                    header_names=(ACAO_HEADER,),
                    remediation=(
                        "Configure Access-Control-Allow-Origin with one "
                        "valid serialized origin, the wildcard token, "
                        "or the null token where explicitly intended."
                    ),
                )
            )

        elif parsed_origin == "*":
            if credentials_enabled:
                findings.append(
                    _build_cors_finding(
                        metadata=metadata,
                        title="Wildcard CORS origin with credentials enabled",
                        description=(
                            "The response combines "
                            "Access-Control-Allow-Origin: * with "
                            "Access-Control-Allow-Credentials: true. "
                            "Browsers reject credentialed CORS sharing "
                            "when the allowed origin is a wildcard. "
                            "This is a contradictory CORS configuration; "
                            "it does not establish credentialed data exposure."
                        ),
                        severity=Severity.LOW,
                        classification=(
                            FindingClassification.CONFIRMED_MISCONFIGURATION
                        ),
                        confidence=98,
                        header_names=(ACAO_HEADER, ACAC_HEADER),
                        remediation=(
                            "If credentialed cross-origin access is required, "
                            "return an explicitly validated allowed origin "
                            "instead of the wildcard. Otherwise, remove the "
                            "unnecessary credentials permission."
                        ),
                    )
                )
            else:
                findings.append(
                    _build_cors_finding(
                        metadata=metadata,
                        title="Wildcard CORS origin",
                        description=(
                            "The response allows requests from any origin "
                            "using Access-Control-Allow-Origin: *. "
                            "This is an informational configuration "
                            "observation and is not inherently vulnerable."
                        ),
                        severity=Severity.INFO,
                        classification=FindingClassification.OBSERVATION,
                        confidence=100,
                        header_names=(ACAO_HEADER,),
                        remediation=(
                            "Review whether public cross-origin access is "
                            "intended. Restrict allowed origins when the "
                            "resource requires a narrower access policy."
                        ),
                    )
                )

        elif parsed_origin == "null":
            findings.append(
                _build_cors_finding(
                    metadata=metadata,
                    title="CORS allows the null origin",
                    description=(
                        "The response explicitly allows the opaque "
                        "origin represented by Access-Control-Allow-Origin: "
                        "null. Sandboxed documents and other opaque-origin "
                        "contexts can serialize their origin as null. "
                        "Whether this creates risk depends on the "
                        "application's trust and data-access requirements."
                    ),
                    severity=Severity.MEDIUM,
                    classification=FindingClassification.POTENTIAL_WEAKNESS,
                    confidence=90,
                    header_names=(ACAO_HEADER,),
                    remediation=(
                        "Avoid allowing the null origin unless there is "
                        "a documented requirement. Prefer an explicit "
                        "allowlist of trusted origins."
                    ),
                )
            )

        elif request_origin is not None:
            normalized_request_origin = parse_cors_origin(request_origin)

            if (
                normalized_request_origin is not None
                and normalized_request_origin not in {"*", "null"}
                and parsed_origin == normalized_request_origin
            ):
                findings.append(
                    _build_cors_finding(
                        metadata=metadata,
                        title="Supplied request origin is allowed by CORS",
                        description=(
                            "The response's Access-Control-Allow-Origin "
                            "value matches the supplied request Origin. "
                            "This confirms that the observed response "
                            "allows that origin, but does not establish "
                            "arbitrary-origin reflection or an exploitable "
                            "cross-origin data exposure."
                        ),
                        severity=Severity.LOW,
                        classification=FindingClassification.POTENTIAL_WEAKNESS,
                        confidence=85,
                        header_names=(ACAO_HEADER,),
                        remediation=(
                            "Review whether the supplied origin belongs "
                            "to the intended trusted-origin allowlist and "
                            "whether the resource should be accessible "
                            "cross-origin."
                        ),
                        additional_details={
                            "supplied_request_origin": normalized_request_origin,
                        },
                    )
                )

    if credentials_enabled and len(acao_values) <= 1:
        if not (
            len(acao_values) == 1
            and parse_cors_origin(
                normalize_header_value(acao_values[0])
            ) == "*"
        ):
            findings.append(
                _build_cors_finding(
                    metadata=metadata,
                    title="CORS credentials permission enabled",
                    description=(
                        "The response includes "
                        "Access-Control-Allow-Credentials: true. "
                        "This permits credentialed CORS sharing only "
                        "when the other CORS requirements are satisfied. "
                        "The header alone does not establish a vulnerability."
                    ),
                    severity=Severity.INFO,
                    classification=FindingClassification.OBSERVATION,
                    confidence=100,
                    header_names=(ACAC_HEADER, ACAO_HEADER),
                    remediation=(
                        "Ensure credentialed cross-origin access is "
                        "necessary and restrict allowed origins to "
                        "explicitly trusted applications."
                    ),
                )
            )

    if request_method is not None and request_method.casefold() == "options":
        preflight_headers = tuple(
            name
            for name in (ACAM_HEADER, ACAH_HEADER)
            if name in headers
        )

        if preflight_headers:
            findings.append(
                _build_cors_finding(
                    metadata=metadata,
                    title="CORS preflight permissions observed",
                    description=(
                        "The supplied OPTIONS response contains "
                        "Access-Control-Allow-Methods and/or "
                        "Access-Control-Allow-Headers. These values "
                        "describe advertised preflight permissions. "
                        "Their presence alone does not establish "
                        "a security weakness."
                    ),
                    severity=Severity.INFO,
                    classification=FindingClassification.OBSERVATION,
                    confidence=100,
                    header_names=preflight_headers,
                    remediation=(
                        "Review advertised methods and headers against "
                        "the application's intended cross-origin API "
                        "requirements. Avoid granting unnecessary permissions."
                    ),
                )
            )

    return findings
