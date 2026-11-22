"""Passive and privacy-preserving HTTP cookie analysis."""

from collections.abc import Sequence
from dataclasses import dataclass
from email.utils import parsedate_to_datetime
import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit

from webhawk.core.normalizer import normalize_hostname
from webhawk.core.models import (
    Evidence,
    Finding,
    FindingClassification,
    Severity,
)


ANALYZER_NAME = "cookies"
SET_COOKIE_HEADER = "set-cookie"

MAX_COOKIE_HEADER_LENGTH = 16_384
MAX_COOKIE_NAME_LENGTH = 256

_COOKIE_NAME_PATTERN = re.compile(
    r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$"
)

_DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)


@dataclass(frozen=True, slots=True)
class ParsedCookie:
    """Sanitized cookie representation without its cookie value."""

    name: str
    secure: bool
    httponly: bool
    samesite: str | None
    domain: str | None
    domain_attribute_present: bool
    path: str | None
    expires_present: bool
    max_age: int | None
    duplicate_attributes: tuple[str, ...]
    invalid_attributes: tuple[str, ...]
    unknown_attributes: tuple[str, ...]


def _valid_cookie_name(name: str) -> bool:
    return (
        bool(name)
        and len(name) <= MAX_COOKIE_NAME_LENGTH
        and _COOKIE_NAME_PATTERN.fullmatch(name) is not None
    )


def _valid_domain_attribute(value: str) -> str | None:
    """Validate and normalize a cookie Domain attribute."""

    if not value or not value.isascii():
        return None

    normalized = value.casefold()

    if normalized.startswith("."):
        normalized = normalized[1:]

        if normalized.startswith("."):
            return None

    if not normalized or len(normalized) > 253:
        return None

    if _DOMAIN_PATTERN.fullmatch(normalized) is None:
        return None

    return normalized


def _valid_expires_attribute(value: str) -> bool:
    """Check whether an Expires value represents a valid date."""

    if not value:
        return False

    try:
        parsed = parsedate_to_datetime(value)
    except (TypeError, ValueError, OverflowError):
        return False

    return parsed is not None and parsed.tzinfo is not None


def _parse_max_age(value: str) -> tuple[int | None, bool]:
    """Parse Max-Age safely without converting unbounded integers."""

    if not value or re.fullmatch(r"-?[0-9]+", value) is None:
        return None, False

    is_negative = value.startswith("-")
    normalized = value.lstrip("-").lstrip("0") or "0"

    if len(normalized) > 18:
        return None, False

    normalized_value = (
        f"-{normalized}" if is_negative else normalized
    )

    return int(normalized_value), True


def _extract_set_cookie_headers(
    raw_headers: Sequence[tuple[bytes, bytes]],
) -> tuple[bytes, ...]:
    """Extract individual Set-Cookie headers without combining duplicates."""

    if not isinstance(raw_headers, Sequence):
        raise TypeError("raw_headers must be a sequence.")

    extracted: list[bytes] = []

    for item in raw_headers:
        if (
            not isinstance(item, (tuple, list))
            or len(item) != 2
            or not isinstance(item[0], bytes)
            or not isinstance(item[1], bytes)
        ):
            continue

        try:
            header_name = item[0].decode("ascii").casefold()
        except UnicodeDecodeError:
            continue

        if header_name == SET_COOKIE_HEADER:
            extracted.append(item[1])

    return tuple(extracted)


def _parse_set_cookie(raw_value: bytes) -> ParsedCookie | None:
    """Parse one Set-Cookie header without retaining its cookie value."""

    if not isinstance(raw_value, bytes):
        return None

    if not raw_value or len(raw_value) > MAX_COOKIE_HEADER_LENGTH:
        return None

    header_value = raw_value.decode("latin-1")

    if any(
        (ord(character) < 32 and character != "\t")
        or ord(character) == 127
        for character in header_value
    ):
        return None

    segments = header_value.split(";")
    cookie_pair = segments[0].strip()

    if "=" not in cookie_pair:
        return None

    cookie_name, _cookie_value = cookie_pair.split("=", 1)

    if not _valid_cookie_name(cookie_name):
        return None

    known_attributes = {
        "secure",
        "httponly",
        "samesite",
        "domain",
        "path",
        "expires",
        "max-age",
    }

    seen_attributes: set[str] = set()
    duplicate_attributes: set[str] = set()
    invalid_attributes: set[str] = set()
    unknown_attributes: set[str] = set()

    # Only recognized attributes have their values temporarily retained.
    attributes: dict[str, str | None] = {}

    for segment in segments[1:]:
        segment = segment.strip()

        if not segment:
            continue

        attribute_name, separator, attribute_value = segment.partition("=")

        attribute_name = attribute_name.strip().casefold()
        attribute_value = attribute_value.strip() if separator else None

        if (
            not attribute_name
            or _COOKIE_NAME_PATTERN.fullmatch(attribute_name) is None
        ):
            continue

        if attribute_name in seen_attributes:
            duplicate_attributes.add(attribute_name)

        seen_attributes.add(attribute_name)

        if attribute_name not in known_attributes:
            unknown_attributes.add(attribute_name)
            continue

        # Preserve the last occurrence of recognized attributes.
        # Duplicate names remain recorded for security analysis.
        attributes[attribute_name] = attribute_value

    # Secure and HttpOnly are presence-based flags.
    # RFC 6265 requires their supplied values to be ignored.
    secure = "secure" in attributes
    httponly = "httponly" in attributes

    # SameSite validation.
    samesite = None

    if "samesite" in attributes:
        raw_samesite = attributes["samesite"]

        if raw_samesite is not None:
            normalized_samesite = raw_samesite.casefold()

            if normalized_samesite in {"strict", "lax", "none"}:
                samesite = normalized_samesite
            else:
                invalid_attributes.add("samesite")
        else:
            invalid_attributes.add("samesite")

    # Preserve attribute presence separately from its validity.
    # __Host- cookies prohibit Domain even when its value is invalid.
    domain_attribute_present = "domain" in attributes

    # Domain validation.
    domain = None

    if domain_attribute_present:
        raw_domain = attributes["domain"]

        if raw_domain is not None:
            domain = _valid_domain_attribute(raw_domain)

        if domain is None:
            invalid_attributes.add("domain")

    # Retain a valid cookie Path because it defines cookie scope.
    # Cookie values are never retained.
    path = None

    if "path" in attributes:
        raw_path = attributes["path"]

        if raw_path is None or not raw_path.startswith("/"):
            invalid_attributes.add("path")
        else:
            path = raw_path

    # Expires is validated but its raw value is never retained.
    expires_present = "expires" in attributes

    if expires_present:
        raw_expires = attributes["expires"]

        if (
            raw_expires is None
            or not _valid_expires_attribute(raw_expires)
        ):
            invalid_attributes.add("expires")

    # Max-Age is converted only after its length has been bounded.
    max_age = None

    if "max-age" in attributes:
        raw_max_age = attributes["max-age"]

        if raw_max_age is not None:
            max_age, valid_max_age = _parse_max_age(raw_max_age)

            if not valid_max_age:
                invalid_attributes.add("max-age")
        else:
            invalid_attributes.add("max-age")

    return ParsedCookie(
        name=cookie_name,
        secure=secure,
        httponly=httponly,
        samesite=samesite,
        domain=domain,
        domain_attribute_present=domain_attribute_present,
        path=path,
        expires_present=expires_present,
        max_age=max_age,
        duplicate_attributes=tuple(sorted(duplicate_attributes)),
        invalid_attributes=tuple(sorted(invalid_attributes)),
        unknown_attributes=tuple(sorted(unknown_attributes)),
    )





def _default_cookie_path(request_path: str) -> str:
    """Calculate the RFC 6265 default cookie path."""

    if not request_path or not request_path.startswith("/"):
        return "/"

    if request_path.count("/") <= 1:
        return "/"

    return request_path.rsplit("/", 1)[0]



def _domain_matches_host(hostname: str, domain: str) -> bool:
    """Check whether a cookie Domain matches a response hostname."""

    normalized_host = hostname.casefold().rstrip(".")
    normalized_domain = domain.casefold().rstrip(".")

    if normalized_host == normalized_domain:
        return True

    # IP literals must not use DNS-style suffix matching.
    try:
        ipaddress.ip_address(normalized_host)
        host_is_ip = True
    except ValueError:
        host_is_ip = False

    try:
        ipaddress.ip_address(normalized_domain)
        domain_is_ip = True
    except ValueError:
        domain_is_ip = False

    if host_is_ip or domain_is_ip:
        return False

    return normalized_host.endswith("." + normalized_domain)


def _is_secure_cookie_origin(*, scheme: str, hostname: str) -> bool:
    """Return whether a cookie response origin is considered secure."""

    if scheme.casefold() == "https":
        return True

    normalized_host = hostname.casefold().rstrip(".")

    if normalized_host == "localhost":
        return True

    try:
        return ipaddress.ip_address(normalized_host).is_loopback
    except ValueError:
        return False


def _build_cookie_finding(
    *,
    cookie: ParsedCookie,
    response_url: str,
    title: str,
    description: str,
    severity: Severity,
    classification: FindingClassification,
    confidence: int,
    remediation: str,
    attributes: dict[str, object],
) -> Finding:
    """Create a finding containing sanitized cookie evidence."""

    evidence = Evidence(
        evidence_type="http_cookie",
        description=(
            f"Cookie '{cookie.name}' was inspected in an HTTP response."
        ),
        source=response_url,
        details={
            "cookie_name": cookie.name,
            "attributes": attributes,
        },
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


def analyze_cookies(
    *,
    response_url: str,
    raw_headers: Sequence[tuple[bytes, bytes]],
) -> list[Finding]:
    """Analyze Set-Cookie response headers without retaining cookie values."""

    if not isinstance(response_url, str):
        raise TypeError("response_url must be a string.")

    try:
        parsed_url = urlsplit(response_url)
        scheme = parsed_url.scheme.casefold()
        hostname = parsed_url.hostname
        port = parsed_url.port
    except ValueError as exc:
        raise ValueError("response_url is invalid.") from exc

    if scheme not in {"http", "https"} or not hostname:
        raise ValueError("response_url must be an HTTP or HTTPS URL.")

    try:
        hostname = normalize_hostname(hostname)
    except ValueError as exc:
        raise ValueError("response_url is invalid.") from exc

    safe_hostname = hostname

    if ":" in safe_hostname:
        safe_hostname = f"[{safe_hostname}]"

    safe_netloc = safe_hostname

    if port is not None:
        safe_netloc = f"{safe_netloc}:{port}"

    response_url = urlunsplit(
        (scheme, safe_netloc, parsed_url.path, "", "")
    )

    is_https = scheme == "https"
    is_secure_origin = _is_secure_cookie_origin(
        scheme=scheme,
        hostname=hostname,
    )

    findings: list[Finding] = []

    raw_cookie_headers = _extract_set_cookie_headers(raw_headers)

    parsed_cookies = [
        cookie
        for raw_cookie_header in raw_cookie_headers
        if (cookie := _parse_set_cookie(raw_cookie_header)) is not None
    ]

    # Detect repeated cookie names with different effective scopes.
    # Cookie values are discarded by the parser and never enter this logic.
    cookies_by_name: dict[str, list[ParsedCookie]] = {}

    for cookie in parsed_cookies:
        cookies_by_name.setdefault(cookie.name, []).append(cookie)

    for cookie_name, same_name_cookies in cookies_by_name.items():
        if len(same_name_cookies) < 2:
            continue

        scopes = []
        scope_keys = set()

        for cookie in same_name_cookies:
            invalid_attributes = set(cookie.invalid_attributes)

            effective_path = (
                cookie.path
                if cookie.path is not None
                else _default_cookie_path(parsed_url.path)
            )

            domain_attribute_valid = "domain" not in invalid_attributes

            scope_key = (
                cookie.domain,
                effective_path,
                domain_attribute_valid,
            )

            scope_keys.add(scope_key)

            scopes.append({
                "domain": cookie.domain,
                "host_only": cookie.domain is None and domain_attribute_valid,
                "domain_attribute_valid": domain_attribute_valid,
                "path": effective_path,
            })

        if len(scope_keys) > 1:
            findings.append(
                _build_cookie_finding(
                    cookie=same_name_cookies[0],
                    response_url=response_url,
                    title="Duplicate cookie names with different scopes",
                    description=(
                        f"Cookie '{cookie_name}' appears more than once "
                        "with different effective domain or path scopes. "
                        "This may cause application or browser behaviour "
                        "to depend on cookie selection order."
                    ),
                    severity=Severity.INFO,
                    classification=FindingClassification.OBSERVATION,
                    confidence=100,
                    remediation=(
                        "Review cookies sharing this name and use distinct "
                        "names or consistent scopes where appropriate."
                    ),
                    attributes={
                        "scopes": scopes,
                    },
                )
            )

    for cookie in parsed_cookies:
        invalid = set(cookie.invalid_attributes)

        # Cookie prefix requirements are case-sensitive.
        # Report all violations together to avoid duplicate findings.
        prefix_violations = []

        if cookie.name.startswith("__Secure-"):
            if not cookie.secure:
                prefix_violations.append("secure_attribute_required")

            if not is_secure_origin:
                prefix_violations.append("secure_origin_required")

        elif cookie.name.startswith("__Host-"):
            if not cookie.secure:
                prefix_violations.append("secure_attribute_required")

            if not is_secure_origin:
                prefix_violations.append("secure_origin_required")

            if cookie.path != "/":
                prefix_violations.append("path_must_be_root")

            if cookie.domain_attribute_present:
                prefix_violations.append("domain_attribute_prohibited")

        if prefix_violations:
            findings.append(
                _build_cookie_finding(
                    cookie=cookie,
                    response_url=response_url,
                    title="Cookie prefix requirements violated",
                    description=(
                        f"Cookie '{cookie.name}' uses a security-sensitive "
                        "name prefix without satisfying all associated "
                        "cookie attribute and origin requirements."
                    ),
                    severity=Severity.MEDIUM,
                    classification=(
                        FindingClassification.CONFIRMED_MISCONFIGURATION
                    ),
                    confidence=98,
                    remediation=(
                        "Correct the cookie attributes and serve the cookie "
                        "from a secure origin. __Secure- cookies require "
                        "Secure. __Host- cookies additionally require "
                        "Path=/ and prohibit the Domain attribute."
                    ),
                    attributes={
                        "prefix": (
                            "__Secure-"
                            if cookie.name.startswith("__Secure-")
                            else "__Host-"
                        ),
                        "violations": prefix_violations,
                        "secure": cookie.secure,
                        "path": cookie.path,
                        "domain_attribute_present": (
                            cookie.domain_attribute_present
                        ),
                        "secure_origin": is_secure_origin,
                    },
                )
            )

        if (
            cookie.secure
            and not is_secure_origin
            and not cookie.name.startswith(("__Secure-", "__Host-"))
        ):
            findings.append(
                _build_cookie_finding(
                    cookie=cookie,
                    response_url=response_url,
                    title="Secure cookie received from insecure origin",
                    description=(
                        f"Cookie '{cookie.name}' includes the Secure "
                        "attribute but was received over an origin that "
                        "is not considered secure. The Secure attribute "
                        "does not protect the response during HTTP "
                        "transmission, and clients may reject the cookie."
                    ),
                    severity=Severity.LOW,
                    classification=(
                        FindingClassification.POTENTIAL_WEAKNESS
                    ),
                    confidence=90,
                    remediation=(
                        "Serve the response over HTTPS and ensure cookies "
                        "requiring secure transport are issued from a "
                        "secure origin."
                    ),
                    attributes={
                        "secure": True,
                        "origin_scheme": scheme,
                        "secure_origin": False,
                    },
                )
            )

        if is_https and not cookie.secure:
            findings.append(
                _build_cookie_finding(
                    cookie=cookie,
                    response_url=response_url,
                    title="Cookie missing Secure attribute",
                    description=(
                        f"Cookie '{cookie.name}' was set without a valid "
                        "Secure attribute in an HTTPS response. This may "
                        "allow the cookie to be transmitted over insecure "
                        "connections."
                    ),
                    severity=Severity.LOW,
                    classification=(
                        FindingClassification.POTENTIAL_WEAKNESS
                    ),
                    confidence=95,
                    remediation=(
                        "Set the Secure attribute on cookies that should "
                        "only be transmitted over HTTPS."
                    ),
                    attributes={
                        "secure": False,
                        "invalid_attributes": sorted(invalid),
                    },
                )
            )

        if not cookie.httponly:
            findings.append(
                _build_cookie_finding(
                    cookie=cookie,
                    response_url=response_url,
                    title="Cookie missing HttpOnly attribute",
                    description=(
                        f"Cookie '{cookie.name}' does not have a valid "
                        "HttpOnly attribute. Client-side JavaScript may "
                        "therefore be able to access it."
                    ),
                    severity=Severity.LOW,
                    classification=(
                        FindingClassification.POTENTIAL_WEAKNESS
                    ),
                    confidence=90,
                    remediation=(
                        "Use HttpOnly for cookies that do not need to be "
                        "accessed by client-side JavaScript."
                    ),
                    attributes={
                        "httponly": False,
                        "invalid_attributes": sorted(invalid),
                    },
                )
            )

        has_samesite = (
            cookie.samesite is not None
            or "samesite" in invalid
        )

        if not has_samesite:
            findings.append(
                _build_cookie_finding(
                    cookie=cookie,
                    response_url=response_url,
                    title="Cookie missing SameSite attribute",
                    description=(
                        f"Cookie '{cookie.name}' does not explicitly "
                        "declare a SameSite policy. Cross-site cookie "
                        "handling may therefore depend on browser defaults."
                    ),
                    severity=Severity.LOW,
                    classification=(
                        FindingClassification.POTENTIAL_WEAKNESS
                    ),
                    confidence=90,
                    remediation=(
                        "Choose an appropriate SameSite policy, such as "
                        "Lax or Strict, based on the application's "
                        "cross-site requirements."
                    ),
                    attributes={"samesite": None},
                )
            )

        if "samesite" in invalid:
            findings.append(
                _build_cookie_finding(
                    cookie=cookie,
                    response_url=response_url,
                    title="Invalid SameSite attribute",
                    description=(
                        f"Cookie '{cookie.name}' contains an invalid "
                        "SameSite attribute value."
                    ),
                    severity=Severity.LOW,
                    classification=(
                        FindingClassification.POTENTIAL_WEAKNESS
                    ),
                    confidence=95,
                    remediation=(
                        "Use a valid SameSite value: Strict, Lax, or None."
                    ),
                    attributes={
                        "samesite": "invalid",
                    },
                )
            )

        if cookie.samesite == "none" and not cookie.secure:
            findings.append(
                _build_cookie_finding(
                    cookie=cookie,
                    response_url=response_url,
                    title="SameSite=None without Secure",
                    description=(
                        f"Cookie '{cookie.name}' declares SameSite=None "
                        "without a valid Secure attribute. Modern browsers "
                        "require Secure for this configuration."
                    ),
                    severity=Severity.HIGH,
                    classification=(
                        FindingClassification.CONFIRMED_MISCONFIGURATION
                    ),
                    confidence=98,
                    remediation=(
                        "Add the Secure attribute when using SameSite=None "
                        "and serve the cookie over HTTPS."
                    ),
                    attributes={
                        "samesite": "none",
                        "secure": False,
                    },
                )
            )

        if cookie.domain is not None and not _domain_matches_host(
            hostname,
            cookie.domain,
        ):
            findings.append(
                _build_cookie_finding(
                    cookie=cookie,
                    response_url=response_url,
                    title="Cookie Domain incompatible with response host",
                    description=(
                        f"Cookie '{cookie.name}' specifies a Domain "
                        "attribute that does not match the response "
                        "hostname."
                    ),
                    severity=Severity.MEDIUM,
                    classification=(
                        FindingClassification.CONFIRMED_MISCONFIGURATION
                    ),
                    confidence=98,
                    remediation=(
                        "Configure the cookie Domain attribute to match "
                        "the response hostname or one of its parent "
                        "domains."
                    ),
                    attributes={
                        "domain": cookie.domain,
                        "response_hostname": hostname,
                    },
                )
            )

        reportable_invalid_attributes = sorted(
            set(cookie.invalid_attributes) - {"samesite"}
        )

        if reportable_invalid_attributes:
            findings.append(
                _build_cookie_finding(
                    cookie=cookie,
                    response_url=response_url,
                    title="Invalid cookie attributes",
                    description=(
                        f"Cookie '{cookie.name}' contains recognized "
                        "attributes with invalid syntax or values."
                    ),
                    severity=Severity.INFO,
                    classification=FindingClassification.OBSERVATION,
                    confidence=100,
                    remediation=(
                        "Review and correct the reported cookie attributes "
                        "according to the applicable cookie specification."
                    ),
                    attributes={
                        "invalid_attributes": reportable_invalid_attributes,
                    },
                )
            )

        if cookie.duplicate_attributes:
            findings.append(
                _build_cookie_finding(
                    cookie=cookie,
                    response_url=response_url,
                    title="Duplicate cookie attributes",
                    description=(
                        f"Cookie '{cookie.name}' contains repeated "
                        "attributes. Different cookie parsers may handle "
                        "conflicting values differently."
                    ),
                    severity=Severity.MEDIUM,
                    classification=(
                        FindingClassification.POTENTIAL_WEAKNESS
                    ),
                    confidence=90,
                    remediation=(
                        "Remove duplicate attributes and define each "
                        "cookie attribute once."
                    ),
                    attributes={
                        "duplicate_attributes": list(
                            cookie.duplicate_attributes
                        ),
                    },
                )
            )

        if cookie.unknown_attributes:
            findings.append(
                _build_cookie_finding(
                    cookie=cookie,
                    response_url=response_url,
                    title="Unrecognized cookie attributes",
                    description=(
                        f"Cookie '{cookie.name}' contains attributes "
                        "not interpreted by the current analyzer."
                    ),
                    severity=Severity.INFO,
                    classification=FindingClassification.OBSERVATION,
                    confidence=100,
                    remediation=(
                        "Review the attributes against the application's "
                        "cookie requirements and relevant browser support."
                    ),
                    attributes={
                        "unknown_attributes": list(
                            cookie.unknown_attributes
                        ),
                    },
                )
            )

    return findings
