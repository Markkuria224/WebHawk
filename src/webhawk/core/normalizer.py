from ipaddress import ip_address
from urllib.parse import urlsplit, urlunsplit


class NormalizationError(ValueError):
    """Base exception for URL normalization errors."""


class UnsupportedSchemeError(NormalizationError):
    """Raised when a URL uses an unsupported scheme."""


class EmbeddedCredentialsError(NormalizationError):
    """Raised when a URL contains embedded credentials."""


class InvalidHostnameError(NormalizationError):
    """Raised when a hostname is invalid."""


class MalformedPortError(NormalizationError):
    """Raised when a port is malformed or outside its valid range."""


def _normalize_hostname(hostname: str) -> str:
    if not hostname:
        raise InvalidHostnameError("URL must contain a hostname.")

    hostname = hostname.rstrip(".")

    if not hostname:
        raise InvalidHostnameError("Hostname cannot be empty.")

    try:
        address = ip_address(hostname)
        return address.compressed
    except ValueError:
        pass

    try:
        hostname = hostname.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise InvalidHostnameError("Hostname contains invalid characters.") from exc

    if len(hostname) > 253:
        raise InvalidHostnameError("Hostname is too long.")

    labels = hostname.split(".")

    for label in labels:
        if (
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
        ):
            raise InvalidHostnameError("Hostname contains an invalid label.")

        if not all(character.isalnum() or character == "-" for character in label):
            raise InvalidHostnameError("Hostname contains invalid characters.")

    return hostname


def normalize_url(value: str) -> str:
    """
    Validate and normalize an HTTP or HTTPS URL.

    This function performs syntactic validation only.
    It does not establish whether a target is authorized or safe to scan.
    """

    if not isinstance(value, str):
        raise NormalizationError("URL must be provided as a string.")

    value = value.strip()

    if not value:
        raise NormalizationError("URL cannot be empty.")

    if any(character.isspace() or ord(character) < 32 for character in value):
        raise NormalizationError("URL cannot contain whitespace or control characters.")

    if "\\" in value:
        raise NormalizationError("URL cannot contain backslashes.")

    try:
        parsed = urlsplit(value)
    except ValueError as exc:
        raise NormalizationError("URL structure is malformed.") from exc

    scheme = parsed.scheme.lower()

    if scheme not in {"http", "https"}:
        raise UnsupportedSchemeError("Only HTTP and HTTPS URLs are supported.")

    if not parsed.netloc:
        raise InvalidHostnameError("URL must contain a hostname.")

    if parsed.username is not None or parsed.password is not None:
        raise EmbeddedCredentialsError("URLs containing embedded credentials are not allowed.")

    try:
        hostname = parsed.hostname
    except ValueError as exc:
        raise InvalidHostnameError("Hostname is malformed.") from exc

    normalized_host = _normalize_hostname(hostname)

    try:
        port = parsed.port
    except ValueError as exc:
        raise MalformedPortError("Port must be a valid integer between 1 and 65535.") from exc

    if port is not None and not 1 <= port <= 65535:
        raise MalformedPortError("Port must be between 1 and 65535.")

    try:
        is_ipv6 = ip_address(normalized_host).version == 6
    except ValueError:
        is_ipv6 = False

    formatted_host = f"[{normalized_host}]" if is_ipv6 else normalized_host

    if port is not None and not (
        (scheme == "http" and port == 80)
        or (scheme == "https" and port == 443)
    ):
        netloc = f"{formatted_host}:{port}"
    else:
        netloc = formatted_host

    path = parsed.path or "/"

    return urlunsplit(
        (
            scheme,
            netloc,
            path,
            parsed.query,
            "",
        )
    )
