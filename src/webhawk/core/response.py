from datetime import datetime
from time import perf_counter_ns

import httpx

from webhawk.core.models import HTTPHeader, HTTPResponseMetadata, utc_now


def build_response_metadata(
    *,
    requested_url: str | httpx.URL,
    response: httpx.Response,
    started_at_ns: int,
    received_at: datetime | None = None,
) -> HTTPResponseMetadata:
    """Extract sanitized metadata from an HTTPX response.

    started_at_ns must be captured with time.perf_counter_ns()
    immediately before the request begins.

    The response body is deliberately excluded.
    """

    if received_at is None:
        received_at = utc_now()

    if not isinstance(response, httpx.Response):
        raise TypeError("response must be an httpx.Response instance.")

    if (
        isinstance(started_at_ns, bool)
        or not isinstance(started_at_ns, int)
        or started_at_ns < 0
    ):
        raise ValueError("started_at_ns must be a non-negative integer.")

    elapsed_ns = perf_counter_ns() - started_at_ns

    if elapsed_ns < 0:
        raise ValueError("The monotonic clock returned an invalid elapsed time.")

    raw_http_version = response.extensions.get("http_version")

    if isinstance(raw_http_version, bytes):
        http_version = raw_http_version.decode("ascii", errors="strict")
    elif isinstance(raw_http_version, str):
        http_version = raw_http_version
    else:
        raise ValueError("The response does not contain a valid HTTP version.")

    supported_http_versions = {
        "HTTP/0.9",
        "HTTP/1.0",
        "HTTP/1.1",
        "HTTP/2",
        "HTTP/3",
    }

    if http_version not in supported_http_versions:
        raise ValueError("The response contains an unsupported HTTP version value.")

    extracted_headers: list[HTTPHeader] = []

    for raw_name, raw_value in response.headers.raw:
        name = raw_name.decode("ascii", errors="strict")
        value = raw_value.decode("latin-1", errors="strict")

        extracted_headers.append(
            HTTPHeader(
                name=name,
                value=value,
            )
        )

    return HTTPResponseMetadata(
        requested_url=str(requested_url),
        response_url=str(response.url),
        status_code=response.status_code,
        http_version=http_version,
        headers=tuple(extracted_headers),
        elapsed_ms=elapsed_ns / 1_000_000,
        received_at=received_at,
    )
