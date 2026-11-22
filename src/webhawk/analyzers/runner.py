from collections.abc import Sequence

from webhawk.analyzers.cookies import analyze_cookies
from webhawk.analyzers.cors import analyze_cors
from webhawk.analyzers.security_headers import analyze_hsts
from webhawk.core.models import Finding, HTTPResponseMetadata


def analyze_response(
    metadata: HTTPResponseMetadata,
    *,
    raw_headers: Sequence[tuple[bytes, bytes]],
    request_origin: str | None = None,
    request_method: str | None = None,
) -> list[Finding]:
    """Run all response analyzers and aggregate their findings.

    Analyzers execute sequentially in a deterministic order:
    security headers, cookies, then CORS.

    Raw response headers are supplied only to the cookie analyzer because
    sensitive cookie values are redacted in HTTPResponseMetadata.

    Analyzer exceptions intentionally propagate. Returning partial findings
    after an analyzer failure could make an incomplete assessment appear
    successful.
    """
    findings: list[Finding] = []

    findings.extend(analyze_hsts(metadata))

    findings.extend(
        analyze_cookies(
            response_url=str(metadata.response_url),
            raw_headers=raw_headers,
        )
    )

    findings.extend(
        analyze_cors(
            metadata,
            request_origin=request_origin,
            request_method=request_method,
        )
    )

    return findings
