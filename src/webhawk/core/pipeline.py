import asyncio
import ssl
from collections.abc import Callable
from time import perf_counter_ns

import httpx
from pydantic import ValidationError

from webhawk.analyzers.runner import analyze_response
from webhawk.core.config import AppConfig, get_default_config
from webhawk.core.models import (
    ScanError,
    ScanErrorCode,
    ScanResult,
    ScanStatus,
    ScanTarget,
    sanitize_metadata_url,
    utc_now,
)
from webhawk.core.normalizer import (
    NormalizationError,
    normalize_url,
)
from webhawk.core.response import build_response_metadata
from webhawk.core.safety import (
    ResolutionError,
    TargetNotAuthorizedError,
    TargetPolicy,
    TargetSafetyError,
    UnsafeAddressError,
)
from webhawk.core.transport.client import (
    ResponseTooLargeError,
    WebHawkAsyncTransport,
)


class AssessmentInputError(ValueError):
    """A controlled error for invalid assessment input."""

    def __init__(self, code: ScanErrorCode) -> None:
        self.error = ScanError(code=code)
        super().__init__(self.error.message)


def _contains_ssl_error(exception: BaseException) -> bool:
    """Inspect chained exceptions without exposing their messages."""

    pending = [exception]
    visited = set()

    while pending:
        current = pending.pop()

        if id(current) in visited:
            continue

        visited.add(id(current))

        if isinstance(current, ssl.SSLError):
            return True

        cause = current.__cause__
        context = current.__context__

        if cause is not None:
            pending.append(cause)

        if context is not None:
            pending.append(context)

    return False


def _classify_exception(exception: Exception) -> ScanErrorCode:
    """Map internal exceptions to controlled public error categories."""

    if isinstance(exception, ResponseTooLargeError):
        return ScanErrorCode.RESPONSE_TOO_LARGE

    if isinstance(exception, httpx.TimeoutException):
        return ScanErrorCode.REQUEST_TIMEOUT

    if isinstance(exception, httpx.ConnectError):
        if _contains_ssl_error(exception):
            return ScanErrorCode.TLS_FAILED

        return ScanErrorCode.CONNECTION_FAILED

    if isinstance(
        exception,
        (
            httpx.NetworkError,
            httpx.RemoteProtocolError,
            httpx.ProxyError,
        ),
    ):
        return ScanErrorCode.CONNECTION_FAILED

    if isinstance(exception, httpx.InvalidURL):
        return ScanErrorCode.INVALID_TARGET

    return ScanErrorCode.UNEXPECTED_ERROR


def _failed_result(
    *,
    target: ScanTarget,
    started_at,
    code: ScanErrorCode,
    tool_version: str = "0.1.0",
) -> ScanResult:
    """Build a failed result without retaining partial findings."""

    return ScanResult(
        target=target,
        status=ScanStatus.FAILED,
        tool_version=tool_version,
        started_at=started_at,
        completed_at=utc_now(),
        findings=[],
        error=ScanError(code=code),
    )


def _validate_configuration(config: AppConfig) -> ScanErrorCode | None:
    """Reject unsupported or insecure pipeline configurations."""

    if not isinstance(config, AppConfig):
        return ScanErrorCode.CONFIGURATION_ERROR

    if not config.http.verify_tls:
        return ScanErrorCode.CONFIGURATION_ERROR

    if config.http.follow_redirects:
        return ScanErrorCode.CONFIGURATION_ERROR

    return None


async def assess_target(
    url: str,
    policy: TargetPolicy,
    config: AppConfig | None = None,
    *,
    resolver: Callable[[str, int], list[str]] | None = None,
    ssl_context: ssl.SSLContext | None = None,
) -> ScanResult:
    """
    Perform one passive HTTP assessment against an authorized target.

    The response body is streamed and discarded. Only sanitized response
    metadata and evidence-backed findings are retained.

    Redirect following, environment proxies and insecure TLS are prohibited.
    Cancellation propagates after HTTPX resource cleanup.
    """

    # Validate and normalize the supplied URL before creating a scan.
    try:
        normalized_url = normalize_url(url)

    except (NormalizationError, ValidationError, TypeError) as exc:
        raise AssessmentInputError(
            ScanErrorCode.INVALID_TARGET
        ) from exc

    stored_target = ScanTarget(url=sanitize_metadata_url(normalized_url))

    started_at = utc_now()

    if config is None:
        config = get_default_config()

    configuration_error = _validate_configuration(config)

    if configuration_error is not None:
        return _failed_result(
            target=stored_target,
            started_at=started_at,
            code=configuration_error,
            tool_version=getattr(config, "version", "0.1.0"),
        )

    if not isinstance(policy, TargetPolicy):
        return _failed_result(
            target=stored_target,
            started_at=started_at,
            code=ScanErrorCode.CONFIGURATION_ERROR,
            tool_version=config.version,
        )

    transport = None

    try:
        try:
            transport = WebHawkAsyncTransport(
                normalized_url,
                policy,
                ssl_context=ssl_context,
                max_response_bytes=config.http.max_response_bytes,
                resolver=resolver,
            )
        except TargetSafetyError:
            raise
        except (ValueError, TypeError):
            return _failed_result(
                target=stored_target,
                started_at=started_at,
                code=ScanErrorCode.CONFIGURATION_ERROR,
                tool_version=config.version,
            )

        timeout = httpx.Timeout(
            connect=config.http.connect_timeout,
            read=config.http.read_timeout,
            write=config.http.write_timeout,
            pool=config.http.pool_timeout,
        )

        async with httpx.AsyncClient(
            transport=transport,
            follow_redirects=False,
            trust_env=False,
            timeout=timeout,
            headers={
                "User-Agent": config.http.user_agent,
                "Accept-Encoding": "identity",
            },
        ) as client:

            started_at_ns = perf_counter_ns()

            async with client.stream(
                "GET",
                normalized_url,
            ) as response:

                # Consume the bounded response stream without retaining
                # or passing the response body to any analyzer.
                async for _chunk in response.aiter_raw():
                    pass

                metadata = build_response_metadata(
                    requested_url=normalized_url,
                    response=response,
                    started_at_ns=started_at_ns,
                )

                try:
                    findings = analyze_response(
                        metadata,
                        raw_headers=response.headers.raw,
                    )

                except asyncio.CancelledError:
                    raise

                except Exception:
                    return _failed_result(
                        target=stored_target,
                        started_at=started_at,
                        code=ScanErrorCode.ANALYSIS_FAILED,
                        tool_version=config.version,
                    )

        return ScanResult(
            target=stored_target,
            status=ScanStatus.COMPLETED,
            tool_version=config.version,
            started_at=started_at,
            completed_at=utc_now(),
            findings=findings,
            error=None,
        )

    except asyncio.CancelledError:
        raise

    except TargetNotAuthorizedError:
        return _failed_result(
            target=stored_target,
            started_at=started_at,
            code=ScanErrorCode.TARGET_NOT_AUTHORIZED,
            tool_version=config.version,
        )

    except UnsafeAddressError:
        return _failed_result(
            target=stored_target,
            started_at=started_at,
            code=ScanErrorCode.UNSAFE_ADDRESS,
            tool_version=config.version,
        )

    except ResolutionError:
        return _failed_result(
            target=stored_target,
            started_at=started_at,
            code=ScanErrorCode.DNS_RESOLUTION_FAILED,
            tool_version=config.version,
        )

    except TargetSafetyError:
        return _failed_result(
            target=stored_target,
            started_at=started_at,
            code=ScanErrorCode.CONFIGURATION_ERROR,
            tool_version=config.version,
        )


    except Exception as exc:
        current_task = asyncio.current_task()

        if current_task is not None and current_task.cancelling():
            raise asyncio.CancelledError from exc

        return _failed_result(
            target=stored_target,
            started_at=started_at,
            code=_classify_exception(exc),
            tool_version=config.version,
        )

    finally:
        if transport is not None:
            try:
                await transport.aclose()
            except asyncio.CancelledError:
                raise
            except Exception:
                current_task = asyncio.current_task()

                if current_task is None or current_task.cancelling() == 0:
                    raise
