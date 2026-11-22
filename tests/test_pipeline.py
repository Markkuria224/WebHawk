import asyncio

import pytest

from webhawk.core.config import AppConfig, HttpConfig
from webhawk.core.models import ScanErrorCode, ScanStatus
from webhawk.core.pipeline import AssessmentInputError, assess_target
from webhawk.core.safety import TargetPolicy


def run(coroutine):
    return asyncio.run(coroutine)


def valid_policy():
    return TargetPolicy(
        authorized_hosts=frozenset({"example.com"}),
    )


def fail_if_transport_is_created(*args, **kwargs):
    raise AssertionError(
        "Transport must not be constructed for rejected input."
    )


@pytest.mark.parametrize(
    "url",
    [
        "",
        "ftp://example.com",
        "https://user:password@example.com/",
        "https://example.com:invalid/",
        "not-a-valid-url",
    ],
)
def test_invalid_urls_raise_controlled_input_error(
    monkeypatch,
    url,
):
    import webhawk.core.pipeline as pipeline

    monkeypatch.setattr(
        pipeline,
        "WebHawkAsyncTransport",
        fail_if_transport_is_created,
    )

    with pytest.raises(AssessmentInputError) as exc_info:
        run(
            assess_target(
                url,
                valid_policy(),
            )
        )

    assert exc_info.value.error.code == ScanErrorCode.INVALID_TARGET


def test_tls_verification_cannot_be_disabled(monkeypatch):
    import webhawk.core.pipeline as pipeline

    monkeypatch.setattr(
        pipeline,
        "WebHawkAsyncTransport",
        fail_if_transport_is_created,
    )

    config = AppConfig(
        http=HttpConfig(verify_tls=False),
    )

    result = run(
        assess_target(
            "https://example.com/",
            valid_policy(),
            config,
        )
    )

    assert result.status == ScanStatus.FAILED
    assert result.error is not None
    assert result.error.code == ScanErrorCode.CONFIGURATION_ERROR
    assert result.findings == []


def test_redirect_following_cannot_be_enabled(monkeypatch):
    import webhawk.core.pipeline as pipeline

    monkeypatch.setattr(
        pipeline,
        "WebHawkAsyncTransport",
        fail_if_transport_is_created,
    )

    config = AppConfig(
        http=HttpConfig(follow_redirects=True),
    )

    result = run(
        assess_target(
            "https://example.com/",
            valid_policy(),
            config,
        )
    )

    assert result.status == ScanStatus.FAILED
    assert result.error is not None
    assert result.error.code == ScanErrorCode.CONFIGURATION_ERROR
    assert result.findings == []


def test_invalid_configuration_object_returns_controlled_failure(
    monkeypatch,
):
    import webhawk.core.pipeline as pipeline

    monkeypatch.setattr(
        pipeline,
        "WebHawkAsyncTransport",
        fail_if_transport_is_created,
    )

    result = run(
        assess_target(
            "https://example.com/",
            valid_policy(),
            config=object(),
        )
    )

    assert result.status == ScanStatus.FAILED
    assert result.error is not None
    assert result.error.code == ScanErrorCode.CONFIGURATION_ERROR


def test_invalid_target_policy_returns_controlled_failure(
    monkeypatch,
):
    import webhawk.core.pipeline as pipeline

    monkeypatch.setattr(
        pipeline,
        "WebHawkAsyncTransport",
        fail_if_transport_is_created,
    )

    result = run(
        assess_target(
            "https://example.com/",
            policy=None,
        )
    )

    assert result.status == ScanStatus.FAILED
    assert result.error is not None
    assert result.error.code == ScanErrorCode.CONFIGURATION_ERROR
    assert result.findings == []


def test_unauthorized_hostname_returns_controlled_failure():
    resolver_called = False

    def resolver(hostname, port):
        nonlocal resolver_called
        resolver_called = True
        return ["93.184.216.34"]

    result = run(
        assess_target(
            "https://unauthorized.example/",
            TargetPolicy(),
            resolver=resolver,
        )
    )

    assert result.status == ScanStatus.FAILED
    assert result.error is not None
    assert result.error.code == ScanErrorCode.TARGET_NOT_AUTHORIZED
    assert result.findings == []
    assert resolver_called is False


def test_unsafe_resolved_address_returns_controlled_failure():
    resolver_called = False

    def resolver(hostname, port):
        nonlocal resolver_called
        resolver_called = True
        return ["192.168.1.10"]

    policy = TargetPolicy(
        authorized_hosts=frozenset({"example.com"}),
    )

    result = run(
        assess_target(
            "https://example.com/",
            policy,
            resolver=resolver,
        )
    )

    assert result.status == ScanStatus.FAILED
    assert result.error is not None
    assert result.error.code == ScanErrorCode.UNSAFE_ADDRESS
    assert result.findings == []
    assert resolver_called is True


def test_dns_resolution_failure_returns_controlled_failure():
    def failing_resolver(hostname, port):
        raise OSError("Simulated DNS failure")

    policy = TargetPolicy(
        authorized_hosts=frozenset({"example.com"}),
    )

    result = run(
        assess_target(
            "https://example.com/",
            policy,
            resolver=failing_resolver,
        )
    )

    assert result.status == ScanStatus.FAILED
    assert result.error is not None
    assert result.error.code == ScanErrorCode.DNS_RESOLUTION_FAILED
    assert result.findings == []


def test_empty_dns_result_returns_controlled_failure():
    def empty_resolver(hostname, port):
        return []

    policy = TargetPolicy(
        authorized_hosts=frozenset({"example.com"}),
    )

    result = run(
        assess_target(
            "https://example.com/",
            policy,
            resolver=empty_resolver,
        )
    )

    assert result.status == ScanStatus.FAILED
    assert result.error is not None
    assert result.error.code == ScanErrorCode.DNS_RESOLUTION_FAILED
    assert result.findings == []


async def run_local_http_assessment(
    monkeypatch,
    *,
    status_code=200,
    reason="OK",
    response_headers=None,
    body=b"WebHawk local integration response",
    target_path="/",
):
    import webhawk.core.pipeline as pipeline

    captured_metadata = []
    captured_requests = []

    def capture_analysis(metadata, *, raw_headers, **kwargs):
        captured_metadata.append(metadata)
        return []

    monkeypatch.setattr(
        pipeline,
        "analyze_response",
        capture_analysis,
    )

    async def handle_client(reader, writer):
        try:
            request_line = await reader.readline()
            captured_requests.append(request_line.decode().strip())

            await reader.readuntil(b"\r\n\r\n")

            headers = [
                (b"Content-Length", str(len(body)).encode()),
                (b"Connection", b"close"),
            ]

            if response_headers:
                headers.extend(response_headers)

            response = bytearray(
                f"HTTP/1.1 {status_code} {reason}\r\n".encode()
            )

            for name, value in headers:
                response.extend(name + b": " + value + b"\r\n")

            response.extend(b"\r\n")
            response.extend(body)

            writer.write(bytes(response))
            await writer.drain()

        except (ConnectionError, asyncio.IncompleteReadError):
            pass

        finally:
            writer.close()

            try:
                await writer.wait_closed()
            except ConnectionError:
                pass

    server = await asyncio.start_server(
        handle_client,
        host="127.0.0.1",
        port=0,
    )

    port = server.sockets[0].getsockname()[1]

    target_url = f"http://webhawk.test:{port}{target_path}"

    policy = TargetPolicy(
        authorized_hosts=frozenset({"webhawk.test"}),
        authorized_networks=("127.0.0.0/8",),
        allow_loopback=True,
    )

    try:
        result = await pipeline.assess_target(
            target_url,
            policy,
            resolver=lambda hostname, port: ["127.0.0.1"],
        )

        return result, captured_requests, captured_metadata

    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.parametrize(
    ("status_code", "reason"),
    [
        (200, "OK"),
        (404, "Not Found"),
        (500, "Internal Server Error"),
    ],
)
def test_local_http_status_responses_complete_assessment(
    monkeypatch,
    status_code,
    reason,
):
    result, requests, metadata = run(
        run_local_http_assessment(
            monkeypatch,
            status_code=status_code,
            reason=reason,
        )
    )

    assert result.status == ScanStatus.COMPLETED
    assert result.error is None
    assert result.findings == []

    assert len(requests) == 1
    assert len(metadata) == 1
    assert metadata[0].status_code == status_code


def test_local_http_redirect_is_not_followed(monkeypatch):
    result, requests, metadata = run(
        run_local_http_assessment(
            monkeypatch,
            status_code=302,
            reason="Found",
            response_headers=[
                (b"Location", b"/redirect-destination"),
            ],
        )
    )

    assert result.status == ScanStatus.COMPLETED
    assert result.error is None

    assert len(requests) == 1
    assert len(metadata) == 1
    assert metadata[0].status_code == 302


def test_local_http_assessment_sanitizes_target_query_and_fragment(
    monkeypatch,
):
    result, requests, metadata = run(
        run_local_http_assessment(
            monkeypatch,
            target_path="/account?token=SUPERSECRET#private",
        )
    )

    assert result.status == ScanStatus.COMPLETED
    assert len(requests) == 1
    assert len(metadata) == 1

    stored_target = str(result.target.url)
    requested_url = str(metadata[0].requested_url)
    response_url = str(metadata[0].response_url)

    for stored_url in (
        stored_target,
        requested_url,
        response_url,
    ):
        assert "SUPERSECRET" not in stored_url
        assert "token=" not in stored_url
        assert "?" not in stored_url
        assert "#" not in stored_url

    assert "/account" in stored_target
    assert "/account" in requested_url
    assert "/account" in response_url

def test_local_http_oversized_response_is_rejected(monkeypatch):
    import webhawk.core.pipeline as pipeline

    monkeypatch.setattr(
        pipeline,
        "get_default_config",
        lambda: AppConfig(
            http=HttpConfig(max_response_bytes=16),
        ),
    )

    result, requests, metadata = run(
        run_local_http_assessment(
            monkeypatch,
            body=b"A" * 128,
        )
    )

    assert result.status == ScanStatus.FAILED
    assert result.error is not None
    assert result.error.code == ScanErrorCode.RESPONSE_TOO_LARGE

    assert result.findings == []
    assert len(requests) == 1

    # Oversized responses must not reach the analyzer.
    assert metadata == []

async def run_local_https_pipeline_assessment(
    monkeypatch,
    *,
    certificate_hostname="webhawk.test",
    target_hostname="webhawk.test",
    trust_certificate=True,
):
    import ssl
    import trustme
    import webhawk.core.pipeline as pipeline

    ca = trustme.CA()
    certificate = ca.issue_cert(certificate_hostname)

    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    certificate.configure_cert(server_context)

    client_context = ssl.create_default_context()

    if trust_certificate:
        ca.configure_trust(client_context)

    captured_metadata = []
    captured_requests = []

    def capture_analysis(metadata, *, raw_headers, **kwargs):
        captured_metadata.append(metadata)
        return []

    monkeypatch.setattr(
        pipeline,
        "analyze_response",
        capture_analysis,
    )

    async def handle_client(reader, writer):
        try:
            request_line = await reader.readline()
            captured_requests.append(request_line.decode().strip())

            await reader.readuntil(b"\r\n\r\n")

            response = (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Length: 2\r\n"
                b"Connection: close\r\n"
                b"\r\n"
                b"OK"
            )

            writer.write(response)
            await writer.drain()

        except (ConnectionError, asyncio.IncompleteReadError):
            pass

        finally:
            writer.close()

            try:
                await writer.wait_closed()
            except ConnectionError:
                pass

    server = await asyncio.start_server(
        handle_client,
        host="127.0.0.1",
        port=0,
        ssl=server_context,
    )

    port = server.sockets[0].getsockname()[1]

    target_url = f"https://{target_hostname}:{port}/"

    policy = TargetPolicy(
        authorized_hosts=frozenset({target_hostname}),
        authorized_networks=("127.0.0.0/8",),
        allow_loopback=True,
    )

    try:
        result = await pipeline.assess_target(
            target_url,
            policy,
            resolver=lambda hostname, port: ["127.0.0.1"],
            ssl_context=client_context,
        )

        return result, captured_requests, captured_metadata

    finally:
        server.close()
        await server.wait_closed()


def test_pipeline_accepts_trusted_https_certificate(monkeypatch):
    result, requests, metadata = run(
        run_local_https_pipeline_assessment(monkeypatch)
    )

    assert result.status == ScanStatus.COMPLETED
    assert result.error is None
    assert result.findings == []

    assert len(requests) == 1
    assert len(metadata) == 1
    assert metadata[0].status_code == 200


def test_pipeline_rejects_untrusted_https_certificate(monkeypatch):
    result, requests, metadata = run(
        run_local_https_pipeline_assessment(
            monkeypatch,
            trust_certificate=False,
        )
    )

    assert result.status == ScanStatus.FAILED
    assert result.error is not None
    assert result.error.code == ScanErrorCode.TLS_FAILED

    assert result.findings == []
    assert metadata == []


def test_pipeline_rejects_https_hostname_mismatch(monkeypatch):
    result, requests, metadata = run(
        run_local_https_pipeline_assessment(
            monkeypatch,
            certificate_hostname="webhawk.test",
            target_hostname="wrong.webhawk.test",
        )
    )

    assert result.status == ScanStatus.FAILED
    assert result.error is not None
    assert result.error.code == ScanErrorCode.TLS_FAILED

    assert result.findings == []
    assert metadata == []

def test_pipeline_returns_analysis_failed_when_analyzer_crashes(monkeypatch):
    import webhawk.core.pipeline as pipeline

    def failing_analyzer(metadata, *, raw_headers, **kwargs):
        raise RuntimeError("INTERNAL_ANALYZER_SECRET")

    monkeypatch.setattr(
        pipeline,
        "analyze_response",
        failing_analyzer,
    )

    async def scenario():
        async def handle_client(reader, writer):
            try:
                await reader.readuntil(b"\r\n\r\n")

                writer.write(
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Length: 2\r\n"
                    b"Connection: close\r\n"
                    b"\r\n"
                    b"OK"
                )
                await writer.drain()

            finally:
                writer.close()
                await writer.wait_closed()

        server = await asyncio.start_server(
            handle_client,
            "127.0.0.1",
            0,
        )

        port = server.sockets[0].getsockname()[1]

        policy = TargetPolicy(
            authorized_hosts=frozenset({"webhawk.test"}),
            authorized_networks=("127.0.0.0/8",),
            allow_loopback=True,
        )

        try:
            return await pipeline.assess_target(
                f"http://webhawk.test:{port}/",
                policy,
                resolver=lambda hostname, port: ["127.0.0.1"],
            )

        finally:
            server.close()
            await server.wait_closed()

    result = run(scenario())

    assert result.status == ScanStatus.FAILED
    assert result.error is not None
    assert result.error.code == ScanErrorCode.ANALYSIS_FAILED
    assert result.findings == []

    assert "INTERNAL_ANALYZER_SECRET" not in repr(result)

def test_pipeline_cancellation_propagates_and_closes_transport(monkeypatch):
    import webhawk.core.pipeline as pipeline

    original_transport = pipeline.WebHawkAsyncTransport
    created_transports = []

    def tracking_transport(*args, **kwargs):
        transport = original_transport(*args, **kwargs)
        created_transports.append(transport)
        return transport

    monkeypatch.setattr(
        pipeline,
        "WebHawkAsyncTransport",
        tracking_transport,
    )

    async def scenario():
        request_received = asyncio.Event()
        client_connection_closed = asyncio.Event()

        async def handle_client(reader, writer):
            try:
                await reader.readline()
                await reader.readuntil(b"\r\n\r\n")

                request_received.set()

                # Keep the connection open without sending a response.
                # Cancellation should cause the client to close it.
                await reader.read()

            except (ConnectionError, asyncio.IncompleteReadError):
                pass

            finally:
                writer.close()

                try:
                    await writer.wait_closed()
                except ConnectionError:
                    pass

                client_connection_closed.set()

        server = await asyncio.start_server(
            handle_client,
            host="127.0.0.1",
            port=0,
        )

        port = server.sockets[0].getsockname()[1]

        target_url = f"http://webhawk.test:{port}/"

        policy = TargetPolicy(
            authorized_hosts=frozenset({"webhawk.test"}),
            authorized_networks=("127.0.0.0/8",),
            allow_loopback=True,
        )

        task = asyncio.create_task(
            pipeline.assess_target(
                target_url,
                policy,
                resolver=lambda hostname, port: ["127.0.0.1"],
            )
        )

        try:
            await asyncio.wait_for(
                request_received.wait(),
                timeout=5,
            )

            assert len(created_transports) == 1

            task.cancel()

            with pytest.raises(asyncio.CancelledError):
                await task

            assert created_transports[0]._closed is True

            await asyncio.wait_for(
                client_connection_closed.wait(),
                timeout=5,
            )

        finally:
            if not task.done():
                task.cancel()

                try:
                    await task
                except asyncio.CancelledError:
                    pass

            server.close()
            await server.wait_closed()

    run(scenario())

def test_pipeline_preserves_cancellation_when_transport_cleanup_fails(
    monkeypatch,
):
    import httpx
    import webhawk.core.pipeline as pipeline

    request_started = asyncio.Event()

    class FailingCleanupTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            request_started.set()
            await asyncio.Event().wait()

        async def aclose(self):
            raise RuntimeError("SIMULATED_CLEANUP_FAILURE")

    monkeypatch.setattr(
        pipeline,
        "WebHawkAsyncTransport",
        lambda *args, **kwargs: FailingCleanupTransport(),
    )

    async def scenario():
        policy = TargetPolicy(
            authorized_hosts=frozenset({"webhawk.test"}),
        )

        task = asyncio.create_task(
            pipeline.assess_target(
                "http://webhawk.test/",
                policy,
            )
        )

        try:
            await asyncio.wait_for(
                request_started.wait(),
                timeout=5,
            )

            task.cancel()

            with pytest.raises(asyncio.CancelledError):
                await task

        finally:
            if not task.done():
                task.cancel()

                try:
                    await task
                except asyncio.CancelledError:
                    pass

    run(scenario())

@pytest.mark.parametrize(
    "exception_type",
    [ValueError, TypeError],
)
def test_pipeline_classifies_unexpected_runtime_type_errors(
    monkeypatch,
    exception_type,
):
    import httpx
    import webhawk.core.pipeline as pipeline

    class StubStream(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield b"test response"

        async def aclose(self):
            pass

    class StubTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            return httpx.Response(
                200,
                request=request,
                stream=StubStream(),
            )

        async def aclose(self):
            pass

    monkeypatch.setattr(
        pipeline,
        "WebHawkAsyncTransport",
        lambda *args, **kwargs: StubTransport(),
    )

    def fail_during_metadata(*args, **kwargs):
        raise exception_type("SIMULATED_RUNTIME_FAILURE")

    monkeypatch.setattr(
        pipeline,
        "build_response_metadata",
        fail_during_metadata,
    )

    result = run(
        pipeline.assess_target(
            "http://example.com/",
            valid_policy(),
        )
    )

    assert result.status == ScanStatus.FAILED
    assert result.error is not None
    assert result.error.code == ScanErrorCode.UNEXPECTED_ERROR
    assert result.findings == []

@pytest.mark.parametrize(
    "exception_type",
    [ValueError, TypeError],
)
def test_pipeline_classifies_transport_constructor_type_errors_as_configuration(
    monkeypatch,
    exception_type,
):
    import webhawk.core.pipeline as pipeline

    def fail_transport_construction(*args, **kwargs):
        raise exception_type("SIMULATED_INVALID_TRANSPORT_CONFIGURATION")

    monkeypatch.setattr(
        pipeline,
        "WebHawkAsyncTransport",
        fail_transport_construction,
    )

    result = run(
        pipeline.assess_target(
            "http://example.com/",
            valid_policy(),
        )
    )

    assert result.status == ScanStatus.FAILED
    assert result.error is not None
    assert result.error.code == ScanErrorCode.CONFIGURATION_ERROR
    assert result.findings == []
