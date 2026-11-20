import asyncio

import httpcore
import httpx
import pytest

from webhawk.core.safety import TargetPolicy
from webhawk.core.transport.client import (
    HTTPXResponseStream,
    RequestBodyTooLargeError,
    WebHawkAsyncTransport,
)
from webhawk.core.transport.connection import IPPinnedNetworkBackend


class FakeCoreResponse:
    def __init__(self, status=200, body=b"hello"):
        self.status = status
        self.headers = [(b"content-type", b"text/plain")]
        self.extensions = {"test": "response"}
        self.stream = self._stream(body)
        self.closed = False

    @staticmethod
    async def _stream(body):
        yield body

    async def aclose(self):
        self.closed = True


class FakePool:
    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.requests = []
        self.response = FakeCoreResponse()
        self.error = None
        self.closed = False

    async def handle_async_request(self, request):
        self.requests.append(request)

        if self.error is not None:
            raise self.error

        body = bytearray()

        async for chunk in request.stream:
            body.extend(chunk)

        self.request_bodies = getattr(self, "request_bodies", [])
        self.request_bodies.append(bytes(body))

        return self.response

    async def aclose(self):
        self.closed = True


@pytest.fixture
def transport_factory(monkeypatch):
    pools = []

    def create_pool(**kwargs):
        pool = FakePool(**kwargs)
        pools.append(pool)
        return pool

    monkeypatch.setattr(
        httpcore,
        "AsyncConnectionPool",
        create_pool,
    )

    policy = TargetPolicy(
        authorized_hosts=frozenset({"example.com"}),
        authorized_networks=(),
        allow_loopback=False,
    )

    def create_transport(**kwargs):
        return WebHawkAsyncTransport(
            "https://example.com",
            policy,
            resolver=lambda hostname, port: ["93.184.216.34"],
            **kwargs,
        )

    return create_transport, pools


def test_transport_creates_ip_pinned_pool(transport_factory):
    create_transport, pools = transport_factory

    transport = create_transport()

    assert len(pools) == 1
    assert isinstance(
        pools[0].kwargs["network_backend"],
        IPPinnedNetworkBackend,
    )
    assert pools[0].kwargs["retries"] == 0
    assert pools[0].kwargs["http2"] is False

    asyncio.run(transport.aclose())


def test_request_is_forwarded_to_httpcore(transport_factory):
    create_transport, pools = transport_factory
    transport = create_transport()

    request = httpx.Request(
        "GET",
        "https://example.com/test",
        headers={"X-Test": "webhawk"},
    )

    async def run():
        response = await transport.handle_async_request(request)
        await response.aclose()

    asyncio.run(run())

    assert len(pools[0].requests) == 1

    core_request = pools[0].requests[0]

    assert core_request.method == b"GET"
    assert core_request.url.scheme == b"https"
    assert core_request.url.host == b"example.com"
    assert core_request.url.target == b"/test"

    assert (b"X-Test", b"webhawk") in core_request.headers


def test_response_metadata_and_streaming(transport_factory):
    create_transport, pools = transport_factory
    transport = create_transport()

    request = httpx.Request("GET", "https://example.com/")

    async def run():
        response = await transport.handle_async_request(request)

        assert response.status_code == 200
        assert response.headers["content-type"] == "text/plain"
        assert response.extensions == {"test": "response"}
        assert response.request is request

        body = b"".join([chunk async for chunk in response.aiter_bytes()])

        assert body == b"hello"

        await response.aclose()

    asyncio.run(run())


def test_response_stream_closes_core_response():
    core_response = FakeCoreResponse()
    stream = HTTPXResponseStream(core_response)

    asyncio.run(stream.aclose())

    assert core_response.closed is True


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com/",
        "https://other.example.com/",
        "https://example.com:8443/",
    ],
)
def test_rejects_different_origins(transport_factory, url):
    create_transport, pools = transport_factory
    transport = create_transport()

    request = httpx.Request("GET", url)

    async def run():
        with pytest.raises(httpx.RequestError):
            await transport.handle_async_request(request)

    asyncio.run(run())

    assert pools[0].requests == []

    asyncio.run(transport.aclose())


def test_maps_httpcore_connect_error(transport_factory):
    create_transport, pools = transport_factory
    transport = create_transport()

    pools[0].error = httpcore.ConnectError("connection failed")

    request = httpx.Request("GET", "https://example.com/")

    async def run():
        with pytest.raises(httpx.ConnectError):
            await transport.handle_async_request(request)

    asyncio.run(run())

    asyncio.run(transport.aclose())


def test_close_is_idempotent(transport_factory):
    create_transport, pools = transport_factory
    transport = create_transport()

    async def run():
        await transport.aclose()
        await transport.aclose()

    asyncio.run(run())

    assert pools[0].closed is True


def test_request_after_close_is_rejected(transport_factory):
    create_transport, pools = transport_factory
    transport = create_transport()

    async def run():
        await transport.aclose()

        request = httpx.Request(
            "GET",
            "https://example.com/",
        )

        with pytest.raises(RuntimeError, match="closed"):
            await transport.handle_async_request(request)

    asyncio.run(run())

    assert pools[0].requests == []


def test_cancellation_propagates(transport_factory):
    create_transport, pools = transport_factory
    transport = create_transport()

    class CancelledPool(FakePool):
        async def handle_async_request(self, request):
            raise asyncio.CancelledError()

    cancelled_pool = CancelledPool()
    transport._pool = cancelled_pool

    request = httpx.Request("GET", "https://example.com/")

    async def run():
        with pytest.raises(asyncio.CancelledError):
            await transport.handle_async_request(request)

    asyncio.run(run())



def test_rejects_mismatched_host_header(transport_factory):
    create_transport, pools = transport_factory
    transport = create_transport()

    request = httpx.Request(
        "GET",
        "https://example.com/",
        headers={"Host": "evil.example"},
    )

    async def run():
        with pytest.raises(httpx.RequestError, match="Host header"):
            await transport.handle_async_request(request)

    asyncio.run(run())

    assert pools[0].requests == []

    asyncio.run(transport.aclose())

@pytest.mark.parametrize(
    "host_header",
    [
        "evil.example",
        "example.com:8443",
        "user@example.com",
        "example.com/path",
        "example.com?query=1",
        "example.com#fragment",
        "example.com:invalid",
    ],
)
def test_rejects_invalid_host_authorities(
    transport_factory,
    host_header,
):
    create_transport, pools = transport_factory
    transport = create_transport()

    request = httpx.Request(
        "GET",
        "https://example.com/",
        headers={"Host": host_header},
    )

    async def run():
        with pytest.raises(httpx.RequestError):
            await transport.handle_async_request(request)

    asyncio.run(run())

    assert pools[0].requests == []

    asyncio.run(transport.aclose())


@pytest.mark.parametrize(
    "host_header",
    [
        "example.com",
        "example.com:443",
    ],
)
def test_accepts_matching_host_authorities(
    transport_factory,
    host_header,
):
    create_transport, pools = transport_factory
    transport = create_transport()

    request = httpx.Request(
        "GET",
        "https://example.com/",
        headers={"Host": host_header},
    )

    async def run():
        response = await transport.handle_async_request(request)
        await response.aclose()

    asyncio.run(run())

    assert len(pools[0].requests) == 1

    asyncio.run(transport.aclose())


def test_rejects_duplicate_host_headers(transport_factory):
    create_transport, pools = transport_factory
    transport = create_transport()

    request = httpx.Request(
        "GET",
        "https://example.com/",
        headers=[
            ("Host", "example.com"),
            ("Host", "evil.example"),
        ],
    )

    async def run():
        with pytest.raises(
            httpx.RequestError,
            match="exactly one Host header",
        ):
            await transport.handle_async_request(request)

    asyncio.run(run())

    assert pools[0].requests == []

    asyncio.run(transport.aclose())

def test_rejects_response_exceeding_content_length_limit(
    transport_factory,
):
    create_transport, pools = transport_factory
    transport = create_transport(max_response_bytes=4)

    pools[0].response.headers = [
        (b"content-length", b"100"),
        (b"content-type", b"text/plain"),
    ]

    request = httpx.Request(
        "GET",
        "https://example.com/",
    )

    async def run():
        with pytest.raises(
            httpx.TransportError,
            match="response size",
        ):
            await transport.handle_async_request(request)

    asyncio.run(run())

    assert pools[0].response.closed is True

    asyncio.run(transport.aclose())


def test_rejects_oversized_stream_without_content_length(
    transport_factory,
):
    create_transport, pools = transport_factory
    transport = create_transport(max_response_bytes=4)

    pools[0].response = FakeCoreResponse(body=b"123456789")
    pools[0].response.headers = [
        (b"content-type", b"text/plain"),
    ]

    request = httpx.Request(
        "GET",
        "https://example.com/",
    )

    async def run():
        response = await transport.handle_async_request(request)

        with pytest.raises(
            httpx.TransportError,
            match="response size",
        ):
            async for _ in response.aiter_bytes():
                pass

        assert pools[0].response.closed is True

    asyncio.run(run())

    asyncio.run(transport.aclose())


def test_accepts_response_at_exact_size_limit(
    transport_factory,
):
    create_transport, pools = transport_factory
    transport = create_transport(max_response_bytes=5)

    pools[0].response = FakeCoreResponse(body=b"12345")
    pools[0].response.headers = [
        (b"content-length", b"5"),
    ]

    request = httpx.Request(
        "GET",
        "https://example.com/",
    )

    async def run():
        response = await transport.handle_async_request(request)

        body = b"".join([
            chunk async for chunk in response.aiter_bytes()
        ])

        assert body == b"12345"

        await response.aclose()

    asyncio.run(run())


@pytest.mark.parametrize(
    "limit",
    [0, -1, -100],
)
def test_rejects_invalid_response_size_limit(
    transport_factory,
    limit,
):
    create_transport, _ = transport_factory

    with pytest.raises(ValueError):
        create_transport(max_response_bytes=limit)


class MultiChunkCoreResponse(FakeCoreResponse):
    def __init__(self, chunks):
        self.status = 200
        self.headers = [(b"content-type", b"text/plain")]
        self.extensions = {}
        self.stream = self._stream_chunks(chunks)
        self.closed = False

    @staticmethod
    async def _stream_chunks(chunks):
        for chunk in chunks:
            yield chunk


def test_rejects_multiple_chunks_exceeding_response_limit(
    transport_factory,
):
    create_transport, pools = transport_factory
    transport = create_transport(max_response_bytes=5)

    response = MultiChunkCoreResponse([b"123", b"456"])
    pools[0].response = response

    request = httpx.Request("GET", "https://example.com/")

    async def run():
        result = await transport.handle_async_request(request)

        received = bytearray()

        with pytest.raises(
            httpx.TransportError,
            match="response size",
        ):
            async for chunk in result.aiter_bytes():
                received.extend(chunk)

        assert bytes(received) == b"123"
        assert response.closed is True

    asyncio.run(run())
    asyncio.run(transport.aclose())


def test_response_stream_closes_after_cancellation():
    class CancelledCoreResponse(FakeCoreResponse):
        @staticmethod
        async def _stream(body):
            yield b"first"
            raise asyncio.CancelledError()

    response = CancelledCoreResponse()
    stream = HTTPXResponseStream(response)

    async def run():
        with pytest.raises(asyncio.CancelledError):
            async for _ in stream:
                pass

    asyncio.run(run())

    assert response.closed is True


def test_default_response_size_limit(transport_factory):
    create_transport, _ = transport_factory

    transport = create_transport()

    assert transport._max_response_bytes == 10 * 1024 * 1024

    asyncio.run(transport.aclose())


@pytest.mark.parametrize(
    "content_length",
    [
        "-1",
        "invalid",
        "10, 20",
        "5, 6",
    ],
)
def test_rejects_invalid_content_length(
    transport_factory,
    content_length,
):
    create_transport, pools = transport_factory
    transport = create_transport(max_response_bytes=10)

    pools[0].response.headers = [
        (b"content-length", content_length.encode()),
    ]

    request = httpx.Request("GET", "https://example.com/")

    async def run():
        with pytest.raises(httpx.TransportError):
            await transport.handle_async_request(request)

    asyncio.run(run())

    assert pools[0].response.closed is True
    asyncio.run(transport.aclose())


def test_accepts_identical_duplicate_content_lengths(
    transport_factory,
):
    create_transport, pools = transport_factory
    transport = create_transport(max_response_bytes=10)

    pools[0].response.headers = [
        (b"content-length", b"5"),
        (b"content-length", b"5"),
    ]

    request = httpx.Request("GET", "https://example.com/")

    async def run():
        response = await transport.handle_async_request(request)
        await response.aclose()

    asyncio.run(run())

    asyncio.run(transport.aclose())


def test_rejects_duplicate_content_length_exceeding_limit(
    transport_factory,
):
    create_transport, pools = transport_factory
    transport = create_transport(max_response_bytes=10)

    pools[0].response.headers = [
        (b"content-length", b"15"),
        (b"content-length", b"15"),
    ]

    request = httpx.Request("GET", "https://example.com/")

    async def run():
        with pytest.raises(
            httpx.TransportError,
            match="response size",
        ):
            await transport.handle_async_request(request)

    asyncio.run(run())

    assert pools[0].response.closed is True
    asyncio.run(transport.aclose())


@pytest.mark.parametrize(
    "content_encoding",
    [
        "gzip",
        "deflate",
        "br",
        "zstd",
        "gzip, br",
    ],
)
def test_rejects_compressed_response(
    transport_factory,
    content_encoding,
):
    create_transport, pools = transport_factory
    transport = create_transport()

    pools[0].response.headers = [
        (b"content-encoding", content_encoding.encode()),
    ]

    request = httpx.Request("GET", "https://example.com/")

    async def run():
        with pytest.raises(
            httpx.TransportError,
            match="encoding",
        ):
            await transport.handle_async_request(request)

    asyncio.run(run())

    assert pools[0].response.closed is True
    asyncio.run(transport.aclose())


def test_accepts_identity_content_encoding(transport_factory):
    create_transport, pools = transport_factory
    transport = create_transport()

    pools[0].response.headers = [
        (b"content-encoding", b"identity"),
    ]

    request = httpx.Request("GET", "https://example.com/")

    async def run():
        response = await transport.handle_async_request(request)
        await response.aclose()

    asyncio.run(run())
    asyncio.run(transport.aclose())




class TrackingAsyncStream(httpx.AsyncByteStream):
    def __init__(self, chunks):
        self.chunks = chunks
        self.closed = False

    async def __aiter__(self):
        for chunk in self.chunks:
            yield chunk

    async def aclose(self):
        self.closed = True


def test_request_body_streaming_within_limit(transport_factory):
    create_transport, pools = transport_factory
    transport = create_transport(max_request_bytes=10)

    stream = TrackingAsyncStream([b"hello", b"world"])
    request = httpx.Request(
        "POST",
        "https://example.com/",
        headers={"Host": "example.com"},
        stream=stream,
    )

    async def run():
        response = await transport.handle_async_request(request)
        await response.aclose()

    asyncio.run(run())

    assert pools[0].request_bodies == [b"helloworld"]
    assert stream.closed is True
    assert request.stream is stream

    asyncio.run(transport.aclose())


def test_request_body_exact_limit_is_accepted(transport_factory):
    create_transport, pools = transport_factory
    transport = create_transport(max_request_bytes=5)

    stream = TrackingAsyncStream([b"he", b"llo"])
    request = httpx.Request(
        "POST",
        "https://example.com/",
        headers={"Host": "example.com"},
        stream=stream,
    )

    async def run():
        response = await transport.handle_async_request(request)
        await response.aclose()

    asyncio.run(run())

    assert pools[0].request_bodies == [b"hello"]
    assert stream.closed is True

    asyncio.run(transport.aclose())


def test_request_body_streaming_over_limit_is_rejected(transport_factory):
    create_transport, pools = transport_factory
    transport = create_transport(max_request_bytes=5)

    stream = TrackingAsyncStream([b"hello", b"world"])
    request = httpx.Request(
        "POST",
        "https://example.com/",
        headers={"Host": "example.com"},
        stream=stream,
    )

    async def run():
        with pytest.raises(RequestBodyTooLargeError):
            await transport.handle_async_request(request)

    asyncio.run(run())

    assert len(pools[0].requests) == 1
    assert not hasattr(pools[0], 'request_bodies')
    assert stream.closed is True
    assert request.stream is stream

    asyncio.run(transport.aclose())


@pytest.mark.parametrize(
    "content_length",
    ["6", "invalid", "5, 6", ""],
)
def test_invalid_or_oversized_request_content_length_is_rejected(
    transport_factory,
    content_length,
):
    create_transport, pools = transport_factory
    transport = create_transport(max_request_bytes=5)

    stream = TrackingAsyncStream([b"hello"])
    request = httpx.Request(
        "POST",
        "https://example.com/",
        headers={
            "Host": "example.com",
            "Content-Length": content_length,
        },
        stream=stream,
    )

    async def run():
        if content_length == "6":
            expected = RequestBodyTooLargeError
        else:
            expected = httpx.RequestError

        with pytest.raises(expected):
            await transport.handle_async_request(request)

    asyncio.run(run())

    assert pools[0].requests == []
    assert stream.closed is True

    asyncio.run(transport.aclose())


def test_request_body_limit_defaults_to_ten_megabytes(transport_factory):
    create_transport, _ = transport_factory
    transport = create_transport()

    assert transport._max_request_bytes == 10 * 1024 * 1024

    asyncio.run(transport.aclose())


@pytest.mark.parametrize("limit", [0, -1, True, 1.5, "100"])
def test_invalid_request_body_limit_is_rejected(transport_factory, limit):
    create_transport, _ = transport_factory

    with pytest.raises(ValueError, match="max_request_bytes"):
        create_transport(max_request_bytes=limit)


def test_request_stream_cleanup_when_pool_fails(transport_factory):
    create_transport, pools = transport_factory
    transport = create_transport()

    stream = TrackingAsyncStream([b"hello"])
    request = httpx.Request(
        "POST",
        "https://example.com/",
        headers={"Host": "example.com"},
        stream=stream,
    )

    pools[0].error = httpcore.ConnectError("connection failed")

    async def run():
        with pytest.raises(httpx.ConnectError):
            await transport.handle_async_request(request)

    asyncio.run(run())

    assert stream.closed is True

    asyncio.run(transport.aclose())


def test_request_stream_cancellation_closes_underlying_stream(
    transport_factory,
):
    create_transport, _ = transport_factory
    transport = create_transport()

    stream = TrackingAsyncStream([b"hello"])
    request = httpx.Request(
        "POST",
        "https://example.com/",
        headers={"Host": "example.com"},
        stream=stream,
    )

    class CancelledPool:
        async def handle_async_request(self, core_request):
            async for _ in core_request.stream:
                raise asyncio.CancelledError()
        async def aclose(self):
            pass

    transport._pool = CancelledPool()

    async def run():
        with pytest.raises(asyncio.CancelledError):
            await transport.handle_async_request(request)

    asyncio.run(run())

    assert stream.closed is True

    asyncio.run(transport.aclose())

class FailingCloseAsyncStream(TrackingAsyncStream):
    async def aclose(self):
        self.closed = True
        raise RuntimeError("Simulated stream cleanup failure")


class SyncOnlyStream:
    def __init__(self):
        self.closed = False

    def __iter__(self):
        yield b"hello"

    def close(self):
        self.closed = True


def test_origin_rejection_closes_request_stream(transport_factory):
    create_transport, pools = transport_factory
    transport = create_transport()

    stream = TrackingAsyncStream([b"hello"])
    request = httpx.Request(
        "POST",
        "https://other.example/",
        headers={"Host": "other.example"},
        stream=stream,
    )

    async def run():
        with pytest.raises(httpx.RequestError):
            await transport.handle_async_request(request)

    asyncio.run(run())

    assert stream.closed is True
    assert pools[0].requests == []

    asyncio.run(transport.aclose())


def test_content_length_error_survives_cleanup_failure(
    transport_factory,
):
    create_transport, pools = transport_factory
    transport = create_transport()

    stream = FailingCloseAsyncStream([b"hello"])
    request = httpx.Request(
        "POST",
        "https://example.com/",
        headers={
            "Host": "example.com",
            "Content-Length": "invalid",
        },
        stream=stream,
    )

    async def run():
        with pytest.raises(httpx.RequestError) as exc_info:
            await transport.handle_async_request(request)

        assert "Content-Length" in str(exc_info.value)

    asyncio.run(run())

    assert stream.closed is True
    assert pools[0].requests == []

    asyncio.run(transport.aclose())


def test_cancellation_survives_cleanup_failure(transport_factory):
    create_transport, _ = transport_factory
    transport = create_transport()

    stream = FailingCloseAsyncStream([b"hello"])
    request = httpx.Request(
        "POST",
        "https://example.com/",
        headers={"Host": "example.com"},
        stream=stream,
    )

    class CancelledPool:
        async def handle_async_request(self, core_request):
            raise asyncio.CancelledError()

        async def aclose(self):
            pass

    transport._pool = CancelledPool()

    async def run():
        with pytest.raises(asyncio.CancelledError):
            await transport.handle_async_request(request)

    asyncio.run(run())

    assert stream.closed is True

    asyncio.run(transport.aclose())


def test_sync_only_request_stream_is_rejected_and_closed(
    transport_factory,
):
    create_transport, pools = transport_factory
    transport = create_transport()

    stream = SyncOnlyStream()
    request = httpx.Request(
        "POST",
        "https://example.com/",
        headers={"Host": "example.com"},
        stream=stream,
    )

    async def run():
        with pytest.raises(httpx.RequestError):
            await transport.handle_async_request(request)

    asyncio.run(run())

    assert stream.closed is True
    assert pools[0].requests == []

    asyncio.run(transport.aclose())
