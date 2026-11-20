import ssl
from typing import AsyncIterator, Callable

import httpcore
import httpx

from webhawk.core.safety import TargetPolicy
from webhawk.core.transport.connection import IPPinnedNetworkBackend


DEFAULT_MAX_RESPONSE_BYTES = 10 * 1024 * 1024
DEFAULT_MAX_REQUEST_BYTES = 10 * 1024 * 1024


class ResponseTooLargeError(httpx.TransportError):
    """Raised when an HTTP response exceeds the configured size limit."""


class RequestBodyTooLargeError(httpx.RequestError):
    """Raised when an HTTP request body exceeds its configured size limit."""


class HTTPXResponseStream(httpx.AsyncByteStream):
    """Adapt an HTTP Core response stream to HTTPX with size enforcement."""

    def __init__(
        self,
        response: httpcore.Response,
        *,
        max_bytes: int | None = None,
        request: httpx.Request | None = None,
    ) -> None:
        self._response = response
        self._max_bytes = max_bytes
        self._request = request
        self._bytes_received = 0
        self._closed = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        try:
            async for chunk in self._response.stream:
                if self._max_bytes is not None:
                    next_total = self._bytes_received + len(chunk)

                    if next_total > self._max_bytes:
                        await self.aclose()
                        raise ResponseTooLargeError(
                            "HTTP response size exceeds the configured limit.",
                            request=self._request,
                        )

                    self._bytes_received = next_total

                yield chunk

        except BaseException:
            await self.aclose()
            raise

    async def aclose(self) -> None:
        if not self._closed:
            self._closed = True
            await self._response.aclose()


class HTTPXRequestStream(httpx.AsyncByteStream):
    """Wrap an HTTPX request stream with streaming size enforcement."""

    def __init__(
        self,
        stream,
        *,
        max_bytes: int,
        request: httpx.Request,
    ) -> None:
        self._stream = stream
        self._max_bytes = max_bytes
        self._request = request
        self._bytes_sent = 0
        self._closed = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        try:
            if not callable(getattr(self._stream, "__aiter__", None)):
                raise TypeError(
                    "HTTP request streams must support asynchronous iteration."
                )

            async for chunk in self._stream:
                yield self._check_chunk(chunk)

        except BaseException:
            # Preserve the original exception, including cancellation,
            # even if closing the underlying stream also fails.
            try:
                await self.aclose()
            except BaseException:
                pass

            raise

        else:
            await self.aclose()

    def _check_chunk(self, chunk: bytes) -> bytes:
        next_total = self._bytes_sent + len(chunk)

        if next_total > self._max_bytes:
            raise RequestBodyTooLargeError(
                "HTTP request body exceeds the configured limit.",
                request=self._request,
            )

        self._bytes_sent = next_total
        return chunk

    async def aclose(self) -> None:
        if self._closed:
            return

        self._closed = True

        close_async = getattr(self._stream, "aclose", None)

        if close_async is not None:
            await close_async()
            return

        close_sync = getattr(self._stream, "close", None)

        if close_sync is not None:
            close_sync()


class WebHawkAsyncTransport(httpx.AsyncBaseTransport):
    """HTTPX transport restricted to one authorized origin."""

    def __init__(
        self,
        target_url: str,
        policy: TargetPolicy,
        *,
        ssl_context: ssl.SSLContext | None = None,
        max_connections: int = 10,
        max_keepalive_connections: int = 5,
        keepalive_expiry: float = 5.0,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
        max_request_bytes: int = DEFAULT_MAX_REQUEST_BYTES,
        resolver: Callable[[str, int], list[str]] | None = None,
        backend: httpcore.AsyncNetworkBackend | None = None,
    ) -> None:
        self._target = httpx.URL(target_url)

        if self._target.scheme not in {"http", "https"}:
            raise ValueError("Only HTTP and HTTPS targets are supported.")

        self._hostname = IPPinnedNetworkBackend._normalize_hostname(
            self._target.host
        )
        self._port = self._target.port or (
            443 if self._target.scheme == "https" else 80
        )

        if max_connections < 1:
            raise ValueError("max_connections must be positive.")

        if not 0 <= max_keepalive_connections <= max_connections:
            raise ValueError("Invalid keepalive connection limit.")

        if keepalive_expiry < 0:
            raise ValueError("keepalive_expiry cannot be negative.")

        if (
            isinstance(max_response_bytes, bool)
            or not isinstance(max_response_bytes, int)
            or max_response_bytes <= 0
        ):
            raise ValueError(
                "max_response_bytes must be a positive integer."
            )

        self._max_response_bytes = max_response_bytes

        if (
            isinstance(max_request_bytes, bool)
            or not isinstance(max_request_bytes, int)
            or max_request_bytes <= 0
        ):
            raise ValueError(
                "max_request_bytes must be a positive integer."
            )

        self._max_request_bytes = max_request_bytes

        network_backend = IPPinnedNetworkBackend(
            target_url,
            policy,
            backend=backend,
            resolver=resolver,
        )

        self._pool = httpcore.AsyncConnectionPool(
            ssl_context=(
                ssl_context
                if ssl_context is not None
                else ssl.create_default_context()
            ),
            max_connections=max_connections,
            max_keepalive_connections=max_keepalive_connections,
            keepalive_expiry=keepalive_expiry,
            http1=True,
            http2=False,
            retries=0,
            network_backend=network_backend,
        )

        self._closed = False

    def _validate_origin(self, request: httpx.Request) -> None:
        try:
            hostname = IPPinnedNetworkBackend._normalize_hostname(
                request.url.host
            )
        except ValueError as exc:
            raise httpx.RequestError(
                "Invalid request hostname.",
                request=request,
            ) from exc

        port = request.url.port or (
            443 if request.url.scheme == "https" else 80
        )

        if (
            request.url.scheme != self._target.scheme
            or hostname != self._hostname
            or port != self._port
        ):
            raise httpx.RequestError(
                "Request origin does not match the authorized target.",
                request=request,
            )

        host_headers = request.headers.get_list("host")

        if len(host_headers) != 1:
            raise httpx.RequestError(
                "Request must contain exactly one Host header.",
                request=request,
            )

        host_value = host_headers[0]

        if (
            not host_value
            or any(char in host_value for char in "/?#\\")
            or any(char.isspace() for char in host_value)
        ):
            raise httpx.RequestError(
                "Invalid Host header authority.",
                request=request,
            )

        try:
            header_authority = httpx.URL(
                f"{request.url.scheme}://{host_value}"
            )

            header_hostname = (
                IPPinnedNetworkBackend._normalize_hostname(
                    header_authority.host
                )
            )

            header_port = header_authority.port or (
                443 if request.url.scheme == "https" else 80
            )

        except (ValueError, httpx.InvalidURL) as exc:
            raise httpx.RequestError(
                "Invalid Host header.",
                request=request,
            ) from exc

        if (
            header_hostname != self._hostname
            or header_port != self._port
            or bool(header_authority.username)
            or bool(header_authority.password)
        ):
            raise httpx.RequestError(
                "Host header does not match the authorized origin.",
                request=request,
            )

    @staticmethod
    def _map_exception(
        exc: Exception,
        request: httpx.Request,
    ) -> None:
        mappings = (
            (httpcore.ConnectTimeout, httpx.ConnectTimeout),
            (httpcore.ReadTimeout, httpx.ReadTimeout),
            (httpcore.WriteTimeout, httpx.WriteTimeout),
            (httpcore.PoolTimeout, httpx.PoolTimeout),
            (httpcore.ConnectError, httpx.ConnectError),
            (httpcore.ReadError, httpx.ReadError),
            (httpcore.WriteError, httpx.WriteError),
            (httpcore.ProxyError, httpx.ProxyError),
            (httpcore.ProtocolError, httpx.ProtocolError),
            (httpcore.NetworkError, httpx.NetworkError),
            (httpcore.TimeoutException, httpx.TimeoutException),
        )

        for source, destination in mappings:
            if isinstance(exc, source):
                raise destination(str(exc), request=request) from exc

        raise exc

    @staticmethod
    def _content_length_exceeds_limit(
        headers: httpx.Headers,
        limit: int,
    ) -> bool:
        values = headers.get_list("content-length")

        if not values:
            return False

        parsed_lengths = []

        for value in values:
            for item in value.split(","):
                item = item.strip()

                if not item or not item.isascii() or not item.isdecimal():
                    raise ValueError("Invalid Content-Length header.")

                parsed_lengths.append(int(item))

        if not parsed_lengths:
            raise ValueError("Empty Content-Length header.")

        if len(set(parsed_lengths)) != 1:
            raise ValueError("Conflicting Content-Length values.")

        return parsed_lengths[0] > limit

    async def handle_async_request(
        self,
        request: httpx.Request,
    ) -> httpx.Response:
        if self._closed:
            raise RuntimeError("WebHawk transport is closed.")

        request_stream = HTTPXRequestStream(
            request.stream,
            max_bytes=self._max_request_bytes,
            request=request,
        )

        try:
            self._validate_origin(request)

            if not callable(getattr(request.stream, "__aiter__", None)):
                raise httpx.RequestError(
                    "Request stream must support asynchronous iteration.",
                    request=request,
                )

        except BaseException:
            try:
                await request_stream.aclose()
            except BaseException:
                pass

            raise

        try:
            request_exceeds_limit = self._content_length_exceeds_limit(
                request.headers,
                self._max_request_bytes,
            )
        except ValueError as exc:
            try:
                await request_stream.aclose()
            except BaseException:
                pass

            raise httpx.RequestError(
                "Invalid or conflicting request Content-Length header.",
                request=request,
            ) from exc

        if request_exceeds_limit:
            try:
                await request_stream.aclose()
            except BaseException:
                pass

            raise RequestBodyTooLargeError(
                "HTTP request body exceeds the configured limit.",
                request=request,
            )

        # Compression is disabled until bounded decompression is implemented.
        request.headers["accept-encoding"] = "identity"

        core_request = httpcore.Request(
            method=request.method,
            url=httpcore.URL(
                scheme=request.url.raw_scheme,
                host=request.url.raw_host,
                port=request.url.port,
                target=request.url.raw_path,
            ),
            headers=request.headers.raw,
            content=request_stream,
            extensions=request.extensions,
        )

        try:
            core_response = await self._pool.handle_async_request(
                core_request
            )
        except BaseException as exc:
            # Ensure the original request stream is closed even when
            # HTTP Core fails before consuming the complete body.
            try:
                await request_stream.aclose()
            except BaseException:
                pass

            if isinstance(exc, Exception):
                self._map_exception(exc, request)

            raise

        response_headers = httpx.Headers(core_response.headers)

        content_encodings = response_headers.get_list("content-encoding")

        try:
            encoding_tokens = [
                token.strip().lower()
                for value in content_encodings
                for token in value.split(",")
            ]

            if any(
                not token or token != "identity"
                for token in encoding_tokens
            ):
                raise ValueError("Unsupported response content encoding.")

        except ValueError as exc:
            await core_response.aclose()

            raise httpx.RemoteProtocolError(
                "Unsupported or invalid response content encoding.",
                request=request,
            ) from exc

        try:
            exceeds_limit = self._content_length_exceeds_limit(
                response_headers,
                self._max_response_bytes,
            )
        except ValueError as exc:
            await core_response.aclose()

            raise httpx.RemoteProtocolError(
                "Invalid or conflicting Content-Length header.",
                request=request,
            ) from exc

        if exceeds_limit:
            await core_response.aclose()

            raise ResponseTooLargeError(
                "HTTP response size exceeds the configured limit.",
                request=request,
            )

        stream = HTTPXResponseStream(
            core_response,
            max_bytes=self._max_response_bytes,
            request=request,
        )

        return httpx.Response(
            status_code=core_response.status,
            headers=core_response.headers,
            stream=stream,
            extensions=core_response.extensions,
            request=request,
        )

    async def aclose(self) -> None:
        if not self._closed:
            self._closed = True
            await self._pool.aclose()
