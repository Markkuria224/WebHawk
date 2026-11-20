import ipaddress
from typing import Callable
from urllib.parse import urlsplit

import anyio
from httpcore import (
    AsyncNetworkBackend,
    ConnectError,
    ConnectTimeout,
)
from httpcore._backends.anyio import AnyIOBackend

from webhawk.core.safety import (
    TargetPolicy,
    authorize_target,
)


class IPPinnedNetworkBackend(AsyncNetworkBackend):
    """Connect only to addresses approved by target authorization."""

    def __init__(
        self,
        target_url: str,
        policy: TargetPolicy,
        backend: AsyncNetworkBackend | None = None,
        resolver: Callable[[str, int], list[str]] | None = None,
    ) -> None:
        self._backend = (
            backend if backend is not None else AnyIOBackend()
        )

        if resolver is None:
            approved = authorize_target(target_url, policy)
        else:
            approved = authorize_target(
                target_url,
                policy,
                resolver=resolver,
            )

        self._target = approved
        parsed = urlsplit(approved.normalized_url)

        if parsed.hostname is None:
            raise ValueError("Approved target has no hostname.")

        self._hostname = self._normalize_hostname(parsed.hostname)
        self._port = parsed.port or (
            443 if parsed.scheme == "https" else 80
        )

        if self._normalize_hostname(approved.hostname) != self._hostname:
            raise ValueError("Approved target hostname is inconsistent.")

        self._addresses = approved.approved_addresses

        if not self._addresses:
            raise ValueError("No approved destination addresses available.")

    @staticmethod
    def _normalize_hostname(hostname: str) -> str:
        try:
            return ipaddress.ip_address(hostname).compressed
        except ValueError:
            try:
                normalized = (
                    hostname.rstrip(".")
                    .encode("idna")
                    .decode("ascii")
                    .lower()
                )
            except UnicodeError as exc:
                raise ValueError("Invalid hostname.") from exc

            if not normalized:
                raise ValueError("Invalid hostname.")

            return normalized

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options=None,
    ):
        try:
            requested_host = self._normalize_hostname(host)
        except ValueError as exc:
            raise ConnectError("Invalid connection hostname.") from exc

        if requested_host != self._hostname:
            raise ConnectError("Connection hostname is not authorized.")

        if port != self._port:
            raise ConnectError("Connection port is not authorized.")

        deadline = (
            anyio.current_time() + timeout
            if timeout is not None
            else None
        )

        last_error = None

        for address in self._addresses:
            remaining = (
                max(0.0, deadline - anyio.current_time())
                if deadline is not None
                else None
            )

            if remaining is not None and remaining <= 0:
                raise ConnectTimeout(
                    "Connection timeout budget exhausted."
                ) from last_error

            try:
                return await self._backend.connect_tcp(
                    host=address,
                    port=port,
                    timeout=remaining,
                    local_address=local_address,
                    socket_options=socket_options,
                )
            except (ConnectError, ConnectTimeout) as exc:
                last_error = exc

        if last_error is not None:
            if deadline is not None and anyio.current_time() >= deadline:
                raise ConnectTimeout(
                    "Connection timeout budget exhausted."
                ) from last_error

            raise last_error

        raise ConnectError("No approved destination addresses are available.")

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options=None,
    ):
        raise ConnectError("Unix socket connections are prohibited.")

    async def sleep(self, seconds: float) -> None:
        await self._backend.sleep(seconds)
