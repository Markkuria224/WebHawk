import anyio
import pytest

from httpcore import ConnectError, ConnectTimeout

from webhawk.core.safety import (
    TargetNotAuthorizedError,
    TargetPolicy,
)
from webhawk.core.transport.connection import (
    DeadlineAwareNetworkStream,
    IPPinnedNetworkBackend,
)


TARGET_URL = "https://lab.example.com"

POLICY = TargetPolicy(
    authorized_hosts=frozenset({"lab.example.com"}),
)


def fake_resolver(addresses):
    def resolve(hostname, port):
        return addresses
    return resolve


class FakeBackend:
    def __init__(self, failures=None):
        self.failures = list(failures or [])
        self.connections = []
        self.sleep_calls = []

    async def connect_tcp(
        self,
        host,
        port,
        timeout=None,
        local_address=None,
        socket_options=None,
    ):
        self.connections.append({
            "host": host,
            "port": port,
            "timeout": timeout,
            "local_address": local_address,
            "socket_options": socket_options,
        })

        if self.failures:
            failure = self.failures.pop(0)
            if failure is not None:
                raise failure

        return "connected"

    async def connect_unix_socket(
        self, path, timeout=None, socket_options=None
    ):
        raise AssertionError("Underlying Unix socket method must not be called.")

    async def sleep(self, seconds):
        self.sleep_calls.append(seconds)


def make_backend(backend=None, resolver=None):
    if resolver is None:
        resolver = fake_resolver([
            "93.184.216.34",
            "1.1.1.1",
        ])

    return IPPinnedNetworkBackend(
        TARGET_URL,
        POLICY,
        backend=backend or FakeBackend(),
        resolver=resolver,
    )


def test_authorizes_target_during_construction():
    pinned = make_backend()

    assert pinned._target.hostname == "lab.example.com"
    assert set(pinned._target.approved_addresses) == {
        "93.184.216.34",
        "1.1.1.1",
    }


def test_rejects_unauthorized_target_during_construction():
    policy = TargetPolicy()

    with pytest.raises(TargetNotAuthorizedError):
        IPPinnedNetworkBackend(
            TARGET_URL,
            policy,
            resolver=fake_resolver(["93.184.216.34"]),
        )


def test_connects_only_to_approved_ip_addresses():
    backend = FakeBackend()
    pinned = make_backend(backend)

    result = anyio.run(
        pinned.connect_tcp,
        "lab.example.com",
        443,
    )

    assert result == "connected"
    assert len(backend.connections) == 1
    assert backend.connections[0]["host"] in {
        "93.184.216.34",
        "1.1.1.1",
    }


def test_rejects_unapproved_hostname():
    backend = FakeBackend()
    pinned = make_backend(backend)

    with pytest.raises(ConnectError):
        anyio.run(
            pinned.connect_tcp,
            "attacker.example",
            443,
        )

    assert backend.connections == []


def test_rejects_unapproved_port():
    backend = FakeBackend()
    pinned = make_backend(backend)

    with pytest.raises(ConnectError):
        anyio.run(
            pinned.connect_tcp,
            "lab.example.com",
            8080,
        )

    assert backend.connections == []


@pytest.mark.parametrize(
    "failure",
    [
        ConnectError("Connection refused"),
        ConnectTimeout("Connection timed out"),
    ],
)
def test_falls_back_only_to_another_approved_ip(failure):
    backend = FakeBackend(failures=[failure, None])
    pinned = make_backend(backend)

    result = anyio.run(
        pinned.connect_tcp,
        "lab.example.com",
        443,
    )

    assert result == "connected"
    assert len(backend.connections) == 2

    attempted = {item["host"] for item in backend.connections}

    assert attempted == {"1.1.1.1", "93.184.216.34"}


def test_raises_after_all_approved_addresses_fail():
    backend = FakeBackend(
        failures=[
            ConnectError("First address failed"),
            ConnectTimeout("Second address timed out"),
        ]
    )
    pinned = make_backend(backend)

    with pytest.raises(ConnectTimeout):
        anyio.run(
            pinned.connect_tcp,
            "lab.example.com",
            443,
        )

    assert len(backend.connections) == 2


def test_rejects_unix_socket_connections():
    backend = FakeBackend()
    pinned = make_backend(backend)

    with pytest.raises(ConnectError):
        anyio.run(
            pinned.connect_unix_socket,
            "/tmp/test.sock",
        )

    assert backend.connections == []


def test_delegates_sleep():
    backend = FakeBackend()
    pinned = make_backend(backend)

    anyio.run(pinned.sleep, 0.5)

    assert backend.sleep_calls == [0.5]


def test_rejects_old_approved_target_constructor_pattern():
    from webhawk.core.safety import ApprovedTarget

    fabricated = ApprovedTarget(
        normalized_url=TARGET_URL,
        hostname="lab.example.com",
        approved_addresses=("203.0.113.10",),
    )

    with pytest.raises((TypeError, ValueError)):
        IPPinnedNetworkBackend(fabricated, FakeBackend())


def test_duplicate_resolver_addresses_are_deduplicated():
    backend = FakeBackend()
    pinned = make_backend(
        backend,
        fake_resolver([
            "93.184.216.34",
            "93.184.216.34",
            "1.1.1.1",
        ]),
    )

    assert len(pinned._target.approved_addresses) == 2


@pytest.mark.parametrize(
    ("hostname", "expected"),
    [
        ("LAB.EXAMPLE.COM", "lab.example.com"),
        ("lab.example.com.", "lab.example.com"),
        ("lab.example.com", "lab.example.com"),
        ("2606:4700:4700::1111", "2606:4700:4700::1111"),
    ],
)
def test_normalizes_hostnames(hostname, expected):
    assert (
        IPPinnedNetworkBackend._normalize_hostname(hostname)
        == expected
    )


def test_accepts_case_and_trailing_dot_hostname_variations():
    backend = FakeBackend()
    pinned = make_backend(backend)

    result = anyio.run(
        pinned.connect_tcp,
        "LAB.EXAMPLE.COM.",
        443,
    )

    assert result == "connected"
    assert len(backend.connections) == 1


def test_supports_ipv6_approved_destinations():
    backend = FakeBackend()

    pinned = make_backend(
        backend,
        fake_resolver(["2606:4700:4700::1111"]),
    )

    result = anyio.run(
        pinned.connect_tcp,
        "lab.example.com",
        443,
    )

    assert result == "connected"
    assert backend.connections[0]["host"] == "2606:4700:4700::1111"


def test_connection_cancellation_does_not_trigger_fallback():
    import asyncio

    class BlockingBackend(FakeBackend):
        async def connect_tcp(
            self,
            host,
            port,
            timeout=None,
            local_address=None,
            socket_options=None,
        ):
            self.connections.append({
                "host": host,
                "port": port,
            })
            await asyncio.Event().wait()

    backend = BlockingBackend()
    pinned = make_backend(backend)

    async def run_test():
        task = asyncio.create_task(
            pinned.connect_tcp("lab.example.com", 443)
        )

        await asyncio.sleep(0)
        task.cancel()

        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(run_test())

    assert len(backend.connections) == 1


def test_fallback_attempts_share_one_timeout_budget():
    import anyio

    class SlowFailingBackend(FakeBackend):
        async def connect_tcp(
            self,
            host,
            port,
            timeout=None,
            local_address=None,
            socket_options=None,
        ):
            self.connections.append({
                "host": host,
                "port": port,
                "timeout": timeout,
            })

            if len(self.connections) == 1:
                await anyio.sleep(0.05)
                raise ConnectError("First address failed.")

            return "connected"

    backend = SlowFailingBackend()
    pinned = make_backend(backend)

    async def run_test():
        return await pinned.connect_tcp(
            "lab.example.com",
            443,
            timeout=1.0,
        )

    result = anyio.run(run_test)

    assert result.__class__.__name__ == "DeadlineAwareNetworkStream"
    assert result._stream == "connected"
    assert len(backend.connections) == 2
    assert backend.connections[0]["timeout"] == pytest.approx(1.0, abs=0.001)
    assert backend.connections[1]["timeout"] < 1.0
    assert backend.connections[1]["timeout"] > 0


def test_exhausted_timeout_budget_prevents_fallback():
    import anyio

    class ExhaustingBackend(FakeBackend):
        async def connect_tcp(
            self,
            host,
            port,
            timeout=None,
            local_address=None,
            socket_options=None,
        ):
            self.connections.append({
                "host": host,
                "port": port,
                "timeout": timeout,
            })

            await anyio.sleep(0.05)
            raise ConnectError("Connection attempt exhausted its budget.")

    backend = ExhaustingBackend()
    pinned = make_backend(backend)

    async def run_test():
        with pytest.raises(ConnectTimeout):
            await pinned.connect_tcp(
                "lab.example.com",
                443,
                timeout=0.01,
            )

    anyio.run(run_test)

    assert len(backend.connections) == 1


class FakeTLSStream:
    def __init__(self, behavior=None):
        self.behavior = behavior
        self.start_tls_calls = []

    async def read(self, max_bytes, timeout=None):
        return b""

    async def write(self, buffer, timeout=None):
        pass

    async def aclose(self):
        pass

    def get_extra_info(self, info):
        return None

    async def start_tls(
        self,
        ssl_context,
        server_hostname=None,
        timeout=None,
    ):
        self.start_tls_calls.append({
            "ssl_context": ssl_context,
            "server_hostname": server_hostname,
            "timeout": timeout,
        })

        if self.behavior is not None:
            return await self.behavior(timeout)

        return self


def test_tls_receives_only_remaining_connection_timeout():
    async def run_test():
        deadline = anyio.current_time() + 1.0
        underlying = FakeTLSStream()

        wrapper = DeadlineAwareNetworkStream(
            underlying,
            deadline,
        )

        await anyio.sleep(0.05)

        await wrapper.start_tls(
            ssl_context=None,
            server_hostname="lab.example.com",
            timeout=1.0,
        )

        received_timeout = underlying.start_tls_calls[0]["timeout"]

        assert received_timeout < 1.0
        assert received_timeout > 0.80

    anyio.run(run_test)


def test_expired_deadline_prevents_tls_negotiation():
    async def run_test():
        underlying = FakeTLSStream()

        wrapper = DeadlineAwareNetworkStream(
            underlying,
            anyio.current_time() - 0.01,
        )

        with pytest.raises(ConnectTimeout):
            await wrapper.start_tls(
                ssl_context=None,
                server_hostname="lab.example.com",
                timeout=1.0,
            )

        assert underlying.start_tls_calls == []

    anyio.run(run_test)


def test_tls_connect_timeout_propagates():
    async def run_test(timeout):
        raise ConnectTimeout("TLS negotiation timed out.")

    async def main():
        underlying = FakeTLSStream(behavior=run_test)

        wrapper = DeadlineAwareNetworkStream(
            underlying,
            anyio.current_time() + 1.0,
        )

        with pytest.raises(ConnectTimeout, match="TLS negotiation"):
            await wrapper.start_tls(
                ssl_context=None,
                server_hostname="lab.example.com",
                timeout=1.0,
            )

        assert len(underlying.start_tls_calls) == 1

    anyio.run(main)


def test_cancellation_during_tls_propagates():
    async def run_test(timeout):
        await anyio.sleep_forever()

    async def main():
        underlying = FakeTLSStream(behavior=run_test)

        wrapper = DeadlineAwareNetworkStream(
            underlying,
            anyio.current_time() + 5.0,
        )

        with anyio.move_on_after(0.05) as scope:
            await wrapper.start_tls(
                ssl_context=None,
                server_hostname="lab.example.com",
                timeout=5.0,
            )

        assert scope.cancel_called
        assert len(underlying.start_tls_calls) == 1

    anyio.run(main)
