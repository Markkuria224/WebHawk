import pytest

from webhawk.core.safety import (
    ResolutionError,
    TargetNotAuthorizedError,
    TargetPolicy,
    UnsafeAddressError,
    authorize_target,
)


def fake_resolver(addresses):
    def resolve(hostname, port):
        return addresses
    return resolve


def test_unauthorized_hostname_is_rejected():
    policy = TargetPolicy()

    with pytest.raises(TargetNotAuthorizedError):
        authorize_target(
            "https://example.com",
            policy,
        )


def test_authorized_public_hostname():
    policy = TargetPolicy(
        authorized_hosts=frozenset({"example.com"}),
    )

    result = authorize_target(
        "https://example.com",
        policy,
        resolver=fake_resolver(["93.184.216.34"]),
    )

    assert result.hostname == "example.com"
    assert result.approved_addresses == ("93.184.216.34",)


def test_unauthorized_public_ip_is_rejected():
    with pytest.raises(TargetNotAuthorizedError):
        authorize_target(
            "https://93.184.216.34",
            TargetPolicy(),
        )


def test_authorized_private_network():
    policy = TargetPolicy(
        authorized_hosts=frozenset({"lab.local"}),
        authorized_networks=("192.168.1.0/24",),
    )

    result = authorize_target(
        "http://lab.local",
        policy,
        resolver=fake_resolver(["192.168.1.10"]),
    )

    assert result.approved_addresses == ("192.168.1.10",)


def test_private_address_outside_authorized_network_is_rejected():
    policy = TargetPolicy(
        authorized_hosts=frozenset({"lab.local"}),
        authorized_networks=("192.168.1.0/24",),
    )

    with pytest.raises(UnsafeAddressError):
        authorize_target(
            "http://lab.local",
            policy,
            resolver=fake_resolver(["10.0.0.5"]),
        )


def test_loopback_requires_explicit_permission():
    policy = TargetPolicy(
        authorized_networks=("127.0.0.0/8",),
        allow_loopback=False,
    )

    with pytest.raises(UnsafeAddressError):
        authorize_target(
            "http://127.0.0.1",
            policy,
        )


def test_loopback_allowed_when_explicitly_enabled():
    policy = TargetPolicy(
        authorized_networks=("127.0.0.0/8",),
        allow_loopback=True,
    )

    result = authorize_target(
        "http://127.0.0.1",
        policy,
    )

    assert result.approved_addresses == ("127.0.0.1",)


def test_mixed_public_and_private_dns_results_are_rejected():
    policy = TargetPolicy(
        authorized_hosts=frozenset({"example.com"}),
    )

    with pytest.raises(UnsafeAddressError):
        authorize_target(
            "https://example.com",
            policy,
            resolver=fake_resolver([
                "93.184.216.34",
                "192.168.1.10",
            ]),
        )


def test_empty_dns_result_is_rejected():
    policy = TargetPolicy(
        authorized_hosts=frozenset({"example.com"}),
    )

    with pytest.raises(ResolutionError):
        authorize_target(
            "https://example.com",
            policy,
            resolver=fake_resolver([]),
        )


def test_dns_resolution_failure_is_reported():
    def failing_resolver(hostname, port):
        raise OSError("DNS unavailable")

    policy = TargetPolicy(
        authorized_hosts=frozenset({"example.com"}),
    )

    with pytest.raises(ResolutionError):
        authorize_target(
            "https://example.com",
            policy,
            resolver=failing_resolver,
        )


def test_multiple_safe_addresses_are_preserved():
    policy = TargetPolicy(
        authorized_hosts=frozenset({"example.com"}),
    )

    result = authorize_target(
        "https://example.com",
        policy,
        resolver=fake_resolver([
            "93.184.216.34",
            "1.1.1.1",
        ]),
    )

    assert len(result.approved_addresses) == 2
