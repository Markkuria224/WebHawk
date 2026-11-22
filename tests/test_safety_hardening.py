import pytest

from webhawk.core.safety import (
    TargetNotAuthorizedError,
    TargetPolicy,
    TargetSafetyError,
    ResolutionError,
    UnsafeAddressError,
    authorize_target,
)


def fake_resolver(addresses):
    def resolve(hostname, port):
        return addresses
    return resolve


@pytest.mark.parametrize(
    "address",
    [
        "169.254.1.1",
        "224.0.0.1",
        "0.0.0.0",
        "255.255.255.255",
        "fe80::1",
        "ff02::1",
        "::",
    ],
)
def test_prohibited_addresses_are_rejected(address):
    policy = TargetPolicy(
        authorized_hosts=frozenset({"lab.example"}),
        authorized_networks=("0.0.0.0/0", "::/0"),
        allow_loopback=True,
    )

    with pytest.raises(UnsafeAddressError):
        authorize_target(
            "https://lab.example",
            policy,
            resolver=fake_resolver([address]),
        )


def test_ipv4_mapped_loopback_requires_loopback_permission():
    policy = TargetPolicy(
        authorized_networks=("127.0.0.0/8",),
        allow_loopback=False,
    )

    with pytest.raises(UnsafeAddressError):
        authorize_target(
            "http://[::ffff:127.0.0.1]",
            policy,
        )


def test_ipv4_mapped_loopback_is_normalized():
    policy = TargetPolicy(
        authorized_networks=("127.0.0.0/8",),
        allow_loopback=True,
    )

    result = authorize_target(
        "http://[::ffff:127.0.0.1]",
        policy,
    )

    assert result.approved_addresses == ("127.0.0.1",)


def test_loopback_requires_network_authorization():
    policy = TargetPolicy(
        authorized_networks=(),
        allow_loopback=True,
    )

    with pytest.raises(TargetNotAuthorizedError):
        authorize_target(
            "http://127.0.0.1",
            policy,
        )


def test_invalid_network_policy_is_rejected():
    policy = TargetPolicy(
        authorized_networks=("not-a-network",),
    )

    with pytest.raises(TargetSafetyError):
        authorize_target(
            "https://example.com",
            policy,
            resolver=fake_resolver(["93.184.216.34"]),
        )


def test_duplicate_dns_answers_are_deduplicated():
    policy = TargetPolicy(
        authorized_hosts=frozenset({"example.com"}),
    )

    result = authorize_target(
        "https://example.com",
        policy,
        resolver=fake_resolver([
            "93.184.216.34",
            "93.184.216.34",
            "1.1.1.1",
        ]),
    )

    assert len(result.approved_addresses) == 2


def test_mapped_private_ipv6_requires_ipv4_network_authorization():
    policy = TargetPolicy(
        authorized_hosts=frozenset({"lab.example"}),
        authorized_networks=("192.168.1.0/24",),
    )

    result = authorize_target(
        "https://lab.example",
        policy,
        resolver=fake_resolver(["::ffff:192.168.1.10"]),
    )

    assert result.approved_addresses == ("192.168.1.10",)


def test_mapped_private_ipv6_cannot_bypass_network_authorization():
    policy = TargetPolicy(
        authorized_hosts=frozenset({"lab.example"}),
        authorized_networks=("10.0.0.0/8",),
    )

    with pytest.raises(UnsafeAddressError):
        authorize_target(
            "https://lab.example",
            policy,
            resolver=fake_resolver(["::ffff:192.168.1.10"]),
        )


def test_default_resolver_uses_getaddrinfo_and_deduplicates(monkeypatch):
    import socket

    from webhawk.core.safety import authorize_target

    calls = []

    def fake_getaddrinfo(hostname, port, type):
        calls.append((hostname, port, type))

        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.1.1.1", port)),
        ]

    monkeypatch.setattr(
        "webhawk.core.safety.socket.getaddrinfo",
        fake_getaddrinfo,
    )

    policy = TargetPolicy(
        authorized_hosts=frozenset({"example.com"}),
    )

    result = authorize_target(
        "https://example.com:8443",
        policy,
    )

    assert calls == [
        ("example.com", 8443, socket.SOCK_STREAM)
    ]

    assert set(result.approved_addresses) == {
        "93.184.216.34",
        "1.1.1.1",
    }


def test_ipv4_mapped_ipv6_authorization_network_is_rejected():
    policy = TargetPolicy(
        authorized_networks=("::ffff:192.168.1.0/120",),
    )

    with pytest.raises(TargetSafetyError):
        authorize_target(
            "https://example.com",
            policy,
        )


def test_loopback_outside_authorized_network_is_rejected():
    policy = TargetPolicy(
        authorized_hosts=frozenset({"lab.example"}),
        authorized_networks=("127.0.0.1/32",),
        allow_loopback=True,
    )

    with pytest.raises(UnsafeAddressError):
        authorize_target(
            "http://lab.example",
            policy,
            resolver=fake_resolver(["127.0.0.2"]),
        )


def test_invalid_resolver_address_is_rejected():
    policy = TargetPolicy(
        authorized_hosts=frozenset({"example.com"}),
    )

    with pytest.raises(ResolutionError, match="invalid IP address"):
        authorize_target(
            "https://example.com",
            policy,
            resolver=fake_resolver(["not-an-ip-address"]),
        )


def test_public_ip_literal_can_be_explicitly_authorized():
    policy = TargetPolicy(
        authorized_hosts=frozenset({"93.184.216.34"}),
    )

    result = authorize_target(
        "https://93.184.216.34",
        policy,
    )

    assert result.approved_addresses == ("93.184.216.34",)


def test_hostname_authorization_is_case_insensitive():
    policy = TargetPolicy(
        authorized_hosts=frozenset({"EXAMPLE.COM"}),
    )

    result = authorize_target(
        "https://example.com",
        policy,
        resolver=fake_resolver(["93.184.216.34"]),
    )

    assert result.hostname == "example.com"


def test_shared_address_space_is_rejected():
    policy = TargetPolicy(
        authorized_hosts=frozenset({"lab.example"}),
    )

    with pytest.raises(UnsafeAddressError):
        authorize_target(
            "https://lab.example",
            policy,
            resolver=fake_resolver(["100.64.0.1"]),
        )


def test_missing_hostname_is_rejected(monkeypatch):
    monkeypatch.setattr(
        "webhawk.core.safety.normalize_url",
        lambda url: "http:///",
    )

    with pytest.raises(TargetSafetyError, match="hostname is missing"):
        authorize_target(
            "http://example.com",
            TargetPolicy(),
        )
