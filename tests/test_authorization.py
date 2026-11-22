import pytest
from datetime import datetime, timezone

from pydantic import ValidationError

from webhawk.core.authorization import AuthorizationProfile


def test_profile_normalizes_and_deduplicates_hosts():
    profile = AuthorizationProfile(
        name="Local Lab",
        authorized_hosts=("LAB.LOCAL", "lab.local."),
    )
    assert profile.authorized_hosts == ("lab.local",)


def test_profile_normalizes_idn_hostname():
    profile = AuthorizationProfile(
        name="IDN Lab",
        authorized_hosts=("m\u00fcnich.example",),
    )
    assert profile.authorized_hosts == ("xn--mnich-kva.example",)


def test_profile_canonicalizes_and_deduplicates_networks():
    profile = AuthorizationProfile(
        name="Network Lab",
        authorized_networks=(
            "192.168.1.10/24",
            "192.168.1.0/24",
        ),
    )
    assert profile.authorized_networks == ("192.168.1.0/24",)


def test_profile_accepts_ipv6_network():
    profile = AuthorizationProfile(
        name="IPv6 Lab",
        authorized_networks=("2001:db8::1/64",),
    )
    assert profile.authorized_networks == ("2001:db8::/64",)


def test_profile_rejects_wildcard_hostname():
    with pytest.raises(ValidationError):
        AuthorizationProfile(
            name="Wildcard",
            authorized_hosts=("*.example.com",),
        )


def test_profile_rejects_invalid_hostname():
    with pytest.raises(ValidationError):
        AuthorizationProfile(
            name="Invalid Host",
            authorized_hosts=("bad host.example",),
        )


def test_profile_rejects_non_string_host():
    with pytest.raises(ValidationError):
        AuthorizationProfile(
            name="Invalid Host",
            authorized_hosts=(123,),
        )


def test_profile_rejects_invalid_network():
    with pytest.raises(ValidationError):
        AuthorizationProfile(
            name="Invalid Network",
            authorized_networks=("192.168.1.999/24",),
        )


def test_profile_rejects_ipv4_mapped_ipv6_network():
    with pytest.raises(ValidationError):
        AuthorizationProfile(
            name="Mapped Network",
            authorized_networks=("::ffff:192.0.2.0/120",),
        )


def test_loopback_requires_authorized_loopback_network():
    with pytest.raises(ValidationError):
        AuthorizationProfile(
            name="Loopback",
            authorized_networks=("192.168.1.0/24",),
            allow_loopback=True,
        )


def test_loopback_is_accepted_with_explicit_network():
    profile = AuthorizationProfile(
        name="Loopback",
        authorized_networks=("127.0.0.0/8",),
        allow_loopback=True,
    )
    assert profile.allow_loopback is True


def test_loopback_is_disabled_by_default():
    profile = AuthorizationProfile(name="Default")
    assert profile.allow_loopback is False


def test_profile_rejects_naive_timestamps():
    with pytest.raises(ValidationError):
        AuthorizationProfile(
            name="Naive Timestamp",
            created_at=datetime(2026, 1, 1),
        )


def test_profile_rejects_updated_timestamp_before_creation():
    with pytest.raises(ValidationError):
        AuthorizationProfile(
            name="Invalid Timeline",
            created_at=datetime(2026, 2, 1, tzinfo=timezone.utc),
            updated_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )


def test_profile_is_immutable():
    profile = AuthorizationProfile(name="Immutable")
    with pytest.raises(ValidationError):
        profile.name = "Changed"


def test_profile_rejects_unexpected_fields():
    with pytest.raises(ValidationError):
        AuthorizationProfile(
            name="Unexpected",
            unknown_field="not allowed",
        )

def test_loopback_rejects_ipv4_network_extending_beyond_loopback():
    with pytest.raises(ValidationError):
        AuthorizationProfile(
            name="Broad IPv4 Loopback",
            authorized_networks=("126.0.0.0/7",),
            allow_loopback=True,
        )


def test_loopback_rejects_ipv6_network_extending_beyond_loopback():
    with pytest.raises(ValidationError):
        AuthorizationProfile(
            name="Broad IPv6 Loopback",
            authorized_networks=("::/1",),
            allow_loopback=True,
        )


def test_loopback_accepts_specific_ipv4_subnet():
    profile = AuthorizationProfile(
        name="Specific IPv4 Loopback",
        authorized_networks=("127.0.0.0/9",),
        allow_loopback=True,
    )

    assert profile.allow_loopback is True


def test_loopback_accepts_ipv6_loopback_address():
    profile = AuthorizationProfile(
        name="IPv6 Loopback",
        authorized_networks=("::1/128",),
        allow_loopback=True,
    )

    assert profile.allow_loopback is True


def test_profile_rejects_whitespace_only_name():
    with pytest.raises(ValidationError):
        AuthorizationProfile(name="   ")


def test_profile_accepts_none_for_authorized_hosts():
    profile = AuthorizationProfile(
        name="No Hosts",
        authorized_hosts=None,
    )

    assert profile.authorized_hosts == ()


def test_profile_rejects_invalid_hosts_collection():
    with pytest.raises(ValidationError):
        AuthorizationProfile(
            name="Invalid Hosts",
            authorized_hosts="example.com",
        )


def test_profile_accepts_none_for_authorized_networks():
    profile = AuthorizationProfile(
        name="No Networks",
        authorized_networks=None,
    )

    assert profile.authorized_networks == ()


def test_profile_rejects_invalid_networks_collection():
    with pytest.raises(ValidationError):
        AuthorizationProfile(
            name="Invalid Networks",
            authorized_networks="192.168.1.0/24",
        )


def test_profile_rejects_non_string_network():
    with pytest.raises(ValidationError):
        AuthorizationProfile(
            name="Non-string Network",
            authorized_networks=(123,),
        )
