import ipaddress
import socket
from dataclasses import dataclass
from typing import Callable
from urllib.parse import urlsplit

from webhawk.core.normalizer import normalize_url


class TargetSafetyError(ValueError):
    """Base exception for target safety failures."""


class TargetNotAuthorizedError(TargetSafetyError):
    """Raised when a target has not been explicitly authorized."""


class UnsafeAddressError(TargetSafetyError):
    """Raised when a target resolves to an unsafe address."""


class ResolutionError(TargetSafetyError):
    """Raised when DNS resolution fails or returns no addresses."""


@dataclass(frozen=True)
class TargetPolicy:
    authorized_hosts: frozenset[str] = frozenset()
    authorized_networks: tuple[str, ...] = ()
    allow_loopback: bool = False


@dataclass(frozen=True)
class ApprovedTarget:
    normalized_url: str
    hostname: str
    approved_addresses: tuple[str, ...]


def _default_resolver(hostname: str, port: int) -> list[str]:
    results = socket.getaddrinfo(
        hostname,
        port,
        type=socket.SOCK_STREAM,
    )
    return list({result[4][0] for result in results})


def _normalize_address(address):
    """Normalize IPv4-mapped IPv6 addresses to IPv4."""

    if isinstance(address, ipaddress.IPv6Address):
        if address.ipv4_mapped is not None:
            return address.ipv4_mapped

    return address


def _parse_networks(networks: tuple[str, ...]) -> tuple:
    try:
        parsed = []

        for network in networks:
            value = ipaddress.ip_network(network, strict=False)

            if isinstance(value, ipaddress.IPv6Network):
                if value.network_address.ipv4_mapped is not None:
                    raise ValueError(
                        "IPv4-mapped IPv6 authorization networks are not supported."
                    )

            parsed.append(value)

        return tuple(parsed)

    except ValueError as exc:
        raise TargetSafetyError(
            "Authorization policy contains an invalid or unsupported network."
        ) from exc


def _is_authorized_network(address, networks: tuple) -> bool:
    return any(
        address.version == network.version and address in network
        for network in networks
    )


def _validate_address(address, policy: TargetPolicy, networks: tuple):
    address = _normalize_address(address)

    if address.is_multicast:
        raise UnsafeAddressError("Multicast destinations are prohibited.")

    if address.is_unspecified:
        raise UnsafeAddressError("Unspecified destinations are prohibited.")

    if address.is_link_local:
        raise UnsafeAddressError("Link-local destinations are prohibited.")

    if address.is_loopback:
        if not policy.allow_loopback:
            raise UnsafeAddressError("Loopback access is disabled.")

        if not _is_authorized_network(address, networks):
            raise UnsafeAddressError(
                "Loopback address is outside the authorized networks."
            )

        return address

    if address.is_reserved:
        raise UnsafeAddressError("Reserved destinations are prohibited.")

    if address.is_private:
        if not _is_authorized_network(address, networks):
            raise UnsafeAddressError(
                "Private address is outside the authorized networks."
            )

        return address

    if not address.is_global:
        raise UnsafeAddressError(
            "Target resolves to a non-global, prohibited address."
        )

    return address


def authorize_target(
    url: str,
    policy: TargetPolicy,
    resolver: Callable[[str, int], list[str]] = _default_resolver,
) -> ApprovedTarget:
    """
    Validate authorization and resolve a target safely.

    Approved addresses must be enforced by the HTTP transport.
    This function alone does not prevent DNS rebinding.
    """

    normalized_url = normalize_url(url)
    parsed = urlsplit(normalized_url)
    hostname = parsed.hostname

    if hostname is None:
        raise TargetSafetyError("Target hostname is missing.")

    networks = _parse_networks(policy.authorized_networks)

    try:
        literal_address = ipaddress.ip_address(hostname)
        literal_address = _normalize_address(literal_address)
    except ValueError:
        literal_address = None

    if literal_address is not None:
        if not (
            literal_address.is_global
            and hostname.lower() in {
                host.lower() for host in policy.authorized_hosts
            }
        ):
            if not _is_authorized_network(literal_address, networks):
                raise TargetNotAuthorizedError(
                    "IP address has not been explicitly authorized."
                )

        addresses = [str(literal_address)]

    else:
        authorized_hosts = {
            host.lower() for host in policy.authorized_hosts
        }

        if hostname.lower() not in authorized_hosts:
            raise TargetNotAuthorizedError(
                "Hostname has not been explicitly authorized."
            )

        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        try:
            addresses = resolver(hostname, port)
        except OSError as exc:
            raise ResolutionError("Target DNS resolution failed.") from exc

        if not addresses:
            raise ResolutionError("Target resolved to no addresses.")

    validated_addresses = set()

    for raw_address in addresses:
        try:
            address = ipaddress.ip_address(raw_address)
        except ValueError as exc:
            raise ResolutionError(
                "Resolver returned an invalid IP address."
            ) from exc

        validated = _validate_address(address, policy, networks)
        validated_addresses.add(validated.compressed)

    if not validated_addresses:
        raise ResolutionError("No approved target addresses were returned.")

    return ApprovedTarget(
        normalized_url=normalized_url,
        hostname=hostname,
        approved_addresses=tuple(sorted(validated_addresses)),
    )
