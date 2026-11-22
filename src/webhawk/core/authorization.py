import ipaddress
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from webhawk.core.normalizer import normalize_hostname


LOOPBACK_NETWORKS = (
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
)


class AuthorizationProfile(BaseModel):
    """Validated, immutable authorization scope for WebHawk assessments."""

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        str_strip_whitespace=True,
    )

    name: str = Field(min_length=1, max_length=80)
    authorized_hosts: tuple[str, ...] = ()
    authorized_networks: tuple[str, ...] = ()
    allow_loopback: bool = False
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        value = value.strip()

        if not value:
            raise ValueError("Profile name cannot be empty.")

        return value

    @field_validator("authorized_hosts", mode="before")
    @classmethod
    def validate_hosts(cls, value: Any) -> tuple[str, ...]:
        if value is None:
            return ()

        if not isinstance(value, (list, tuple, set, frozenset)):
            raise ValueError("Authorized hosts must be a collection.")

        normalized = set()

        for host in value:
            if not isinstance(host, str):
                raise ValueError("Every authorized host must be a string.")

            normalized.add(normalize_hostname(host.strip()))

        return tuple(sorted(normalized))

    @field_validator("authorized_networks", mode="before")
    @classmethod
    def validate_networks(cls, value: Any) -> tuple[str, ...]:
        if value is None:
            return ()

        if not isinstance(value, (list, tuple, set, frozenset)):
            raise ValueError("Authorized networks must be a collection.")

        normalized = set()

        for network in value:
            if not isinstance(network, str):
                raise ValueError("Every authorized network must be a string.")

            try:
                parsed = ipaddress.ip_network(network.strip(), strict=False)
            except ValueError as exc:
                raise ValueError(
                    "An authorized network is invalid."
                ) from exc

            if isinstance(parsed, ipaddress.IPv6Network):
                if parsed.network_address.ipv4_mapped is not None:
                    raise ValueError(
                        "IPv4-mapped IPv6 authorization networks are unsupported."
                    )

            normalized.add(str(parsed))

        return tuple(sorted(normalized))

    @field_validator("created_at", "updated_at")
    @classmethod
    def validate_timestamps(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Profile timestamps must be timezone-aware.")

        return value

    @model_validator(mode="after")
    def validate_loopback_scope(self):
        if self.allow_loopback:
            authorized_networks = tuple(
                ipaddress.ip_network(network)
                for network in self.authorized_networks
            )

            has_loopback_network = any(
                network.version == loopback.version
                and network.subnet_of(loopback)
                for network in authorized_networks
                for loopback in LOOPBACK_NETWORKS
            )

            if not has_loopback_network:
                raise ValueError(
                    "Loopback permission requires an authorized network "
                    "entirely contained within a loopback range."
                )

        if self.updated_at < self.created_at:
            raise ValueError(
                "Updated timestamp cannot be earlier than creation timestamp."
            )

        return self
