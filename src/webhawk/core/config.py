from pydantic import BaseModel, ConfigDict, Field


class HttpConfig(BaseModel):
    """Controls HTTP communication behaviour."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    connect_timeout: float = Field(default=5.0, gt=0, le=30)
    read_timeout: float = Field(default=10.0, gt=0, le=60)
    write_timeout: float = Field(default=10.0, gt=0, le=60)
    pool_timeout: float = Field(default=5.0, gt=0, le=30)

    max_redirects: int = Field(default=3, ge=0, le=5)
    follow_redirects: bool = False

    max_response_bytes: int = Field(
        default=2_000_000,
        gt=0,
        le=10_000_000,
    )

    verify_tls: bool = True

    user_agent: str = Field(
        default="WebHawk/0.1.0",
        min_length=1,
        max_length=200,
    )


class ScanConfig(BaseModel):
    """Controls scan execution limits."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    max_concurrent_targets: int = Field(default=2, ge=1, le=5)

    max_requests_per_target: int = Field(
        default=20,
        ge=1,
        le=50,
    )

    request_delay_seconds: float = Field(
        default=1.0,
        gt=0,
        le=30,
    )


class AppConfig(BaseModel):
    """Central application configuration."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    application_name: str = "WebHawk"
    version: str = "0.1.0"

    http: HttpConfig = Field(default_factory=HttpConfig)
    scan: ScanConfig = Field(default_factory=ScanConfig)


def get_default_config() -> AppConfig:
    """Return the default WebHawk configuration."""

    return AppConfig()
