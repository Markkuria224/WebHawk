import pytest
from pydantic import ValidationError

from webhawk.core.config import (
    AppConfig,
    HttpConfig,
    ScanConfig,
    get_default_config,
)


def test_default_configuration():
    config = get_default_config()

    assert config.application_name == "WebHawk"
    assert config.version == "0.1.0"


def test_default_http_configuration():
    config = HttpConfig()

    assert config.connect_timeout == 5.0
    assert config.read_timeout == 10.0
    assert config.follow_redirects is False
    assert config.verify_tls is True


def test_default_scan_configuration():
    config = ScanConfig()

    assert config.max_concurrent_targets == 2
    assert config.max_requests_per_target == 20
    assert config.request_delay_seconds == 1.0


def test_app_config_creates_nested_defaults():
    config = AppConfig()

    assert isinstance(config.http, HttpConfig)
    assert isinstance(config.scan, ScanConfig)


def test_http_rejects_zero_timeout():
    with pytest.raises(ValidationError):
        HttpConfig(connect_timeout=0)


def test_http_rejects_excessive_timeout():
    with pytest.raises(ValidationError):
        HttpConfig(read_timeout=100)


def test_http_rejects_excessive_redirects():
    with pytest.raises(ValidationError):
        HttpConfig(max_redirects=10)


def test_http_rejects_excessive_response_size():
    with pytest.raises(ValidationError):
        HttpConfig(max_response_bytes=20_000_000)


def test_http_rejects_empty_user_agent():
    with pytest.raises(ValidationError):
        HttpConfig(user_agent="")


def test_scan_rejects_excessive_concurrency():
    with pytest.raises(ValidationError):
        ScanConfig(max_concurrent_targets=10)


def test_scan_rejects_excessive_requests():
    with pytest.raises(ValidationError):
        ScanConfig(max_requests_per_target=100)


def test_scan_rejects_zero_request_delay():
    with pytest.raises(ValidationError):
        ScanConfig(request_delay_seconds=0)


def test_configuration_rejects_unknown_fields():
    with pytest.raises(ValidationError):
        HttpConfig(unrecognized_setting=True)


def test_configuration_is_immutable():
    config = HttpConfig()

    with pytest.raises(ValidationError):
        config.verify_tls = False


def test_default_configuration_uses_safe_redirect_policy():
    config = get_default_config()

    assert config.http.follow_redirects is False
    assert config.http.max_redirects == 3
    assert config.http.verify_tls is True
