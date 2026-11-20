import pytest

from webhawk.core.normalizer import (
    EmbeddedCredentialsError,
    InvalidHostnameError,
    MalformedPortError,
    NormalizationError,
    UnsupportedSchemeError,
    normalize_url,
)


@pytest.mark.parametrize(
    ("input_url", "expected"),
    [
        ("https://example.com", "https://example.com/"),
        ("HTTP://EXAMPLE.COM", "http://example.com/"),
        ("https://example.com:443", "https://example.com/"),
        ("http://example.com:80", "http://example.com/"),
        ("https://example.com:8443", "https://example.com:8443/"),
        ("https://example.com/path", "https://example.com/path"),
        ("https://example.com/path?q=1", "https://example.com/path?q=1"),
        ("https://example.com/path#section", "https://example.com/path"),
        (" https://example.com ", "https://example.com/"),
        ("https://localhost", "https://localhost/"),
        ("https://127.0.0.1", "https://127.0.0.1/"),
        ("https://[::1]", "https://[::1]/"),
        ("https://example.com.", "https://example.com/"),
    ],
)
def test_normalize_valid_urls(input_url, expected):
    assert normalize_url(input_url) == expected


@pytest.mark.parametrize(
    ("input_url", "exception"),
    [
        ("", NormalizationError),
        ("not-a-url", UnsupportedSchemeError),
        ("ftp://example.com", UnsupportedSchemeError),
        ("file:///etc/passwd", UnsupportedSchemeError),
        ("https:///missing-host", InvalidHostnameError),
        ("https://", InvalidHostnameError),
        ("https://user:password@example.com", EmbeddedCredentialsError),
        ("https://example.com:abc", MalformedPortError),
        ("https://example.com:70000", MalformedPortError),
        ("https://example.com:0", MalformedPortError),
        ("https://-invalid.com", InvalidHostnameError),
        ("https://invalid..com", InvalidHostnameError),
        ("https://example.com/path with spaces", NormalizationError),
        ("https://example.com\\@evil.com", NormalizationError),
    ],
)
def test_reject_invalid_urls(input_url, exception):
    with pytest.raises(exception):
        normalize_url(input_url)


def test_reject_non_string_input():
    with pytest.raises(NormalizationError):
        normalize_url(None)
