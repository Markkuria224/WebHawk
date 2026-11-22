import pytest

from webhawk.analyzers.cookies import (
    MAX_COOKIE_HEADER_LENGTH,
    ParsedCookie,
    _extract_set_cookie_headers,
    _parse_max_age,
    _parse_set_cookie,
    _valid_cookie_name,
    _valid_domain_attribute,
    _valid_expires_attribute,
    analyze_cookies,
)

from webhawk.core.models import (
    FindingClassification,
    Severity,
)


def test_parses_valid_cookie():
    result = _parse_set_cookie(
        b"session=secret; Secure; HttpOnly; SameSite=Lax"
    )

    assert isinstance(result, ParsedCookie)
    assert result.name == "session"
    assert result.secure is True
    assert result.httponly is True
    assert result.samesite == "lax"


def test_cookie_value_is_not_retained():
    secret = b"SUPER_SECRET_SESSION_TOKEN_928374"

    result = _parse_set_cookie(
        b"session=" + secret + b"; Secure; HttpOnly"
    )

    assert result is not None
    assert secret.decode() not in repr(result)
    assert secret.decode() not in str(result)


def test_cookie_name_validation():
    assert _valid_cookie_name("session")
    assert _valid_cookie_name("__Host-session")
    assert _valid_cookie_name("user.id")
    assert not _valid_cookie_name("")
    assert not _valid_cookie_name("invalid name")
    assert not _valid_cookie_name("invalid;name")
    assert not _valid_cookie_name("a" * 257)


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        (b"session=value; Secure", True),
        (b"session=value; secure", True),
        (b"session=value; Secure=true", True),
        (b"session=value; HttpOnly", True),
        (b"session=value; HttpOnly=yes", True),
    ],
)
def test_security_flag_attributes(header, expected):
    result = _parse_set_cookie(header)

    assert result is not None

    if b"Secure" in header or b"secure" in header:
        assert result.secure is expected

    if b"HttpOnly" in header:
        assert result.httponly is expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (b"Strict", "strict"),
        (b"Lax", "lax"),
        (b"None", "none"),
        (b"STRICT", "strict"),
        (b"invalid", None),
        (b"", None),
    ],
)
def test_samesite_validation(value, expected):
    result = _parse_set_cookie(
        b"session=value; SameSite=" + value
    )

    assert result is not None
    assert result.samesite == expected

    if expected is None:
        assert "samesite" in result.invalid_attributes


def test_missing_samesite_is_none():
    result = _parse_set_cookie(b"session=value; Secure")

    assert result is not None
    assert result.samesite is None


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("example.com", "example.com"),
        ("sub.example.com", "sub.example.com"),
        (".example.com", "example.com"),
        ("..example.com", None),
        ("...example.com", None),
        ("LOCALHOST", "localhost"),
        ("-invalid.com", None),
        ("invalid-.com", None),
        ("example..com", None),
        ("", None),
        ("a" * 254, None),
        ("exämple.com", None),
    ],
)
def test_domain_validation(value, expected):
    assert _valid_domain_attribute(value) == expected


def test_invalid_domain_is_recorded():
    result = _parse_set_cookie(
        b"session=value; Domain=-invalid.com"
    )

    assert result is not None
    assert result.domain is None
    assert "domain" in result.invalid_attributes


def test_valid_domain_is_normalized():
    result = _parse_set_cookie(
        b"session=value; Domain=.Example.COM"
    )

    assert result is not None
    assert result.domain == "example.com"
    assert "domain" not in result.invalid_attributes


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("Wed, 21 Oct 2015 07:28:00 GMT", True),
        ("Thu, 01 Jan 1970 00:00:00 GMT", True),
        ("not-a-date", False),
        ("", False),
        ("Wed, 21 Oct 2015 07:28:00", False),
    ],
)
def test_expires_validation(value, expected):
    assert _valid_expires_attribute(value) is expected


def test_expires_attribute_is_recorded_without_raw_value():
    result = _parse_set_cookie(
        b"session=value; Expires=Wed, 21 Oct 2015 07:28:00 GMT"
    )

    assert result is not None
    assert result.expires_present is True


@pytest.mark.parametrize(
    ("value", "expected", "valid"),
    [
        ("0", 0, True),
        ("3600", 3600, True),
        ("-3600", -3600, True),
        ("0003600", 3600, True),
        ("-0003600", -3600, True),
        ("0000", 0, True),
        ("", None, False),
        ("invalid", None, False),
        ("999999999999999999999", None, False),
    ],
)
def test_max_age_parser(value, expected, valid):
    assert _parse_max_age(value) == (expected, valid)


def test_max_age_handles_thousands_of_leading_zeroes():
    result = _parse_set_cookie(
        b"session=value; Max-Age=" + (b"0" * 5000)
    )

    assert result is not None
    assert result.max_age == 0
    assert "max-age" not in result.invalid_attributes


def test_max_age_rejects_extremely_large_integer():
    result = _parse_set_cookie(
        b"session=value; Max-Age=999999999999999999999999"
    )

    assert result is not None
    assert result.max_age is None
    assert "max-age" in result.invalid_attributes


def test_valid_path_is_retained():
    result = _parse_set_cookie(
        b"session=value; Path=/account"
    )

    assert result is not None
    assert result.path == "/account"


def test_root_path_is_retained():
    result = _parse_set_cookie(
        b"session=value; Path=/"
    )

    assert result is not None
    assert result.path == "/"


def test_missing_path_is_none():
    result = _parse_set_cookie(b"session=value; Secure")

    assert result is not None
    assert result.path is None


def test_invalid_path_is_recorded():
    result = _parse_set_cookie(
        b"session=value; Path=account"
    )

    assert result is not None
    assert result.path is None
    assert "path" in result.invalid_attributes


def test_duplicate_attributes_are_detected():
    result = _parse_set_cookie(
        b"session=value; Secure; Secure; HttpOnly"
    )

    assert result is not None
    assert result.duplicate_attributes == ("secure",)


def test_last_duplicate_attribute_value_is_preserved():
    result = _parse_set_cookie(
        b"session=value; SameSite=Lax; SameSite=None"
    )

    assert result is not None
    assert result.samesite == "none"
    assert result.duplicate_attributes == ("samesite",)


@pytest.mark.parametrize(
    ("header", "attribute", "expected"),
    [
        (
            b"session=value; Path=/; Path=/admin",
            "path",
            "/admin",
        ),
        (
            b"session=value; Domain=example.com; Domain=sub.example.com",
            "domain",
            "sub.example.com",
        ),
        (
            b"session=value; Max-Age=60; Max-Age=120",
            "max_age",
            120,
        ),
    ],
)
def test_last_duplicate_scope_and_lifetime_attributes_are_used(
    header,
    attribute,
    expected,
):
    result = _parse_set_cookie(header)

    assert result is not None
    assert getattr(result, attribute) == expected
    assert attribute.replace("_", "-") in result.duplicate_attributes


def test_unknown_attribute_names_are_preserved():
    result = _parse_set_cookie(
        b"session=value; Priority=High; Partitioned"
    )

    assert result is not None
    assert result.unknown_attributes == (
        "partitioned",
        "priority",
    )


def test_unknown_attribute_values_are_not_retained():
    secret = "UNKNOWN_ATTRIBUTE_SECRET_123"

    result = _parse_set_cookie(
        f"session=value; CustomAttribute={secret}".encode()
    )

    assert result is not None
    assert secret not in repr(result)


def test_extracts_set_cookie_headers_case_insensitively():
    headers = (
        (b"content-type", b"text/html"),
        (b"Set-Cookie", b"session=one; Secure"),
        (b"set-cookie", b"theme=dark; HttpOnly"),
    )

    result = _extract_set_cookie_headers(headers)

    assert result == (
        b"session=one; Secure",
        b"theme=dark; HttpOnly",
    )


def test_extraction_preserves_duplicate_header_order():
    headers = [
        (b"Set-Cookie", b"session=one"),
        (b"Set-Cookie", b"session=two"),
    ]

    result = _extract_set_cookie_headers(headers)

    assert result == (
        b"session=one",
        b"session=two",
    )


def test_extraction_ignores_malformed_header_items():
    headers = [
        (b"Set-Cookie", b"session=one"),
        ("Set-Cookie", b"invalid"),
        (b"Set-Cookie", "invalid"),
        (b"Content-Type", b"text/html"),
    ]

    result = _extract_set_cookie_headers(headers)

    assert result == (b"session=one",)


def test_extraction_rejects_non_sequence():
    with pytest.raises(TypeError):
        _extract_set_cookie_headers(None)


@pytest.mark.parametrize(
    "value",
    [
        b"",
        b"session",
        b"=value",
        b"invalid name=value",
        b"session=value\x00",
        b"session=value\x7f",
        b"session=value\nInjected=header",
    ],
)
def test_rejects_malformed_cookie_headers(value):
    assert _parse_set_cookie(value) is None


def test_rejects_oversized_cookie_header():
    value = (
        b"session="
        + b"a" * MAX_COOKIE_HEADER_LENGTH
    )

    assert _parse_set_cookie(value) is None


def test_rejects_non_bytes_cookie_header():
    assert _parse_set_cookie("session=value") is None
    assert _parse_set_cookie(None) is None


def test_empty_cookie_value_is_allowed():
    result = _parse_set_cookie(b"session=; Secure")

    assert result is not None
    assert result.name == "session"
    assert result.secure is True


def test_cookie_with_multiple_attributes():
    result = _parse_set_cookie(
        b"session=secret; "
        b"Secure; HttpOnly; SameSite=Strict; "
        b"Domain=example.com; Path=/; "
        b"Max-Age=3600"
    )

    assert result is not None
    assert result.secure is True
    assert result.httponly is True
    assert result.samesite == "strict"
    assert result.domain == "example.com"
    assert result.path == "/"
    assert result.max_age == 3600
    assert result.invalid_attributes == ()
    assert result.duplicate_attributes == ()



# ---------------------------------------------------------------------------
# Cookie security analyzer tests
# ---------------------------------------------------------------------------


def _analyze_cookie(
    cookie_header: bytes,
    response_url: str = "https://example.com/account",
):
    return analyze_cookies(
        response_url=response_url,
        raw_headers=[
            (b"set-cookie", cookie_header),
        ],
    )


def _finding_by_title(findings, title):
    return next(
        finding for finding in findings
        if finding.title == title
    )


def test_https_cookie_missing_security_attributes():
    findings = _analyze_cookie(b"session=secret")

    titles = {finding.title for finding in findings}

    assert "Cookie missing Secure attribute" in titles
    assert "Cookie missing HttpOnly attribute" in titles
    assert "Cookie missing SameSite attribute" in titles


def test_http_cookie_does_not_receive_missing_secure_finding():
    findings = _analyze_cookie(
        b"session=secret",
        response_url="http://example.com/account",
    )

    assert "Cookie missing Secure attribute" not in {
        finding.title for finding in findings
    }


def test_secure_cookie_does_not_receive_missing_secure_finding():
    findings = _analyze_cookie(
        b"session=secret; Secure; HttpOnly; SameSite=Lax"
    )

    assert "Cookie missing Secure attribute" not in {
        finding.title for finding in findings
    }


def test_samesite_none_without_secure_is_high_severity():
    findings = _analyze_cookie(
        b"session=secret; SameSite=None"
    )

    finding = _finding_by_title(
        findings,
        "SameSite=None without Secure",
    )

    assert finding.severity == Severity.HIGH
    assert (
        finding.classification
        == FindingClassification.CONFIRMED_MISCONFIGURATION
    )


def test_samesite_none_with_secure_is_not_flagged():
    findings = _analyze_cookie(
        b"session=secret; Secure; SameSite=None"
    )

    assert "SameSite=None without Secure" not in {
        finding.title for finding in findings
    }


def test_valid_cookie_domain_matching_response_host():
    findings = _analyze_cookie(
        b"session=secret; Domain=example.com",
        response_url="https://example.com/",
    )

    assert "Cookie Domain incompatible with response host" not in {
        finding.title for finding in findings
    }


def test_parent_cookie_domain_matches_subdomain():
    findings = _analyze_cookie(
        b"session=secret; Domain=example.com",
        response_url="https://shop.example.com/",
    )

    assert "Cookie Domain incompatible with response host" not in {
        finding.title for finding in findings
    }


def test_cookie_domain_does_not_match_unrelated_hostname():
    findings = _analyze_cookie(
        b"session=secret; Domain=example.com",
        response_url="https://notexample.com/",
    )

    finding = _finding_by_title(
        findings,
        "Cookie Domain incompatible with response host",
    )

    assert finding.severity == Severity.MEDIUM
    assert (
        finding.classification
        == FindingClassification.CONFIRMED_MISCONFIGURATION
    )


def test_duplicate_cookie_attributes_are_reported():
    findings = _analyze_cookie(
        b"session=secret; Secure; Secure; HttpOnly"
    )

    finding = _finding_by_title(
        findings,
        "Duplicate cookie attributes",
    )

    assert finding.severity == Severity.MEDIUM
    assert finding.classification == (
        FindingClassification.POTENTIAL_WEAKNESS
    )


def test_invalid_samesite_is_reported_without_missing_samesite_finding():
    findings = _analyze_cookie(
        b"session=secret; SameSite=invalid"
    )

    titles = {finding.title for finding in findings}

    assert "Invalid SameSite attribute" in titles
    assert "Cookie missing SameSite attribute" not in titles


@pytest.mark.parametrize(
    ("header", "attribute"),
    [
        (b"session=secret; Domain=bad_domain", "domain"),
        (b"session=secret; Path=relative-path", "path"),
        (b"session=secret; Expires=not-a-valid-date", "expires"),
        (b"session=secret; Max-Age=not-a-number", "max-age"),
    ],
)
def test_invalid_cookie_attributes_are_reported_as_observations(
    header,
    attribute,
):
    findings = _analyze_cookie(header)

    finding = _finding_by_title(
        findings,
        "Invalid cookie attributes",
    )

    assert finding.severity == Severity.INFO
    assert finding.classification == FindingClassification.OBSERVATION
    assert attribute in (
        finding.evidence[0].details["attributes"]["invalid_attributes"]
    )


def test_invalid_samesite_is_not_repeated_in_generic_invalid_attributes():
    findings = _analyze_cookie(
        b"session=secret; SameSite=invalid"
    )

    titles = {finding.title for finding in findings}

    assert "Invalid SameSite attribute" in titles
    assert "Invalid cookie attributes" not in titles


def test_invalid_attribute_findings_never_expose_rejected_values():
    secret_values = [
        "COOKIE_VALUE_SECRET_839201",
        "bad_domain_secret",
        "relative_path_secret",
        "invalid_expires_secret",
        "invalid_max_age_secret",
    ]

    findings = _analyze_cookie(
        (
            f"session={secret_values[0]}; "
            f"Domain={secret_values[1]}; "
            f"Path={secret_values[2]}; "
            f"Expires={secret_values[3]}; "
            f"Max-Age={secret_values[4]}"
        ).encode()
    )

    serialized = "\n".join(
        finding.model_dump_json()
        for finding in findings
    )

    for secret in secret_values:
        assert secret not in serialized


def test_unknown_cookie_attributes_are_observations():
    findings = _analyze_cookie(
        b"session=secret; Priority=High"
    )

    finding = _finding_by_title(
        findings,
        "Unrecognized cookie attributes",
    )

    assert finding.severity == Severity.INFO
    assert finding.classification == FindingClassification.OBSERVATION


def test_cookie_findings_never_expose_cookie_values():
    secret = "WEBHAWK_SESSION_SECRET_839201"

    findings = _analyze_cookie(
        (
            f"session={secret}; "
            "Secure; HttpOnly; SameSite=Lax"
        ).encode()
    )

    serialized = "\n".join(
        finding.model_dump_json()
        for finding in findings
    )

    assert secret not in serialized


def test_cookie_evidence_does_not_expose_query_or_fragment():
    findings = _analyze_cookie(
        b"session=secret",
        response_url=(
            "https://example.com/account"
            "?access_token=URL_SECRET_123#private-fragment"
        ),
    )

    assert findings

    for finding in findings:
        source = finding.evidence[0].source

        assert "access_token" not in source
        assert "URL_SECRET_123" not in source
        assert "private-fragment" not in source
        assert source == "https://example.com/account"


def test_cookie_evidence_does_not_expose_url_credentials():
    findings = _analyze_cookie(
        b"session=secret",
        response_url="https://user:password@example.com/account",
    )

    assert findings

    for finding in findings:
        source = finding.evidence[0].source

        assert "user" not in source
        assert "password" not in source
        assert source == "https://example.com/account"


@pytest.mark.parametrize(
    "response_url",
    [
        "",
        "ftp://example.com/",
        "https:///missing-host",
        "not-a-url",
    ],
)
def test_analyzer_rejects_invalid_response_urls(response_url):
    with pytest.raises(ValueError):
        analyze_cookies(
            response_url=response_url,
            raw_headers=[],
        )


def test_analyzer_rejects_non_string_response_url():
    with pytest.raises(TypeError):
        analyze_cookies(
            response_url=None,
            raw_headers=[],
        )

# ---------------------------------------------------------------------------
# Duplicate cookie-name and scope analysis tests
# ---------------------------------------------------------------------------

def _analyze_cookie_headers(headers, response_url="https://shop.example.com/account"):
    return analyze_cookies(
        response_url=response_url,
        raw_headers=[
            (b"set-cookie", header)
            for header in headers
        ],
    )


def test_same_cookie_name_with_different_paths_is_observed():
    findings = _analyze_cookie_headers([
        b"session=first; Path=/",
        b"session=second; Path=/admin",
    ])

    finding = _finding_by_title(
        findings,
        "Duplicate cookie names with different scopes",
    )

    assert finding.severity == Severity.INFO
    assert finding.classification == FindingClassification.OBSERVATION


def test_same_cookie_name_with_different_domains_is_observed():
    findings = _analyze_cookie_headers([
        b"session=first; Domain=example.com; Path=/",
        b"session=second; Domain=shop.example.com; Path=/",
    ])

    finding = _finding_by_title(
        findings,
        "Duplicate cookie names with different scopes",
    )

    assert finding.severity == Severity.INFO
    assert finding.classification == FindingClassification.OBSERVATION


def test_host_only_and_domain_cookie_with_same_name_are_distinguished():
    findings = _analyze_cookie_headers([
        b"session=first; Path=/",
        b"session=second; Domain=shop.example.com; Path=/",
    ])

    assert "Duplicate cookie names with different scopes" in {
        finding.title for finding in findings
    }


def test_same_cookie_name_with_identical_scopes_is_not_flagged():
    findings = _analyze_cookie_headers([
        b"session=first; Path=/admin",
        b"session=second; Path=/admin",
    ])

    assert "Duplicate cookie names with different scopes" not in {
        finding.title for finding in findings
    }


def test_duplicate_cookie_name_evidence_never_exposes_values():
    secrets = [
        "COOKIE_SECRET_FIRST_839201",
        "COOKIE_SECRET_SECOND_739102",
    ]

    findings = _analyze_cookie_headers([
        f"session={secrets[0]}; Path=/".encode(),
        f"session={secrets[1]}; Path=/admin".encode(),
    ])

    finding = _finding_by_title(
        findings,
        "Duplicate cookie names with different scopes",
    )

    serialized = finding.model_dump_json()

    for secret in secrets:
        assert secret not in serialized

    assert "session" in serialized

def test_exact_ipv4_cookie_domain_matches_response_host():
    findings = _analyze_cookie(
        b"session=secret; Domain=192.0.2.1",
        response_url="https://192.0.2.1/",
    )

    assert "Cookie Domain incompatible with response host" not in {
        finding.title for finding in findings
    }


def test_ipv4_cookie_domain_does_not_use_suffix_matching():
    findings = _analyze_cookie(
        b"session=secret; Domain=0.2.1",
        response_url="https://192.0.2.1/",
    )

    assert "Cookie Domain incompatible with response host" in {
        finding.title for finding in findings
    }

@pytest.mark.parametrize(
    ("request_path", "expected_path"),
    [
        ("", "/"),
        ("/", "/"),
        ("/account", "/"),
        ("/account/", "/account"),
        ("/account/settings", "/account"),
        ("/account/settings/profile", "/account/settings"),
    ],
)
def test_default_cookie_path_follows_rfc6265(request_path, expected_path):
    from webhawk.analyzers.cookies import _default_cookie_path

    assert _default_cookie_path(request_path) == expected_path


def test_omitted_path_and_explicit_default_path_have_identical_scope():
    findings = _analyze_cookie_headers(
        [
            b"session=first",
            b"session=second; Path=/",
        ],
        response_url="https://shop.example.com/account",
    )

    assert "Duplicate cookie names with different scopes" not in {
        finding.title for finding in findings
    }


def test_omitted_paths_use_response_url_for_scope_comparison():
    findings = _analyze_cookie_headers(
        [
            b"session=first",
            b"session=second",
        ],
        response_url="https://shop.example.com/account/settings",
    )

    assert "Duplicate cookie names with different scopes" not in {
        finding.title for finding in findings
    }


def test_omitted_path_and_explicit_different_path_have_different_scopes():
    findings = _analyze_cookie_headers(
        [
            b"session=first",
            b"session=second; Path=/",
        ],
        response_url="https://shop.example.com/account/settings",
    )

    assert "Duplicate cookie names with different scopes" in {
        finding.title for finding in findings
    }

# ---------------------------------------------------------------------------
# Cookie security-prefix enforcement tests
# ---------------------------------------------------------------------------

def test_secure_prefix_requires_secure_attribute():
    findings = _analyze_cookie(
        b"__Secure-session=secret; HttpOnly; SameSite=Lax"
    )

    finding = _finding_by_title(
        findings,
        "Cookie prefix requirements violated",
    )

    assert finding.severity == Severity.MEDIUM
    assert (
        finding.classification
        == FindingClassification.CONFIRMED_MISCONFIGURATION
    )
    assert "secure_attribute_required" in (
        finding.evidence[0].details["attributes"]["violations"]
    )


def test_secure_prefix_requires_secure_origin():
    findings = _analyze_cookie(
        b"__Secure-session=secret; Secure",
        response_url="http://example.com/",
    )

    finding = _finding_by_title(
        findings,
        "Cookie prefix requirements violated",
    )

    assert "secure_origin_required" in (
        finding.evidence[0].details["attributes"]["violations"]
    )


def test_valid_secure_prefix_is_not_flagged():
    findings = _analyze_cookie(
        b"__Secure-session=secret; Secure; HttpOnly; SameSite=Lax"
    )

    assert "Cookie prefix requirements violated" not in {
        finding.title for finding in findings
    }


@pytest.mark.parametrize(
    ("header", "expected_violation"),
    [
        (
            b"__Host-session=secret; Secure; Path=/",
            None,
        ),
        (
            b"__Host-session=secret; Path=/",
            "secure_attribute_required",
        ),
        (
            b"__Host-session=secret; Secure",
            "path_must_be_root",
        ),
        (
            b"__Host-session=secret; Secure; Path=/admin",
            "path_must_be_root",
        ),
        (
            b"__Host-session=secret; Secure; Path=/; Domain=example.com",
            "domain_attribute_prohibited",
        ),
        (
            b"__Host-session=secret; Secure; Path=/; Domain=bad_domain",
            "domain_attribute_prohibited",
        ),
    ],
)
def test_host_prefix_requirements(header, expected_violation):
    findings = _analyze_cookie(header)

    prefix_findings = [
        finding
        for finding in findings
        if finding.title == "Cookie prefix requirements violated"
    ]

    if expected_violation is None:
        assert prefix_findings == []
    else:
        assert len(prefix_findings) == 1

        violations = (
            prefix_findings[0]
            .evidence[0]
            .details["attributes"]["violations"]
        )

        assert expected_violation in violations


def test_host_prefix_rejects_invalid_domain_attribute_presence():
    result = _parse_set_cookie(
        b"__Host-session=secret; Secure; Path=/; Domain=bad_domain"
    )

    assert result is not None
    assert result.domain is None
    assert result.domain_attribute_present is True


def test_host_prefix_accepts_absent_domain_attribute():
    result = _parse_set_cookie(
        b"__Host-session=secret; Secure; Path=/"
    )

    assert result is not None
    assert result.domain is None
    assert result.domain_attribute_present is False


def test_prefix_matching_is_case_sensitive():
    findings = _analyze_cookie(
        b"__secure-session=secret"
    )

    assert "Cookie prefix requirements violated" not in {
        finding.title for finding in findings
    }


@pytest.mark.parametrize(
    "response_url",
    [
        "http://localhost/",
        "http://127.0.0.1/",
        "http://127.0.0.2/",
        "http://[::1]/",
    ],
)
def test_secure_prefix_accepts_local_secure_origins(response_url):
    findings = _analyze_cookie(
        b"__Secure-session=secret; Secure",
        response_url=response_url,
    )

    assert "Cookie prefix requirements violated" not in {
        finding.title for finding in findings
    }


def test_prefix_findings_never_expose_cookie_values():
    secret = "PREFIX_COOKIE_SECRET_839201"

    findings = _analyze_cookie(
        (
            f"__Host-session={secret}; "
            "Secure; Path=/; Domain=example.com"
        ).encode()
    )

    serialized = "\n".join(
        finding.model_dump_json()
        for finding in findings
    )

    assert "Cookie prefix requirements violated" in {
        finding.title for finding in findings
    }
    assert secret not in serialized

def test_secure_prefix_does_not_assume_localhost_subdomains_are_secure():
    findings = _analyze_cookie(
        b"__Secure-session=secret; Secure",
        response_url="http://app.localhost/",
    )

    finding = _finding_by_title(
        findings,
        "Cookie prefix requirements violated",
    )

    assert "secure_origin_required" in (
        finding.evidence[0].details["attributes"]["violations"]
    )


# ---------------------------------------------------------------------------
# Stage 2: Secure cookies received from insecure origins
# ---------------------------------------------------------------------------


def test_secure_cookie_received_from_insecure_origin():
    findings = _analyze_cookie(
        b"session=secret; Secure; HttpOnly; SameSite=Lax",
        response_url="http://example.com/account",
    )

    finding = _finding_by_title(
        findings,
        "Secure cookie received from insecure origin",
    )

    assert finding.severity == Severity.LOW
    assert (
        finding.classification
        == FindingClassification.POTENTIAL_WEAKNESS
    )
    assert finding.confidence == 90


@pytest.mark.parametrize(
    "response_url",
    [
        "http://192.168.1.10/account",
        "http://10.0.0.5/account",
    ],
)
def test_secure_cookie_received_from_private_ip_is_flagged(response_url):
    findings = _analyze_cookie(
        b"session=secret; Secure",
        response_url=response_url,
    )

    finding = _finding_by_title(
        findings,
        "Secure cookie received from insecure origin",
    )

    assert finding.severity == Severity.LOW
    assert (
        finding.classification
        == FindingClassification.POTENTIAL_WEAKNESS
    )


@pytest.mark.parametrize(
    "response_url",
    [
        "https://example.com/account",
        "http://localhost/account",
        "http://127.0.0.1/account",
        "http://127.0.0.2/account",
        "http://[::1]/account",
    ],
)
def test_secure_cookie_from_secure_origin_is_not_flagged(response_url):
    findings = _analyze_cookie(
        b"session=secret; Secure",
        response_url=response_url,
    )

    assert "Secure cookie received from insecure origin" not in {
        finding.title for finding in findings
    }


def test_ordinary_cookie_received_over_http_is_not_flagged_by_new_rule():
    findings = _analyze_cookie(
        b"session=secret; HttpOnly; SameSite=Lax",
        response_url="http://example.com/account",
    )

    assert "Secure cookie received from insecure origin" not in {
        finding.title for finding in findings
    }


@pytest.mark.parametrize(
    "cookie_header",
    [
        b"__Secure-session=secret; Secure",
        b"__Host-session=secret; Secure; Path=/",
    ],
)
def test_secure_prefix_cookie_does_not_receive_duplicate_origin_finding(
    cookie_header,
):
    findings = _analyze_cookie(
        cookie_header,
        response_url="http://example.com/account",
    )

    titles = [finding.title for finding in findings]

    assert titles.count("Cookie prefix requirements violated") == 1
    assert "Secure cookie received from insecure origin" not in titles


def test_insecure_origin_finding_never_exposes_cookie_value():
    secret = "INSECURE_ORIGIN_SECRET_728491"

    findings = _analyze_cookie(
        (
            f"session={secret}; "
            "Secure; HttpOnly; SameSite=Lax"
        ).encode(),
        response_url="http://example.com/account",
    )

    finding = _finding_by_title(
        findings,
        "Secure cookie received from insecure origin",
    )

    serialized = finding.model_dump_json()

    assert secret not in serialized
    assert "session" in serialized
    assert "secure_origin" in serialized

# ---------------------------------------------------------------------------
# IDNA / Punycode cookie-domain matching
# ---------------------------------------------------------------------------

def test_unicode_response_hostname_matches_punycode_cookie_domain():
    findings = _analyze_cookie(
        b"session=secret; Domain=xn--mnich-kva.example",
        response_url="https://m\u00fcnich.example/",
    )

    assert "Cookie Domain incompatible with response host" not in {
        finding.title for finding in findings
    }


def test_punycode_response_hostname_matches_punycode_cookie_domain():
    findings = _analyze_cookie(
        b"session=secret; Domain=xn--mnich-kva.example",
        response_url="https://xn--mnich-kva.example/",
    )

    assert "Cookie Domain incompatible with response host" not in {
        finding.title for finding in findings
    }
