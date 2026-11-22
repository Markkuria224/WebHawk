import asyncio
import ssl
from datetime import datetime, timedelta, timezone
from time import perf_counter_ns

import httpx
import pytest
import trustme

from webhawk.analyzers.cookies import analyze_cookies
from webhawk.core.response import build_response_metadata
from webhawk.core.safety import TargetPolicy
from webhawk.core.transport.client import WebHawkAsyncTransport


async def run_local_https_request(
    ca,
    server_cert,
    client_context,
    hostname,
    sni_names,
    protocol_version=None,
    negotiated_versions=None,
    response_headers=None,
    return_response=False,
):
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_cert.configure_cert(server_context)

    if protocol_version is not None:
        server_context.minimum_version = protocol_version
        server_context.maximum_version = protocol_version

    server_context.set_servername_callback(
        lambda ssl_socket, server_name, context:
            sni_names.append(server_name)
    )

    async def handle_client(reader, writer):
        try:
            ssl_object = writer.get_extra_info("ssl_object")

            if ssl_object is not None and negotiated_versions is not None:
                negotiated_versions.append(ssl_object.version())

            await reader.readuntil(b"\r\n\r\n")

            headers = [
                (b"Content-Length", b"2"),
                (b"Connection", b"close"),
            ]

            if response_headers:
                headers.extend(response_headers)

            response = bytearray(b"HTTP/1.1 200 OK\r\n")

            for name, value in headers:
                response.extend(name + b": " + value + b"\r\n")

            response.extend(b"\r\nOK")

            writer.write(bytes(response))
            await writer.drain()

        except (ConnectionError, asyncio.IncompleteReadError):
            pass

        finally:
            writer.close()

            try:
                await writer.wait_closed()
            except ConnectionError:
                pass

    server = await asyncio.start_server(
        handle_client,
        host="127.0.0.1",
        port=0,
        ssl=server_context,
    )

    port = server.sockets[0].getsockname()[1]

    policy = TargetPolicy(
        authorized_hosts=frozenset({hostname}),
        authorized_networks=("127.0.0.0/8",),
        allow_loopback=True,
    )

    target_url = f"https://{hostname}:{port}/"

    transport = WebHawkAsyncTransport(
        target_url,
        policy,
        ssl_context=client_context,
        resolver=lambda host, port: ["127.0.0.1"],
    )

    try:
        async with httpx.AsyncClient(
            transport=transport,
            trust_env=False,
            follow_redirects=False,
            timeout=5.0,
        ) as client:
            started_at_ns = perf_counter_ns()
            response = await client.get(target_url)

            if return_response:
                return response, target_url, started_at_ns

            return response.status_code

    finally:
        server.close()
        await server.wait_closed()


def test_trusted_certificate_and_sni():
    ca = trustme.CA()
    cert = ca.issue_cert("webhawk.test")

    client_context = ssl.create_default_context()
    ca.configure_trust(client_context)

    sni_names = []

    status = asyncio.run(
        run_local_https_request(
            ca,
            cert,
            client_context,
            "webhawk.test",
            sni_names,
        )
    )

    assert status == 200
    assert sni_names == ["webhawk.test"]


def test_untrusted_certificate_is_rejected():
    ca = trustme.CA()
    cert = ca.issue_cert("webhawk.test")

    client_context = ssl.create_default_context()

    sni_names = []

    with pytest.raises(httpx.ConnectError):
        asyncio.run(
            run_local_https_request(
                ca,
                cert,
                client_context,
                "webhawk.test",
                sni_names,
            )
        )


def test_hostname_mismatch_is_rejected():
    ca = trustme.CA()
    cert = ca.issue_cert("webhawk.test")

    client_context = ssl.create_default_context()
    ca.configure_trust(client_context)

    sni_names = []

    with pytest.raises(httpx.ConnectError):
        asyncio.run(
            run_local_https_request(
                ca,
                cert,
                client_context,
                "wrong.webhawk.test",
                sni_names,
            )
        )

    assert sni_names == ["wrong.webhawk.test"]


def test_expired_certificate_is_rejected():
    ca = trustme.CA()
    now = datetime.now(timezone.utc)

    cert = ca.issue_cert(
        "webhawk.test",
        not_before=now - timedelta(days=30),
        not_after=now - timedelta(days=1),
    )

    client_context = ssl.create_default_context()
    ca.configure_trust(client_context)

    with pytest.raises(httpx.ConnectError):
        asyncio.run(
            run_local_https_request(
                ca,
                cert,
                client_context,
                "webhawk.test",
                [],
            )
        )


def test_not_yet_valid_certificate_is_rejected():
    ca = trustme.CA()
    now = datetime.now(timezone.utc)

    cert = ca.issue_cert(
        "webhawk.test",
        not_before=now + timedelta(days=1),
        not_after=now + timedelta(days=30),
    )

    client_context = ssl.create_default_context()
    ca.configure_trust(client_context)

    with pytest.raises(httpx.ConnectError):
        asyncio.run(
            run_local_https_request(
                ca,
                cert,
                client_context,
                "webhawk.test",
                [],
            )
        )


@pytest.mark.parametrize(
    "protocol_version, expected_version",
    [
        (ssl.TLSVersion.TLSv1_2, "TLSv1.2"),
        (ssl.TLSVersion.TLSv1_3, "TLSv1.3"),
    ],
)
def test_explicit_tls_protocol_negotiation(
    protocol_version,
    expected_version,
):
    ca = trustme.CA()
    cert = ca.issue_cert("webhawk.test")

    client_context = ssl.create_default_context()
    ca.configure_trust(client_context)

    client_context.minimum_version = protocol_version
    client_context.maximum_version = protocol_version

    sni_names = []
    negotiated_versions = []

    status = asyncio.run(
        run_local_https_request(
            ca,
            cert,
            client_context,
            "webhawk.test",
            sni_names,
            protocol_version=protocol_version,
            negotiated_versions=negotiated_versions,
        )
    )

    assert status == 200
    assert sni_names == ["webhawk.test"]
    assert negotiated_versions == [expected_version]


def test_https_response_metadata_is_extracted_and_sanitized():
    ca = trustme.CA()
    cert = ca.issue_cert("webhawk.test")

    client_context = ssl.create_default_context()
    ca.configure_trust(client_context)

    response_headers = [
        (b"Content-Type", b"text/plain"),
        (b"X-Frame-Options", b"DENY"),
        (b"Set-Cookie", b"session=metadata-secret; Path=/"),
    ]

    response, target_url, started_at_ns = asyncio.run(
        run_local_https_request(
            ca,
            cert,
            client_context,
            "webhawk.test",
            [],
            response_headers=response_headers,
            return_response=True,
        )
    )

    metadata = build_response_metadata(
        requested_url=target_url,
        response=response,
        started_at_ns=started_at_ns,
    )

    assert metadata.status_code == 200
    assert metadata.http_version == "HTTP/1.1"
    assert str(metadata.response_url) == target_url
    assert metadata.elapsed_ms > 0

    headers = {
        header.name.casefold(): header.value
        for header in metadata.headers
    }

    assert headers["content-type"] == "text/plain"
    assert headers["x-frame-options"] == "DENY"
    assert headers["set-cookie"] == "[REDACTED]"

    serialized_metadata = metadata.model_dump_json()

    assert "metadata-secret" not in serialized_metadata
    assert "session=" not in serialized_metadata
    assert "OK" not in serialized_metadata
    assert "body" not in type(metadata).model_fields


def test_https_cookie_analyzer_detects_weak_cookie_without_leaking_value():
    ca = trustme.CA()
    cert = ca.issue_cert("webhawk.test")

    client_context = ssl.create_default_context()
    ca.configure_trust(client_context)

    cookie_secret = b"lab-https-session-secret"

    response, target_url, started_at_ns = asyncio.run(
        run_local_https_request(
            ca,
            cert,
            client_context,
            "webhawk.test",
            [],
            response_headers=[
                (
                    b"Set-Cookie",
                    b"sessionid=" + cookie_secret + b"; Path=/",
                ),
            ],
            return_response=True,
        )
    )

    metadata = build_response_metadata(
        requested_url=target_url,
        response=response,
        started_at_ns=started_at_ns,
    )

    findings = analyze_cookies(
        response_url=str(metadata.response_url),
        raw_headers=response.headers.raw,
    )

    assert len(findings) == 3

    serialized_findings = repr(findings)

    assert cookie_secret.decode() not in serialized_findings
    assert "sessionid=" not in serialized_findings
    assert all(finding.analyzer == "cookies" for finding in findings)


def test_https_cookie_analyzer_accepts_configured_cookie():
    ca = trustme.CA()
    cert = ca.issue_cert("webhawk.test")

    client_context = ssl.create_default_context()
    ca.configure_trust(client_context)

    cookie_secret = b"lab-configured-session-secret"

    response, target_url, started_at_ns = asyncio.run(
        run_local_https_request(
            ca,
            cert,
            client_context,
            "webhawk.test",
            [],
            response_headers=[
                (
                    b"Set-Cookie",
                    b"sessionid="
                    + cookie_secret
                    + b"; Path=/; Secure; HttpOnly; SameSite=Lax",
                ),
            ],
            return_response=True,
        )
    )

    metadata = build_response_metadata(
        requested_url=target_url,
        response=response,
        started_at_ns=started_at_ns,
    )

    findings = analyze_cookies(
        response_url=str(metadata.response_url),
        raw_headers=response.headers.raw,
    )

    assert findings == []
    assert cookie_secret.decode() not in repr(metadata)
    assert cookie_secret.decode() not in repr(findings)
