import asyncio
import ssl

import httpx
import pytest
import trustme

from webhawk.core.safety import TargetPolicy
from webhawk.core.transport.client import WebHawkAsyncTransport


async def run_local_https_request(
    ca,
    server_cert,
    client_context,
    hostname,
    sni_names,
):
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_cert.configure_cert(server_context)

    server_context.set_servername_callback(
        lambda ssl_socket, server_name, context:
            sni_names.append(server_name)
    )

    async def handle_client(reader, writer):
        try:
            await reader.readuntil(b"\r\n\r\n")

            writer.write(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Length: 2\r\n"
                b"Connection: close\r\n"
                b"\r\n"
                b"OK"
            )

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
            response = await client.get(target_url)
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
