import asyncio
from time import perf_counter_ns

import httpx

from webhawk.analyzers.cookies import analyze_cookies
from webhawk.analyzers.cors import analyze_cors
from webhawk.core.response import build_response_metadata
from webhawk.core.safety import TargetPolicy
from webhawk.core.transport.client import WebHawkAsyncTransport


BASE_URL = "http://127.0.0.1:8000"

REQUEST_ORIGIN = "https://trusted.example"
UNTRUSTED_ORIGIN = "https://untrusted.example"

CORS_PATHS = (
    "/cors/wildcard",
    "/cors/credentials",
    "/cors/null",
    "/cors/duplicate",
    "/cors/invalid",
)

COOKIE_PATHS = (
    "/cookies/insecure",
    "/cookies/configured",
)

COOKIE_TEST_VALUES = (
    b"lab-only-value",
    b"lab-safe-value",
)


def print_finding(finding):
    print(f"\nFinding: {finding.title}")
    print(f"Severity: {finding.severity.value}")
    print(f"Classification: {finding.classification.value}")
    print(f"Confidence: {finding.confidence}%")
    print(f"Analyzer: {finding.analyzer}")
    print(f"Description: {finding.description}")
    print(f"Remediation: {finding.remediation}")


async def main():
    policy = TargetPolicy(
        authorized_hosts=frozenset({"127.0.0.1"}),
        authorized_networks=("127.0.0.1/32",),
        allow_loopback=True,
    )

    transport = WebHawkAsyncTransport(
        BASE_URL,
        policy,
    )

    timeout = httpx.Timeout(
        connect=5.0,
        read=10.0,
        write=10.0,
        pool=5.0,
    )

    total_findings = 0
    cookie_value_leak_check_passed = True
    allowlist_positive_test_passed = False
    allowlist_negative_test_passed = False
    configured_cookie_clean_test_passed = False

    async with httpx.AsyncClient(
        transport=transport,
        timeout=timeout,
        follow_redirects=False,
    ) as client:

        print("\n==========================================")
        print("       WEBHAWK LIVE SECURITY ASSESSMENT")
        print("==========================================")
        print(f"Target: {BASE_URL}")
        print(f"Request Origin: {REQUEST_ORIGIN}")
        print("Transport: WebHawkAsyncTransport")
        print("Scope: Local authorized lab only")

        for path in CORS_PATHS:
            url = BASE_URL + path

            print("\n------------------------------------------")
            print(f"CORS TEST: {path}")
            print("------------------------------------------")

            started_at_ns = perf_counter_ns()

            response = await client.get(
                url,
                headers={"Origin": REQUEST_ORIGIN},
            )

            metadata = build_response_metadata(
                requested_url=url,
                response=response,
                started_at_ns=started_at_ns,
            )

            print(f"HTTP Status: {response.status_code}")
            print(f"Elapsed: {metadata.elapsed_ms} ms")

            findings = analyze_cors(
                metadata,
                request_origin=REQUEST_ORIGIN,
                request_method="GET",
            )

            if not findings:
                print("Findings: None")
                continue

            for finding in findings:
                total_findings += 1
                print_finding(finding)

        print("\n------------------------------------------")
        print("CORS POSITIVE TEST: /cors/allowlist")
        print("------------------------------------------")
        print(f"Trusted Origin: {REQUEST_ORIGIN}")

        url = BASE_URL + "/cors/allowlist"
        started_at_ns = perf_counter_ns()

        response = await client.get(
            url,
            headers={"Origin": REQUEST_ORIGIN},
        )

        metadata = build_response_metadata(
            requested_url=url,
            response=response,
            started_at_ns=started_at_ns,
        )

        acao_values = [
            value.decode("latin-1")
            for name, value in response.headers.raw
            if name.lower() == b"access-control-allow-origin"
        ]

        findings = analyze_cors(
            metadata,
            request_origin=REQUEST_ORIGIN,
            request_method="GET",
        )

        for finding in findings:
            total_findings += 1
            print_finding(finding)

        trusted_origin_was_allowed = (
            response.status_code == 200
            and acao_values == [REQUEST_ORIGIN]
        )

        analyzer_recognized_trusted_origin = any(
            finding.title == "Supplied request origin is allowed by CORS"
            for finding in findings
        )

        allowlist_positive_test_passed = (
            trusted_origin_was_allowed
            and analyzer_recognized_trusted_origin
        )

        print(f"HTTP Status: {response.status_code}")
        print(f"Access-Control-Allow-Origin values: {acao_values}")
        print(
            "Trusted origin allowed and recognized:",
            "PASS" if allowlist_positive_test_passed else "FAIL",
        )

        print("\n------------------------------------------")
        print("CORS NEGATIVE TEST: /cors/allowlist")
        print("------------------------------------------")
        print(f"Untrusted Origin: {UNTRUSTED_ORIGIN}")

        url = BASE_URL + "/cors/allowlist"
        started_at_ns = perf_counter_ns()

        response = await client.get(
            url,
            headers={"Origin": UNTRUSTED_ORIGIN},
        )

        metadata = build_response_metadata(
            requested_url=url,
            response=response,
            started_at_ns=started_at_ns,
        )

        acao_values = [
            value.decode("latin-1")
            for name, value in response.headers.raw
            if name.lower() == b"access-control-allow-origin"
        ]

        findings = analyze_cors(
            metadata,
            request_origin=UNTRUSTED_ORIGIN,
            request_method="GET",
        )

        print(f"HTTP Status: {response.status_code}")
        print(f"Elapsed: {metadata.elapsed_ms} ms")
        print(f"Access-Control-Allow-Origin values: {acao_values}")

        for finding in findings:
            total_findings += 1
            print_finding(finding)

        origin_was_not_allowed = len(acao_values) == 0

        analyzer_did_not_claim_origin_allowed = not any(
            finding.title == "Supplied request origin is allowed by CORS"
            for finding in findings
        )

        allowlist_negative_test_passed = (
            response.status_code == 200
            and origin_was_not_allowed
            and analyzer_did_not_claim_origin_allowed
        )

        print(
            "Untrusted origin not authorized by CORS:",
            "PASS" if allowlist_negative_test_passed else "FAIL",
        )

        for path in COOKIE_PATHS:
            url = BASE_URL + path

            print("\n------------------------------------------")
            print(f"COOKIE TEST: {path}")
            print("------------------------------------------")

            started_at_ns = perf_counter_ns()
            response = await client.get(url)

            metadata = build_response_metadata(
                requested_url=url,
                response=response,
                started_at_ns=started_at_ns,
            )

            print(f"HTTP Status: {response.status_code}")
            print(f"Elapsed: {metadata.elapsed_ms} ms")

            raw_headers = response.headers.raw

            cookie_headers = [
                (name, value)
                for name, value in raw_headers
                if name.lower() == b"set-cookie"
            ]

            print(f"Set-Cookie headers received: {len(cookie_headers)}")

            findings = analyze_cookies(
                response_url=str(metadata.response_url),
                raw_headers=raw_headers,
            )

            if not findings:
                print("Findings: None")

            if path == "/cookies/configured":
                configured_cookie_clean_test_passed = not findings

            for finding in findings:
                total_findings += 1
                print_finding(finding)

                finding_content = repr(finding).encode(
                    "utf-8",
                    errors="replace",
                )

                if any(
                    secret in finding_content
                    for secret in COOKIE_TEST_VALUES
                ):
                    cookie_value_leak_check_passed = False

        print("\n==========================================")
        print("             ASSESSMENT SUMMARY")
        print("==========================================")
        print(f"CORS endpoints tested: {len(CORS_PATHS)}")
        print("CORS allowlist tests: 2 (trusted positive + untrusted negative)")
        print(f"Cookie endpoints tested: {len(COOKIE_PATHS)}")
        print(f"Total findings: {total_findings}")

        print(
            "Trusted origin allowed and recognized:",
            "PASS" if allowlist_positive_test_passed else "FAIL",
        )

        print(
            "Untrusted origin not authorized by CORS:",
            "PASS" if allowlist_negative_test_passed else "FAIL",
        )

        print(
            "Configured cookie false-positive test:",
            "PASS" if configured_cookie_clean_test_passed else "FAIL",
        )

        print(
            "Cookie value leakage check:",
            "PASS" if cookie_value_leak_check_passed else "FAIL",
        )

        checks_passed = all((
            allowlist_positive_test_passed,
            allowlist_negative_test_passed,
            configured_cookie_clean_test_passed,
            cookie_value_leak_check_passed,
        ))

        print(
            "Overall lab checks:",
            "PASS" if checks_passed else "FAIL",
        )

        print("Assessment completed.")
        print("==========================================")

        return 0 if checks_passed else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
