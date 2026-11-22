import os
import threading

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest

from PySide6.QtCore import QEventLoop, QTimer, QThread
from PySide6.QtWidgets import QApplication

from webhawk.core.authorization import AuthorizationProfile
from webhawk.core.authorization_store import AuthorizationStore
from webhawk.core.safety import ApprovedTarget, TargetNotAuthorizedError
from webhawk.gui.pages import assessment


@pytest.fixture(scope="session")
def qt_app():
    app = QApplication.instance()

    if app is None:
        app = QApplication([])

    yield app


@pytest.fixture
def store(tmp_path):
    authorization_store = AuthorizationStore(
        tmp_path / "profiles.json"
    )

    authorization_store.save_profile(
        AuthorizationProfile(
            name="Local Lab",
            authorized_hosts=("lab.example",),
            authorized_networks=("192.168.1.0/24",),
        )
    )

    authorization_store.save_profile(
        AuthorizationProfile(
            name="Secondary Lab",
            authorized_hosts=("secondary.example",),
            authorized_networks=("10.0.0.0/24",),
        )
    )

    return authorization_store


@pytest.fixture
def page(qt_app, store):
    widget = assessment.AssessmentPage(store)
    widget.show()

    yield widget

    if widget._worker is not None:
        if widget._worker.isRunning():
            widget._worker.wait(3000)

    widget.close()
    widget.deleteLater()
    qt_app.processEvents()


def wait_for_worker(page, timeout_ms=5000):
    worker = page._worker

    assert worker is not None

    loop = QEventLoop()
    timer = QTimer()
    timer.setSingleShot(True)

    worker.finished.connect(loop.quit)
    timer.timeout.connect(loop.quit)

    timer.start(timeout_ms)
    loop.exec()

    assert not worker.isRunning(), "Worker did not finish in time."

    page._on_worker_finished()


def approved_target():
    return ApprovedTarget(
        normalized_url="https://lab.example/",
        hostname="lab.example",
        approved_addresses=("192.168.1.10", "192.168.1.11"),
    )


def test_saved_profiles_are_loaded(page):
    assert page.profile_combo.count() == 2

    assert page.profile_combo.itemText(0) == "Local Lab"
    assert page.profile_combo.itemText(1) == "Secondary Lab"


def test_empty_store_displays_no_profile_message(qt_app, tmp_path):
    store = AuthorizationStore(tmp_path / "empty.json")
    page = assessment.AssessmentPage(store)

    assert page.profile_combo.count() == 0
    assert "No authorization profiles exist" in (
        page.status_label.text()
    )
    assert not page.validate_button.isEnabled()

    page.close()


def test_successful_authorization_displays_approved_target(
    page,
    monkeypatch,
):
    expected = approved_target()

    def fake_authorize(url, policy):
        assert url == "https://lab.example"
        assert "lab.example" in policy.authorized_hosts
        return expected

    monkeypatch.setattr(
        assessment,
        "authorize_target",
        fake_authorize,
    )

    page.target_input.setText("https://lab.example")
    page._validate_target()

    wait_for_worker(page)

    assert page._approved_target == expected
    assert "https://lab.example/" in (
        page.normalized_url_label.text()
    )
    assert "lab.example" in page.hostname_label.text()
    assert "192.168.1.10" in page.addresses_label.text()
    assert "192.168.1.11" in page.addresses_label.text()
    assert "successful" in page.status_label.text().lower()


def test_unauthorized_target_displays_failure_without_addresses(
    page,
    monkeypatch,
):
    def fake_authorize(url, policy):
        raise TargetNotAuthorizedError(
            "Hostname has not been explicitly authorized."
        )

    monkeypatch.setattr(
        assessment,
        "authorize_target",
        fake_authorize,
    )

    page.target_input.setText("https://unauthorized.example")
    page._validate_target()

    wait_for_worker(page)

    assert page._approved_target is None
    assert "Authorization failed" in page.status_label.text()
    assert "not been explicitly authorized" in page.status_label.text().lower()
    assert "Approved addresses: —" == (
        page.addresses_label.text()
    )


def test_url_change_invalidates_successful_preview(
    page,
    monkeypatch,
):
    monkeypatch.setattr(
        assessment,
        "authorize_target",
        lambda url, policy: approved_target(),
    )

    page.target_input.setText("https://lab.example")
    page._validate_target()

    wait_for_worker(page)

    assert page._approved_target is not None

    page.target_input.setText("https://changed.example")

    assert page._approved_target is None
    assert page.normalized_url_label.text() == "Normalized URL: —"
    assert page.hostname_label.text() == "Hostname: —"
    assert page.addresses_label.text() == "Approved addresses: —"
    assert "Validate the target again" in page.status_label.text()


def test_profile_change_invalidates_successful_preview(
    page,
    monkeypatch,
):
    monkeypatch.setattr(
        assessment,
        "authorize_target",
        lambda url, policy: approved_target(),
    )

    page.target_input.setText("https://lab.example")
    page._validate_target()

    wait_for_worker(page)

    assert page._approved_target is not None

    page.profile_combo.setCurrentIndex(1)

    assert page._approved_target is None
    assert page.normalized_url_label.text() == "Normalized URL: —"
    assert page.hostname_label.text() == "Hostname: —"
    assert page.addresses_label.text() == "Approved addresses: —"


def test_authorization_worker_runs_outside_gui_thread(
    monkeypatch,
):
    gui_thread_id = threading.get_ident()
    worker_thread_ids = []

    def fake_authorize(url, policy):
        worker_thread_ids.append(threading.get_ident())
        return approved_target()

    monkeypatch.setattr(
        assessment,
        "authorize_target",
        fake_authorize,
    )

    worker = assessment.AuthorizationPreviewWorker(
        "https://lab.example",
        assessment.TargetPolicy(
            authorized_hosts=frozenset({"lab.example"}),
        ),
    )

    loop = QEventLoop()
    timer = QTimer()
    timer.setSingleShot(True)

    worker.finished.connect(loop.quit)
    timer.timeout.connect(loop.quit)

    worker.start()
    timer.start(5000)
    loop.exec()

    assert not worker.isRunning()
    assert worker_thread_ids
    assert worker_thread_ids[0] != gui_thread_id



# =============================================================
# Assessment execution tests
# =============================================================

def make_completed_result():
    from datetime import datetime, timezone

    from webhawk.core.models import (
        Evidence,
        Finding,
        FindingClassification,
        ScanResult,
        ScanStatus,
        ScanTarget,
        Severity,
    )

    now = datetime.now(timezone.utc)

    finding = Finding(
        title="Missing Content Security Policy",
        description="The response does not contain a Content-Security-Policy header.",
        severity=Severity.MEDIUM,
        classification=FindingClassification.POTENTIAL_WEAKNESS,
        confidence=85,
        analyzer="security_headers",
        evidence=[
            Evidence(
                evidence_type="http_response_header",
                description="Content-Security-Policy header was not present.",
                source="security_headers",
            )
        ],
        remediation="Configure an appropriate Content-Security-Policy header.",
    )

    return ScanResult(
        target=ScanTarget(url="https://lab.example/"),
        status=ScanStatus.COMPLETED,
        started_at=now,
        completed_at=now,
        findings=[finding],
    )


def test_successful_assessment_displays_findings(
    page,
    monkeypatch,
):
    monkeypatch.setattr(
        assessment,
        "authorize_target",
        lambda url, policy: approved_target(),
    )

    async def fake_assess_target(url, policy):
        assert url == "https://lab.example"
        assert "lab.example" in policy.authorized_hosts
        return make_completed_result()

    monkeypatch.setattr(
        assessment,
        "assess_target",
        fake_assess_target,
    )

    page.target_input.setText("https://lab.example")
    page._validate_target()
    wait_for_worker(page)

    assert page.run_button.isEnabled()

    page._run_assessment()
    wait_for_worker(page)

    assert "COMPLETED" in page.execution_status_label.text()
    assert "Missing Content Security Policy" in (
        page.findings_output.toPlainText()
    )
    assert "security_headers" in (
        page.findings_output.toPlainText()
    )
    assert not page.progress_bar.isVisible()
    assert page.run_button.isEnabled()


def test_failed_assessment_displays_safe_error(
    page,
    monkeypatch,
):
    from datetime import datetime, timezone

    from webhawk.core.models import (
        ScanError,
        ScanErrorCode,
        ScanResult,
        ScanStatus,
        ScanTarget,
    )

    monkeypatch.setattr(
        assessment,
        "authorize_target",
        lambda url, policy: approved_target(),
    )

    async def fake_assess_target(url, policy):
        now = datetime.now(timezone.utc)

        return ScanResult(
            target=ScanTarget(url="https://lab.example/"),
            status=ScanStatus.FAILED,
            started_at=now,
            completed_at=now,
            error=ScanError(
                code=ScanErrorCode.CONNECTION_FAILED,
                message="A connection to the target could not be established.",
            ),
        )

    monkeypatch.setattr(
        assessment,
        "assess_target",
        fake_assess_target,
    )

    page.target_input.setText("https://lab.example")
    page._validate_target()
    wait_for_worker(page)

    page._run_assessment()
    wait_for_worker(page)

    assert "assessment finished: failed" in (
        page.execution_status_label.text().lower()
    )
    assert "connection to the target could not be established" in (
        page.findings_output.toPlainText().lower()
    )
    assert not page.progress_bar.isVisible()


def test_assessment_execution_runs_outside_gui_thread(
    page,
    monkeypatch,
):
    gui_thread_id = threading.get_ident()
    worker_thread_ids = []

    monkeypatch.setattr(
        assessment,
        "authorize_target",
        lambda url, policy: approved_target(),
    )

    async def fake_assess_target(url, policy):
        worker_thread_ids.append(threading.get_ident())
        return make_completed_result()

    monkeypatch.setattr(
        assessment,
        "assess_target",
        fake_assess_target,
    )

    page.target_input.setText("https://lab.example")
    page._validate_target()
    wait_for_worker(page)

    page._run_assessment()
    wait_for_worker(page)

    assert worker_thread_ids
    assert worker_thread_ids[0] != gui_thread_id


def test_modified_profile_prevents_assessment_execution(
    page,
    monkeypatch,
):
    assessment_calls = []

    monkeypatch.setattr(
        assessment,
        "authorize_target",
        lambda url, policy: approved_target(),
    )

    async def fake_assess_target(url, policy):
        assessment_calls.append(url)
        return make_completed_result()

    monkeypatch.setattr(
        assessment,
        "assess_target",
        fake_assess_target,
    )

    page.target_input.setText("https://lab.example")
    page._validate_target()
    wait_for_worker(page)

    from webhawk.core.authorization import AuthorizationProfile

    page.store.save_profile(
        AuthorizationProfile(
            name="Local Lab",
            authorized_hosts=("changed.example",),
            authorized_networks=("192.168.1.0/24",),
        )
    )

    page._run_assessment()

    assert assessment_calls == []
    assert page._approved_target is None
    assert "changed after preview" in (
        page.status_label.text().lower()
    )
    assert not page.run_button.isEnabled()


def test_deleted_profile_prevents_assessment_execution(
    page,
    monkeypatch,
):
    assessment_calls = []

    monkeypatch.setattr(
        assessment,
        "authorize_target",
        lambda url, policy: approved_target(),
    )

    async def fake_assess_target(url, policy):
        assessment_calls.append(url)
        return make_completed_result()

    monkeypatch.setattr(
        assessment,
        "assess_target",
        fake_assess_target,
    )

    page.target_input.setText("https://lab.example")
    page._validate_target()
    wait_for_worker(page)

    page.store.delete_profile("Local Lab")

    page._run_assessment()

    assert assessment_calls == []
    assert page._approved_target is None
    assert "no longer exists" in (
        page.status_label.text().lower()
    )
    assert not page.run_button.isEnabled()





def test_assessment_prevents_duplicate_launch_and_restores_controls(
    page,
    monkeypatch,
):
    import asyncio
    import threading

    assessment_started = threading.Event()
    release_assessment = threading.Event()
    assessment_calls = []

    monkeypatch.setattr(
        assessment,
        "authorize_target",
        lambda url, policy: approved_target(),
    )

    async def fake_assess_target(url, policy):
        assessment_calls.append(url)
        assessment_started.set()

        await asyncio.to_thread(
            release_assessment.wait,
            10,
        )

        return make_completed_result()

    monkeypatch.setattr(
        assessment,
        "assess_target",
        fake_assess_target,
    )

    try:
        page.target_input.setText("https://lab.example")
        page._validate_target()
        wait_for_worker(page)

        assert page.run_button.isEnabled()

        page._run_assessment()

        assert assessment_started.wait(3), (
            "Assessment worker did not start."
        )

        active_worker = page._worker

        assert active_worker is not None
        assert active_worker.isRunning()
        assert page._worker_running()

        # Controls must remain disabled during execution.
        assert not page.profile_combo.isEnabled()
        assert not page.target_input.isEnabled()
        assert not page.validate_button.isEnabled()
        assert not page.run_button.isEnabled()
        assert page.progress_bar.isVisible()

        # A second launch attempt must not create another worker.
        page._run_assessment()

        assert page._worker is active_worker
        assert len(assessment_calls) == 1

        release_assessment.set()
        wait_for_worker(page)

        # The interface must recover after execution.
        assert page._worker is None
        assert not page._worker_running()
        assert page.profile_combo.isEnabled()
        assert page.target_input.isEnabled()
        assert page.validate_button.isEnabled()
        assert page.run_button.isEnabled()
        assert not page.progress_bar.isVisible()

    finally:
        release_assessment.set()

        worker = page._worker
        if worker is not None and worker.isRunning():
            worker.wait(3000)



def test_authorization_worker_preserves_expected_error_message(monkeypatch):
    def fake_authorize(url, policy):
        raise TargetNotAuthorizedError("Hostname has not been explicitly authorized.")

    monkeypatch.setattr(assessment, "authorize_target", fake_authorize)

    worker = assessment.AuthorizationPreviewWorker(
        "https://lab.example",
        assessment.TargetPolicy(
            authorized_hosts=frozenset({"lab.example"}),
        ),
    )

    messages = []
    worker.failed.connect(messages.append)

    worker.run()

    assert messages == [
        "Hostname has not been explicitly authorized."
    ]


def test_authorization_worker_sanitizes_unexpected_error(monkeypatch):
    def fake_authorize(url, policy):
        raise RuntimeError("Sensitive internal implementation detail")

    monkeypatch.setattr(assessment, "authorize_target", fake_authorize)

    worker = assessment.AuthorizationPreviewWorker(
        "https://lab.example",
        assessment.TargetPolicy(
            authorized_hosts=frozenset({"lab.example"}),
        ),
    )

    messages = []
    worker.failed.connect(messages.append)

    worker.run()

    assert messages == [
        "An unexpected internal error prevented target authorization."
    ]
    assert "Sensitive internal implementation detail" not in messages[0]

def test_stale_authorization_result_cannot_approve_changed_url(
    page,
    monkeypatch,
):
    authorization_started = threading.Event()
    release_authorization = threading.Event()

    expected = approved_target()

    def fake_authorize(url, policy):
        assert url == "https://lab.example"
        authorization_started.set()
        release_authorization.wait(timeout=5)
        return expected

    monkeypatch.setattr(
        assessment,
        "authorize_target",
        fake_authorize,
    )

    page.target_input.setText("https://lab.example")
    page._validate_target()

    try:
        assert authorization_started.wait(timeout=3)

        # Simulate a state change while the worker is still running.
        page.target_input.setText("https://changed.example")

        release_authorization.set()
        wait_for_worker(page)

        # The old authorization result must not approve the new URL.
        assert page._approved_target is None
        assert page._preview_profile is None
        assert page._preview_url is None
        assert page.addresses_label.text() == "Approved addresses: —"

    finally:
        release_authorization.set()

        worker = page._worker
        if worker is not None and worker.isRunning():
            worker.wait(3000)

def test_revalidation_clears_previous_assessment_findings(
    page,
    monkeypatch,
):
    authorization_calls = 0
    authorization_started = threading.Event()
    release_authorization = threading.Event()

    def fake_authorize(url, policy):
        nonlocal authorization_calls
        authorization_calls += 1

        if authorization_calls == 2:
            authorization_started.set()
            release_authorization.wait(timeout=5)

        return approved_target()

    async def fake_assess_target(url, policy):
        return make_completed_result()

    monkeypatch.setattr(
        assessment,
        "authorize_target",
        fake_authorize,
    )
    monkeypatch.setattr(
        assessment,
        "assess_target",
        fake_assess_target,
    )

    try:
        page.target_input.setText("https://lab.example")

        # First authorization and assessment.
        page._validate_target()
        wait_for_worker(page)

        page._run_assessment()
        wait_for_worker(page)

        assert "Missing Content Security Policy" in (
            page.findings_output.toPlainText()
        )

        # Start another authorization for the same target.
        page._validate_target()

        assert authorization_started.wait(timeout=3)

        # Previous assessment findings must not remain visible.
        assert "Missing Content Security Policy" not in (
            page.findings_output.toPlainText()
        )

    finally:
        release_authorization.set()

        worker = page._worker
        if worker is not None and worker.isRunning():
            worker.wait(3000)
