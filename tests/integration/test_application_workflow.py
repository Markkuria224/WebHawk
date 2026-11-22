import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QEventLoop, QTimer
from PySide6.QtWidgets import QApplication, QTableWidget

from webhawk.core.authorization import AuthorizationProfile
from webhawk.core.authorization_store import AuthorizationStore
from webhawk.gui.main_window import WebHawkMainWindow

import webhawk.gui.pages.assessment as assessment_module
import webhawk.gui.pages.authorized_targets as authorized_targets_module


SECRET_COOKIE_VALUE = "WEBHAWK_E2E_SECRET_DO_NOT_LEAK"


class ControlledHTTPHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"WebHawk controlled integration test."

        self.send_response(200)
        self.send_header(
            "Content-Type",
            "text/plain; charset=utf-8",
        )
        self.send_header(
            "Content-Length",
            str(len(body)),
        )
        self.send_header(
            "Set-Cookie",
            f"sessionid={SECRET_COOKIE_VALUE}; Path=/",
        )
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


@pytest.fixture
def qt_app():
    app = QApplication.instance()

    if app is None:
        app = QApplication([])

    yield app

    app.processEvents()


def wait_for_worker(page, timeout_ms=15000):
    """
    Wait for the actual QThread worker without blocking Qt's
    event processing.
    """
    worker = page._worker

    assert worker is not None, "Expected a worker to be running."

    loop = QEventLoop()

    poll_timer = QTimer()
    poll_timer.setInterval(10)

    timeout_timer = QTimer()
    timeout_timer.setSingleShot(True)

    def check_worker():
        if not worker.isRunning():
            loop.quit()

    poll_timer.timeout.connect(check_worker)
    timeout_timer.timeout.connect(loop.quit)

    poll_timer.start()
    timeout_timer.start(timeout_ms)

    if worker.isRunning():
        loop.exec()

    poll_timer.stop()
    timeout_timer.stop()

    QApplication.processEvents()

    if worker.isRunning():
        worker.wait(5000)
        QApplication.processEvents()

    assert not worker.isRunning(), "Worker did not finish within the timeout."

    QApplication.processEvents()

    assert page._worker is None, (
        "The GUI did not correctly clear its completed worker reference."
    )


def test_complete_authorized_assessment_workflow(
    qt_app,
    tmp_path,
    monkeypatch,
):
    server = ThreadingHTTPServer(
        ("127.0.0.1", 0),
        ControlledHTTPHandler,
    )

    server_thread = threading.Thread(
        target=server.serve_forever,
        daemon=True,
    )

    window = None

    try:
        server_thread.start()

        target_url = (
            f"http://127.0.0.1:{server.server_port}/"
        )

        # Use a real temporary authorization store.
        store = AuthorizationStore(
            tmp_path / "authorization_profiles.json"
        )

        profile = AuthorizationProfile(
            name="Loopback Integration Lab",
            authorized_hosts=("127.0.0.1",),
            authorized_networks=("127.0.0.0/8",),
            allow_loopback=True,
        )

        store.save_profile(profile)

        assert len(store.list_profiles()) == 1

        # Both real GUI pages must use the same temporary store.
        monkeypatch.setattr(
            assessment_module,
            "AuthorizationStore",
            lambda: store,
        )

        monkeypatch.setattr(
            authorized_targets_module,
            "AuthorizationStore",
            lambda: store,
        )

        # Construct the actual application window.
        window = WebHawkMainWindow()
        window.show()
        qt_app.processEvents()

        # ---------------------------------------------------------
        # 1. Verify the Authorized Targets page.
        # ---------------------------------------------------------

        window._navigate(4)
        qt_app.processEvents()

        authorized_page = window.pages.widget(4)

        assert authorized_page.store is store

        authorized_page.refresh_profiles()
        qt_app.processEvents()

        table_widgets = authorized_page.findChildren(
            QTableWidget
        )

        visible_table_text = []

        for table in table_widgets:
            for row in range(table.rowCount()):
                for column in range(table.columnCount()):
                    item = table.item(row, column)

                    if item is not None:
                        visible_table_text.append(item.text())

        assert any(
            "Loopback Integration Lab" in text
            for text in visible_table_text
        ), "The saved authorization profile was not displayed."

        # ---------------------------------------------------------
        # 2. Verify the Assessment page loads that profile.
        # ---------------------------------------------------------

        window._navigate(1)
        qt_app.processEvents()

        assessment_page = window.pages.widget(1)

        assert assessment_page.store is store

        profile_index = assessment_page.profile_combo.findText(
            "Loopback Integration Lab"
        )

        assert profile_index >= 0, (
            "The assessment page did not load the authorization profile."
        )

        assessment_page.profile_combo.setCurrentIndex(
            profile_index
        )

        assessment_page.target_input.setText(target_url)

        qt_app.processEvents()

        assert assessment_page.validate_button.isEnabled()

        # ---------------------------------------------------------
        # 3. Perform real authorization preview.
        # ---------------------------------------------------------

        assessment_page.validate_button.click()

        wait_for_worker(assessment_page)

        assert assessment_page._approved_target is not None

        assert (
            assessment_page._approved_target.hostname
            == "127.0.0.1"
        )

        assert assessment_page.run_button.isEnabled()

        assert (
            "Target authorization successful"
            in assessment_page.status_label.text()
        )

        # ---------------------------------------------------------
        # 4. Run the actual assessment pipeline.
        # ---------------------------------------------------------

        assessment_page.run_button.click()

        wait_for_worker(assessment_page)

        assert (
            "Assessment finished: COMPLETED"
            in assessment_page.execution_status_label.text()
        )

        findings_text = (
            assessment_page.findings_output.toPlainText()
        )

        assert "Cookie missing HttpOnly attribute" in findings_text

        assert "Cookie missing SameSite attribute" in findings_text

        # ---------------------------------------------------------
        # 5. Verify sensitive cookie values are not disclosed.
        # ---------------------------------------------------------

        assert SECRET_COOKIE_VALUE not in findings_text

        assert "sessionid" in findings_text

        assert assessment_page._worker is None

    finally:
        # Close the window only after the workers have completed.
        if window is not None:
            assessment_page = window.pages.widget(1)

            if assessment_page._worker is not None:
                worker = assessment_page._worker

                if worker.isRunning():
                    worker.wait(10000)

                qt_app.processEvents()

            window.close()
            qt_app.processEvents()

        server.shutdown()
        server.server_close()
        server_thread.join(timeout=5)
