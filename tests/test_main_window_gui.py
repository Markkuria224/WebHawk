import sys

import pytest
from PySide6.QtWidgets import QApplication

from webhawk.gui.main_window import (
    AssessmentPage,
    AuthorizedTargetsPage,
    DashboardPage,
    PlaceholderPage,
    WebHawkMainWindow,
    create_main_window,
)


@pytest.fixture(scope="session")
def qt_app():
    app = QApplication.instance() or QApplication([])
    yield app


@pytest.fixture
def window(qt_app):
    instance = WebHawkMainWindow()
    instance.show()
    yield instance
    instance.close()
    instance.deleteLater()
    qt_app.processEvents()


def test_main_window_initializes_with_correct_identity(window):
    assert window.windowTitle() == "WebHawk"
    assert window.size().width() == 1280
    assert window.size().height() == 800
    assert window.minimumWidth() == 1050
    assert window.minimumHeight() == 680


def test_dashboard_is_initial_page(window):
    assert window.pages.currentIndex() == 0
    assert isinstance(window.pages.currentWidget(), DashboardPage)
    assert window.navigation_buttons[0].isChecked()


def test_navigation_contains_all_expected_sections(window):
    expected = [
        "Dashboard",
        "Assessment",
        "Findings",
        "Evidence",
        "Authorized Targets",
        "Settings",
    ]

    actual = [button.text() for button in window.navigation_buttons]

    assert actual == expected
    assert len(window.navigation_buttons) == len(window.NAVIGATION)


@pytest.mark.parametrize(
    ("index", "expected_type"),
    [
        (0, DashboardPage),
        (1, AssessmentPage),
        (2, PlaceholderPage),
        (3, PlaceholderPage),
        (4, AuthorizedTargetsPage),
        (5, PlaceholderPage),
    ],
)
def test_navigation_opens_expected_page(window, index, expected_type):
    window.navigation_buttons[index].click()

    assert window.pages.currentIndex() == index
    assert isinstance(window.pages.currentWidget(), expected_type)


@pytest.mark.parametrize(
    ("index", "section"),
    [
        (0, "Dashboard"),
        (1, "Assessment"),
        (2, "Findings"),
        (3, "Evidence"),
        (4, "Authorized Targets"),
        (5, "Settings"),
    ],
)
def test_navigation_updates_status_bar(window, index, section):
    window.navigation_buttons[index].click()

    assert window.statusBar().currentMessage() == f"WebHawk | {section}"


def test_navigation_keeps_only_active_button_checked(window):
    for selected_index in range(len(window.navigation_buttons)):
        window.navigation_buttons[selected_index].click()

        checked_indexes = [
            index
            for index, button in enumerate(window.navigation_buttons)
            if button.isChecked()
        ]

        assert checked_indexes == [selected_index]


def test_navigation_does_not_recreate_page_instances(window):
    original_pages = [
        window.pages.widget(index)
        for index in range(window.pages.count())
    ]

    for index in reversed(range(window.pages.count())):
        window.navigation_buttons[index].click()

    current_pages = [
        window.pages.widget(index)
        for index in range(window.pages.count())
    ]

    assert current_pages == original_pages


def test_main_window_contains_exactly_six_pages(window):
    assert window.pages.count() == 6


def test_factory_returns_main_window(qt_app):
    instance = create_main_window()

    try:
        assert isinstance(instance, WebHawkMainWindow)
        assert instance.windowTitle() == "WebHawk"
    finally:
        instance.close()
        instance.deleteLater()
        qt_app.processEvents()


def test_main_window_starts_with_ready_status(window):
    assert window.statusBar().currentMessage() == "WebHawk | Ready"


def test_main_window_blocks_close_while_assessment_worker_runs(
    window,
    monkeypatch,
):
    assessment_page = window.pages.widget(1)
    worker_state = {"running": True}

    monkeypatch.setattr(
        assessment_page,
        "_worker_running",
        lambda: worker_state["running"],
    )

    closed = window.close()

    assert closed is False
    assert window.isVisible()
    assert window.statusBar().currentMessage() == (
        "An operation is still running. "
        "Wait for it to finish before closing WebHawk."
    )

    worker_state["running"] = False

    assert window.close() is True
