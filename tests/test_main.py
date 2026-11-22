import sys

from webhawk import main as main_module


def test_main_initializes_and_runs_application(monkeypatch):
    calls = []
    expected_exit_code = 7

    class FakeApplication:
        def __init__(self, arguments):
            calls.append(("application_created", arguments))

        def setApplicationName(self, name):
            calls.append(("application_name", name))

        def setOrganizationName(self, name):
            calls.append(("organization_name", name))

        def exec(self):
            calls.append(("event_loop_started",))
            return expected_exit_code

    class FakeWindow:
        def show(self):
            calls.append(("window_shown",))

    fake_window = FakeWindow()

    monkeypatch.setattr(
        main_module,
        "QApplication",
        FakeApplication,
    )

    monkeypatch.setattr(
        main_module,
        "create_main_window",
        lambda: calls.append(("window_created",)) or fake_window,
    )

    monkeypatch.setattr(sys, "argv", ["webhawk"])

    result = main_module.main()

    assert result == expected_exit_code

    assert calls == [
        ("application_created", ["webhawk"]),
        ("application_name", "WebHawk"),
        ("organization_name", "WebHawk"),
        ("window_created",),
        ("window_shown",),
        ("event_loop_started",),
    ]
