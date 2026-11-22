import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest

from PySide6.QtWidgets import QApplication, QDialog

from webhawk.core.authorization import AuthorizationProfile
from webhawk.core.authorization_store import (
    AuthorizationStore,
    AuthorizationStoreCorruptionError,
    AuthorizationStoreError,
)
from webhawk.gui.pages.authorized_targets import (
    AuthorizationProfileDialog,
    AuthorizedTargetsPage,
)


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
    widget = AuthorizedTargetsPage(store)
    widget.show()

    yield widget

    widget.close()
    widget.deleteLater()
    qt_app.processEvents()


@pytest.fixture
def empty_page(qt_app, tmp_path):
    store = AuthorizationStore(tmp_path / "empty.json")
    widget = AuthorizedTargetsPage(store)
    widget.show()

    yield widget

    widget.close()
    widget.deleteLater()
    qt_app.processEvents()


def test_new_profile_dialog_initializes_empty_fields(qt_app):
    dialog = AuthorizationProfileDialog()

    assert dialog.windowTitle() == "Create Authorization Profile"
    assert dialog.name_input.text() == ""
    assert dialog.hosts_input.toPlainText() == ""
    assert dialog.networks_input.toPlainText() == ""
    assert not dialog.loopback_checkbox.isChecked()

    dialog.close()


def test_existing_profile_dialog_loads_profile(qt_app):
    profile = AuthorizationProfile(
        name="Internal Lab",
        authorized_hosts=("lab.example", "staging.example"),
        authorized_networks=(
            "192.168.1.0/24",
            "127.0.0.1/32",
        ),
        allow_loopback=True,
    )

    dialog = AuthorizationProfileDialog(profile)

    assert dialog.windowTitle() == "Edit Authorization Profile"
    assert dialog.name_input.text() == "Internal Lab"
    assert set(dialog.hosts_input.toPlainText().splitlines()) == {
        "lab.example",
        "staging.example",
    }
    assert set(dialog.networks_input.toPlainText().splitlines()) == {
        "192.168.1.0/24",
        "127.0.0.1/32",
    }
    assert dialog.loopback_checkbox.isChecked()

    dialog.close()


def test_dialog_parses_and_accepts_valid_profile(qt_app):
    dialog = AuthorizationProfileDialog()

    dialog.name_input.setText(" Internal Lab ")
    dialog.hosts_input.setPlainText(
        "lab.example\n\n staging.example \n"
    )
    dialog.networks_input.setPlainText(
        "192.168.1.0/24\n"
    )

    dialog.validate_and_accept()

    assert dialog.result() == QDialog.DialogCode.Accepted

    profile = dialog.get_profile()

    assert profile.name == "Internal Lab"
    assert profile.authorized_hosts == (
        "lab.example",
        "staging.example",
    )
    assert profile.authorized_networks == (
        "192.168.1.0/24",
    )

    dialog.close()


def test_dialog_rejects_invalid_hostname_without_accepting(qt_app):
    dialog = AuthorizationProfileDialog()

    dialog.name_input.setText("Invalid Scope")
    dialog.hosts_input.setPlainText("*.example.com")

    dialog.validate_and_accept()

    assert dialog.result() == QDialog.DialogCode.Rejected
    assert dialog.error_label.text()

    dialog.close()


def test_dialog_rejects_loopback_without_authorized_network(qt_app):
    dialog = AuthorizationProfileDialog()

    dialog.name_input.setText("Loopback Lab")
    dialog.hosts_input.setPlainText("localhost")
    dialog.loopback_checkbox.setChecked(True)

    dialog.validate_and_accept()

    assert dialog.result() == QDialog.DialogCode.Rejected
    assert "loopback" in dialog.error_label.text().lower()

    dialog.close()


def test_dialog_returns_valid_loopback_profile(qt_app):
    dialog = AuthorizationProfileDialog()

    dialog.name_input.setText("Localhost Lab")
    dialog.hosts_input.setPlainText("localhost")
    dialog.networks_input.setPlainText("127.0.0.1/32")
    dialog.loopback_checkbox.setChecked(True)

    dialog.validate_and_accept()

    profile = dialog.get_profile()

    assert profile.allow_loopback is True
    assert profile.authorized_networks == ("127.0.0.1/32",)

    dialog.close()


def test_saved_profiles_are_displayed(page):
    assert page.table.rowCount() == 2

    assert page.table.item(0, 0).text() == "Local Lab"
    assert page.table.item(1, 0).text() == "Secondary Lab"

    assert page.table.item(0, 1).text() == "1"
    assert page.table.item(0, 2).text() == "1"
    assert page.table.item(0, 3).text() == "Disabled"

    assert "2 authorization profile(s) loaded" in (
        page.status_label.text()
    )


def test_empty_store_displays_no_profile_message(empty_page):
    assert empty_page.table.rowCount() == 0

    assert "No authorization profiles" in (
        empty_page.status_label.text()
    )

    assert not empty_page.edit_button.isEnabled()
    assert not empty_page.delete_button.isEnabled()


def test_selection_enables_edit_and_delete_buttons(page):
    assert not page.edit_button.isEnabled()
    assert not page.delete_button.isEnabled()

    page.table.selectRow(0)

    assert page.edit_button.isEnabled()
    assert page.delete_button.isEnabled()

    page.table.clearSelection()

    assert not page.edit_button.isEnabled()
    assert not page.delete_button.isEnabled()


def test_refresh_storage_error_clears_profiles_and_disables_actions(
    page,
    monkeypatch,
):
    def fail_list_profiles():
        raise AuthorizationStoreCorruptionError(
            "Simulated storage corruption."
        )

    monkeypatch.setattr(
        page.store,
        "list_profiles",
        fail_list_profiles,
    )

    page.table.selectRow(0)

    page.refresh_profiles()

    assert page.profiles == ()
    assert page.table.rowCount() == 0
    assert "Storage error" in page.status_label.text()
    assert not page.edit_button.isEnabled()
    assert not page.delete_button.isEnabled()



def test_create_profile_saves_and_refreshes_table(
    page,
    monkeypatch,
):
    new_profile = AuthorizationProfile(
        name="New Lab",
        authorized_hosts=("new.example",),
        authorized_networks=("172.16.0.0/16",),
    )

    monkeypatch.setattr(
        AuthorizationProfileDialog,
        "exec",
        lambda self: QDialog.DialogCode.Accepted,
    )

    monkeypatch.setattr(
        AuthorizationProfileDialog,
        "get_profile",
        lambda self: new_profile,
    )

    page.create_profile()

    saved_profile = page.store.get_profile("New Lab")

    assert saved_profile is not None
    assert saved_profile.name == "New Lab"
    assert page.table.rowCount() == 3
    assert any(
        profile.name == "New Lab"
        for profile in page.profiles
    )
    assert "created successfully" in (
        page.status_label.text().lower()
    )

def test_create_duplicate_profile_does_not_overwrite_existing_profile(
    page,
    monkeypatch,
):
    original_profile = page.store.get_profile("Local Lab")

    duplicate_profile = AuthorizationProfile(
        name="Local Lab",
        authorized_hosts=("attacker.example",),
        authorized_networks=("172.16.0.0/16",),
    )

    warnings = []

    monkeypatch.setattr(
        AuthorizationProfileDialog,
        "exec",
        lambda self: QDialog.DialogCode.Accepted,
    )

    monkeypatch.setattr(
        AuthorizationProfileDialog,
        "get_profile",
        lambda self: duplicate_profile,
    )

    monkeypatch.setattr(
        "webhawk.gui.pages.authorized_targets.QMessageBox.warning",
        lambda *args: warnings.append(args),
    )

    def unexpected_save(profile):
        raise AssertionError(
            "Duplicate profile must not be saved."
        )

    monkeypatch.setattr(
        page.store,
        "save_profile",
        unexpected_save,
    )

    page.create_profile()

    unchanged_profile = page.store.get_profile("Local Lab")

    assert unchanged_profile == original_profile
    assert unchanged_profile.authorized_hosts == (
        "lab.example",
    )
    assert len(warnings) == 1
    assert page.table.rowCount() == 2

def test_create_profile_handles_storage_failure(
    page,
    monkeypatch,
):
    new_profile = AuthorizationProfile(
        name="Storage Failure Lab",
        authorized_hosts=("storage.example",),
        authorized_networks=("172.16.0.0/16",),
    )

    critical_errors = []

    monkeypatch.setattr(
        AuthorizationProfileDialog,
        "exec",
        lambda self: QDialog.DialogCode.Accepted,
    )

    monkeypatch.setattr(
        AuthorizationProfileDialog,
        "get_profile",
        lambda self: new_profile,
    )

    def fail_save(profile):
        raise AuthorizationStoreError(
            "Simulated disk write failure."
        )

    monkeypatch.setattr(
        page.store,
        "save_profile",
        fail_save,
    )

    monkeypatch.setattr(
        "webhawk.gui.pages.authorized_targets.QMessageBox.critical",
        lambda *args: critical_errors.append(args),
    )

    page.create_profile()

    assert page.store.get_profile("Storage Failure Lab") is None
    assert page.table.rowCount() == 2
    assert len(critical_errors) == 1
    assert "disk write failure" in (
        str(critical_errors[0]).lower()
    )


def test_edit_profile_renames_and_preserves_original_scope(
    page,
    monkeypatch,
):
    original_profile = page.store.get_profile("Local Lab")

    updated_profile = AuthorizationProfile(
        name="Renamed Lab",
        authorized_hosts=original_profile.authorized_hosts,
        authorized_networks=original_profile.authorized_networks,
        allow_loopback=original_profile.allow_loopback,
    )

    page.table.selectRow(0)

    monkeypatch.setattr(
        AuthorizationProfileDialog,
        "exec",
        lambda self: QDialog.DialogCode.Accepted,
    )

    monkeypatch.setattr(
        AuthorizationProfileDialog,
        "get_profile",
        lambda self: updated_profile,
    )

    page.edit_profile()

    renamed_profile = page.store.get_profile("Renamed Lab")

    assert renamed_profile is not None
    assert page.store.get_profile("Local Lab") is None
    assert renamed_profile.authorized_hosts == (
        original_profile.authorized_hosts
    )
    assert renamed_profile.authorized_networks == (
        original_profile.authorized_networks
    )
    assert renamed_profile.created_at == original_profile.created_at
    assert page.table.rowCount() == 2
    assert any(
        profile.name == "Renamed Lab"
        for profile in page.profiles
    )

def test_edit_profile_rejects_duplicate_name_without_overwriting(
    page,
    monkeypatch,
):
    original_local = page.store.get_profile("Local Lab")
    original_secondary = page.store.get_profile("Secondary Lab")

    conflicting_profile = AuthorizationProfile(
        name="Secondary Lab",
        authorized_hosts=("replacement.example",),
        authorized_networks=("172.16.0.0/16",),
    )

    warnings = []

    page.table.selectRow(0)

    monkeypatch.setattr(
        AuthorizationProfileDialog,
        "exec",
        lambda self: QDialog.DialogCode.Accepted,
    )

    monkeypatch.setattr(
        AuthorizationProfileDialog,
        "get_profile",
        lambda self: conflicting_profile,
    )

    monkeypatch.setattr(
        "webhawk.gui.pages.authorized_targets.QMessageBox.warning",
        lambda *args: warnings.append(args),
    )

    page.edit_profile()

    unchanged_local = page.store.get_profile("Local Lab")
    unchanged_secondary = page.store.get_profile("Secondary Lab")

    assert unchanged_local == original_local
    assert unchanged_secondary == original_secondary
    assert unchanged_local.authorized_hosts == ("lab.example",)
    assert unchanged_secondary.authorized_hosts == (
        "secondary.example",
    )
    assert len(warnings) == 1
    assert page.table.rowCount() == 2

def test_delete_profile_cancel_preserves_profile(
    page,
    monkeypatch,
):
    original_profile = page.store.get_profile("Local Lab")

    page.table.selectRow(0)

    monkeypatch.setattr(
        "webhawk.gui.pages.authorized_targets.QMessageBox.question",
        lambda *args: (
            __import__(
                "PySide6.QtWidgets",
                fromlist=["QMessageBox"],
            ).QMessageBox.StandardButton.Cancel
        ),
    )

    page.delete_profile()

    assert page.store.get_profile("Local Lab") == original_profile
    assert page.table.rowCount() == 2
    assert len(page.profiles) == 2

def test_delete_profile_confirm_removes_profile(
    page,
    monkeypatch,
):
    page.table.selectRow(0)

    monkeypatch.setattr(
        "webhawk.gui.pages.authorized_targets.QMessageBox.question",
        lambda *args: (
            __import__(
                "PySide6.QtWidgets",
                fromlist=["QMessageBox"],
            ).QMessageBox.StandardButton.Yes
        ),
    )

    page.delete_profile()

    assert page.store.get_profile("Local Lab") is None
    assert page.store.get_profile("Secondary Lab") is not None
    assert page.table.rowCount() == 1
    assert len(page.profiles) == 1
    assert page.profiles[0].name == "Secondary Lab"

def test_delete_profile_handles_storage_failure(
    page,
    monkeypatch,
):
    critical_errors = []

    page.table.selectRow(0)

    monkeypatch.setattr(
        "webhawk.gui.pages.authorized_targets.QMessageBox.question",
        lambda *args: (
            __import__(
                "PySide6.QtWidgets",
                fromlist=["QMessageBox"],
            ).QMessageBox.StandardButton.Yes
        ),
    )

    def fail_delete(name):
        raise AuthorizationStoreError(
            "Simulated deletion failure."
        )

    monkeypatch.setattr(
        page.store,
        "delete_profile",
        fail_delete,
    )

    monkeypatch.setattr(
        "webhawk.gui.pages.authorized_targets.QMessageBox.critical",
        lambda *args: critical_errors.append(args),
    )

    page.delete_profile()

    assert page.store.get_profile("Local Lab") is not None
    assert page.table.rowCount() == 2
    assert len(critical_errors) == 1
    assert "deletion failure" in str(
        critical_errors[0]
    ).lower()

def test_refresh_does_not_retain_selection_for_deleted_profile(page):
    page.table.selectRow(0)

    selected_before = page._selected_profile()

    assert selected_before is not None
    assert selected_before.name == "Local Lab"

    page.store.delete_profile("Local Lab")
    page.refresh_profiles()

    selected_after = page._selected_profile()

    assert selected_after is None
    assert not page.edit_button.isEnabled()
    assert not page.delete_button.isEnabled()
