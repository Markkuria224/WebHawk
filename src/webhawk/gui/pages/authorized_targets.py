from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QPlainTextEdit,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from pydantic import ValidationError

from webhawk.core.authorization import AuthorizationProfile
from webhawk.core.authorization_store import (
    AuthorizationProfileConflictError,
    AuthorizationStore,
    AuthorizationStoreError,
)


class AuthorizationProfileDialog(QDialog):
    """Dialog for creating or editing an authorization profile."""

    def __init__(self, profile=None, parent=None):
        super().__init__(parent)

        self.profile = profile

        self.setWindowTitle(
            "Edit Authorization Profile"
            if profile is not None
            else "Create Authorization Profile"
        )
        self.setMinimumWidth(540)

        layout = QVBoxLayout(self)
        layout.setSpacing(12)

        heading = QLabel(
            "Profile Details"
            if profile is None
            else "Update Profile Scope"
        )
        heading.setObjectName("CardHeading")
        layout.addWidget(heading)

        layout.addWidget(QLabel("Profile name"))

        self.name_input = QLineEdit()
        self.name_input.setPlaceholderText("e.g. Internal Lab")
        self.name_input.setMaxLength(80)

        if profile is not None:
            self.name_input.setText(profile.name)
            self.name_input.setToolTip(
                "You can rename this authorization profile."
            )

        layout.addWidget(self.name_input)

        layout.addWidget(QLabel("Authorized hostnames"))

        self.hosts_input = QPlainTextEdit()
        self.hosts_input.setPlaceholderText(
            "lab.example.com\n"
            "staging.example.com\n"
            "192.0.2.10"
        )
        self.hosts_input.setMaximumHeight(110)
        layout.addWidget(self.hosts_input)

        hosts_help = QLabel(
            "Enter one hostname or IP address per line."
        )
        hosts_help.setObjectName("Muted")
        layout.addWidget(hosts_help)

        layout.addWidget(QLabel("Authorized network ranges"))

        self.networks_input = QPlainTextEdit()
        self.networks_input.setPlaceholderText(
            "192.168.1.0/24\n"
            "10.10.0.0/16\n"
            "127.0.0.1/32"
        )
        self.networks_input.setMaximumHeight(110)
        layout.addWidget(self.networks_input)

        networks_help = QLabel(
            "Enter one CIDR network per line. "
            "Only include ranges you are authorized to assess."
        )
        networks_help.setObjectName("Muted")
        networks_help.setWordWrap(True)
        layout.addWidget(networks_help)

        self.loopback_checkbox = QCheckBox(
            "Allow loopback assessment (localhost)"
        )
        self.loopback_checkbox.setToolTip(
            "Requires an explicitly authorized loopback network."
        )
        layout.addWidget(self.loopback_checkbox)

        if profile is not None:
            self.hosts_input.setPlainText(
                "\n".join(profile.authorized_hosts)
            )
            self.networks_input.setPlainText(
                "\n".join(profile.authorized_networks)
            )
            self.loopback_checkbox.setChecked(
                profile.allow_loopback
            )

        self.error_label = QLabel("")
        self.error_label.setWordWrap(True)
        self.error_label.setStyleSheet("color: #F87171;")
        layout.addWidget(self.error_label)

        buttons = QDialogButtonBox(
            QDialogButtonBox.Save | QDialogButtonBox.Cancel
        )
        buttons.accepted.connect(self.validate_and_accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    @staticmethod
    def _parse_entries(value):
        return tuple(
            line.strip()
            for line in value.splitlines()
            if line.strip()
        )

    def validate_and_accept(self):
        try:
            AuthorizationProfile(
                name=self.name_input.text(),
                authorized_hosts=self._parse_entries(
                    self.hosts_input.toPlainText()
                ),
                authorized_networks=self._parse_entries(
                    self.networks_input.toPlainText()
                ),
                allow_loopback=self.loopback_checkbox.isChecked(),
            )

        except (ValidationError, ValueError, TypeError) as exc:
            self.error_label.setText(str(exc))
            return

        self.error_label.clear()
        self.accept()

    def get_profile(self):
        """Return the validated profile represented by this dialog."""

        return AuthorizationProfile(
            name=self.name_input.text(),
            authorized_hosts=self._parse_entries(
                self.hosts_input.toPlainText()
            ),
            authorized_networks=self._parse_entries(
                self.networks_input.toPlainText()
            ),
            allow_loopback=self.loopback_checkbox.isChecked(),
        )


class AuthorizedTargetsPage(QWidget):
    """Workspace for managing locally stored authorization profiles."""

    def __init__(self, store=None, parent=None):
        super().__init__(parent)

        self.store = store or AuthorizationStore()
        self.profiles = ()

        self._build_ui()
        self.refresh_profiles()

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(28, 24, 28, 24)
        root.setSpacing(18)

        title = QLabel("Authorized Targets")
        title.setObjectName("PageTitle")
        root.addWidget(title)

        subtitle = QLabel(
            "Manage the hostnames and network ranges declared "
            "within your assessment scope."
        )
        subtitle.setObjectName("PageSubtitle")
        root.addWidget(subtitle)

        notice = QFrame()
        notice.setObjectName("Card")
        notice_layout = QVBoxLayout(notice)

        notice_title = QLabel("Authorization responsibility")
        notice_title.setObjectName("CardHeading")
        notice_layout.addWidget(notice_title)

        notice_text = QLabel(
            "Profiles record the scope you declare for WebHawk. "
            "Saving a profile does not establish ownership, "
            "legal permission, or authorization to assess a target. "
            "Only add assets you are explicitly permitted to test."
        )
        notice_text.setObjectName("CardDescription")
        notice_text.setWordWrap(True)
        notice_layout.addWidget(notice_text)

        root.addWidget(notice)

        section_header = QHBoxLayout()

        section_title = QLabel("Saved Authorization Profiles")
        section_title.setObjectName("CardHeading")
        section_header.addWidget(section_title)

        section_header.addStretch()

        self.create_button = QPushButton("+ New Profile")
        self.create_button.clicked.connect(self.create_profile)
        section_header.addWidget(self.create_button)

        self.edit_button = QPushButton("Edit")
        self.edit_button.setEnabled(False)
        self.edit_button.clicked.connect(self.edit_profile)
        section_header.addWidget(self.edit_button)

        self.delete_button = QPushButton("Delete")
        self.delete_button.setEnabled(False)
        self.delete_button.clicked.connect(self.delete_profile)
        section_header.addWidget(self.delete_button)

        root.addLayout(section_header)

        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(
            ["Profile Name", "Authorized Hosts", "Networks", "Loopback"]
        )
        self.table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        self.table.setSelectionMode(
            QTableWidget.SelectionMode.SingleSelection
        )
        self.table.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers
        )
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)

        header = self.table.horizontalHeader()
        header.setStretchLastSection(True)
        header.setSectionResizeMode(0, header.ResizeMode.Stretch)
        header.setSectionResizeMode(1, header.ResizeMode.Stretch)
        header.setSectionResizeMode(2, header.ResizeMode.Stretch)

        self.table.itemSelectionChanged.connect(
            self._update_selection_actions
        )

        root.addWidget(self.table, 1)

        self.status_label = QLabel("")
        self.status_label.setObjectName("Muted")
        self.status_label.setWordWrap(True)
        root.addWidget(self.status_label)

        refresh_button = QPushButton("Refresh Profiles")
        refresh_button.clicked.connect(self.refresh_profiles)
        root.addWidget(refresh_button, alignment=Qt.AlignmentFlag.AlignRight)

    def _selected_profile(self):
        selected_rows = self.table.selectionModel().selectedRows()

        if not selected_rows:
            return None

        index = selected_rows[0].row()

        if index < 0 or index >= len(self.profiles):
            return None

        return self.profiles[index]

    def _update_selection_actions(self):
        has_selection = self._selected_profile() is not None

        self.edit_button.setEnabled(has_selection)
        self.delete_button.setEnabled(has_selection)

    def refresh_profiles(self):
        self.table.clearSelection()

        try:
            self.profiles = self.store.list_profiles()

        except AuthorizationStoreError as exc:
            self.profiles = ()
            self.table.setRowCount(0)
            self.status_label.setText(
                f"Storage error: {exc}"
            )
            self._update_selection_actions()
            return

        self.table.setRowCount(len(self.profiles))

        for row, profile in enumerate(self.profiles):
            values = (
                profile.name,
                str(len(profile.authorized_hosts)),
                str(len(profile.authorized_networks)),
                "Enabled" if profile.allow_loopback else "Disabled",
            )

            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setFlags(
                    item.flags()
                    & ~Qt.ItemFlag.ItemIsEditable
                )

                if column in (1, 2):
                    item.setTextAlignment(
                        Qt.AlignmentFlag.AlignCenter
                    )

                self.table.setItem(row, column, item)

        if not self.profiles:
            self.status_label.setText(
                "No authorization profiles have been created yet."
            )
        else:
            self.status_label.setText(
                f"{len(self.profiles)} authorization profile(s) loaded."
            )

        self._update_selection_actions()

    def create_profile(self):
        dialog = AuthorizationProfileDialog(parent=self)

        if dialog.exec() != QDialog.DialogCode.Accepted:
            return

        try:
            profile = dialog.get_profile()

            if self.store.get_profile(profile.name) is not None:
                QMessageBox.warning(
                    self,
                    "Profile Already Exists",
                    "A profile with this name already exists. "
                    "Choose another name or edit the existing profile.",
                )
                return

            self.store.save_profile(profile)

        except ValidationError as exc:
            QMessageBox.warning(
                self,
                "Invalid Profile",
                str(exc),
            )
            return

        except AuthorizationStoreError as exc:
            QMessageBox.critical(
                self,
                "Storage Error",
                str(exc),
            )
            return

        self.refresh_profiles()
        self.status_label.setText(
            f"Profile '{profile.name}' created successfully."
        )

    def edit_profile(self):
        profile = self._selected_profile()

        if profile is None:
            return

        dialog = AuthorizationProfileDialog(
            profile=profile,
            parent=self,
        )

        if dialog.exec() != QDialog.DialogCode.Accepted:
            return

        try:
            updated_profile = dialog.get_profile()
            self.store.rename_profile(profile.name, updated_profile)

        except AuthorizationProfileConflictError as exc:
            QMessageBox.warning(
                self,
                "Duplicate Profile Name",
                str(exc),
            )
            return

        except ValidationError as exc:
            QMessageBox.warning(
                self,
                "Invalid Profile",
                str(exc),
            )
            return

        except AuthorizationStoreError as exc:
            QMessageBox.critical(
                self,
                "Storage Error",
                str(exc),
            )
            return

        self.refresh_profiles()
        self.status_label.setText(
            f"Profile '{updated_profile.name}' updated successfully."
        )

    def delete_profile(self):
        profile = self._selected_profile()

        if profile is None:
            return

        confirmation = QMessageBox.question(
            self,
            "Delete Authorization Profile",
            f"Delete the profile '{profile.name}'?\n\n"
            "This action cannot be undone.",
            QMessageBox.StandardButton.Yes
            | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel,
        )

        if confirmation != QMessageBox.StandardButton.Yes:
            return

        try:
            deleted = self.store.delete_profile(profile.name)

        except AuthorizationStoreError as exc:
            QMessageBox.critical(
                self,
                "Storage Error",
                str(exc),
            )
            return

        if not deleted:
            QMessageBox.warning(
                self,
                "Profile Not Found",
                "The selected profile no longer exists.",
            )

        self.refresh_profiles()

        if deleted:
            self.status_label.setText(
                f"Profile '{profile.name}' deleted."
            )
