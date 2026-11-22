import asyncio

from PySide6.QtCore import QThread, Signal, Qt
from PySide6.QtWidgets import (
    QComboBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from webhawk.core.authorization_store import (
    AuthorizationStore,
    AuthorizationStoreError,
)
from webhawk.core.pipeline import (
    AssessmentInputError,
    assess_target,
)
from webhawk.core.normalizer import NormalizationError
from webhawk.core.safety import (
    ApprovedTarget,
    TargetPolicy,
    TargetSafetyError,
    authorize_target,
)


class AuthorizationPreviewWorker(QThread):
    """Resolve and authorize a target outside the GUI thread."""

    succeeded = Signal(object)
    failed = Signal(str)

    def __init__(self, url: str, policy: TargetPolicy):
        super().__init__()
        self.url = url
        self.policy = policy

    def run(self):
        try:
            approved = authorize_target(self.url, self.policy)
            self.succeeded.emit(approved)

        except (NormalizationError, TargetSafetyError) as exc:
            self.failed.emit(str(exc).strip() or "Target authorization failed.")

        except Exception:
            self.failed.emit(
                "An unexpected internal error prevented target authorization."
            )


class AssessmentExecutionWorker(QThread):
    """Execute an assessment without blocking the GUI."""

    succeeded = Signal(object)
    failed = Signal(str)

    def __init__(self, url: str, policy: TargetPolicy):
        super().__init__()
        self.url = url
        self.policy = policy

    def run(self):
        try:
            result = asyncio.run(
                assess_target(
                    self.url,
                    self.policy,
                )
            )

            self.succeeded.emit(result)

        except AssessmentInputError as exc:
            self.failed.emit(exc.error.message)

        except Exception:
            # Do not expose internal exception messages to the GUI.
            self.failed.emit(
                "An unexpected internal error prevented the assessment."
            )


class AssessmentPage(QWidget):
    """Configure, authorize and execute a target assessment."""

    def __init__(self, store: AuthorizationStore | None = None):
        super().__init__()

        self.store = store or AuthorizationStore()

        self._worker = None
        self._approved_target: ApprovedTarget | None = None

        # Preserve the exact profile and URL used for authorization.
        self._preview_profile = None
        self._preview_url: str | None = None

        # Track the request currently being authorized.
        self._pending_preview_profile = None
        self._pending_preview_url: str | None = None

        self._build_ui()
        self._load_profiles()

    def _build_ui(self):
        # The outer layout holds a scrollable content area.
        page_layout = QVBoxLayout(self)
        page_layout.setContentsMargins(0, 0, 0, 0)
        page_layout.setSpacing(0)

        self.scroll_area = QScrollArea()
        self.scroll_area.setObjectName("AssessmentScrollArea")
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setFrameShape(QFrame.Shape.NoFrame)
        self.scroll_area.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff
        )
        self.scroll_area.setVerticalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAsNeeded
        )

        self.content_widget = QWidget()
        self.content_widget.setObjectName("AssessmentContent")

        layout = QVBoxLayout(self.content_widget)
        layout.setContentsMargins(32, 28, 32, 28)
        layout.setSpacing(18)

        self.scroll_area.setWidget(self.content_widget)
        page_layout.addWidget(self.scroll_area)

        heading = QLabel("Assessment Configuration")
        heading.setObjectName("PageTitle")

        subtitle = QLabel(
            "Select an authorization profile, validate a target "
            "and launch a controlled security assessment."
        )
        subtitle.setObjectName("PageSubtitle")
        subtitle.setWordWrap(True)

        layout.addWidget(heading)
        layout.addWidget(subtitle)

        # ---------------------------------------------------------
        # Target configuration
        # ---------------------------------------------------------

        configuration_card = QFrame()
        configuration_card.setObjectName("Card")

        configuration_layout = QVBoxLayout(configuration_card)
        configuration_layout.setContentsMargins(24, 22, 24, 22)
        configuration_layout.setSpacing(12)

        configuration_heading = QLabel("Target Configuration")
        configuration_heading.setObjectName("CardHeading")

        profile_label = QLabel("Authorization Profile")
        profile_label.setObjectName("CardDescription")

        self.profile_combo = QComboBox()
        self.profile_combo.setObjectName("AuthorizationProfileSelector")
        self.profile_combo.setMinimumHeight(38)

        target_label = QLabel("Target URL")
        target_label.setObjectName("CardDescription")

        self.target_input = QLineEdit()
        self.target_input.setObjectName("AssessmentTargetInput")
        self.target_input.setPlaceholderText("https://example.com")
        self.target_input.setMinimumHeight(38)

        button_layout = QHBoxLayout()
        button_layout.setSpacing(10)

        self.validate_button = QPushButton("Validate Target")
        self.validate_button.setObjectName("ValidateTargetButton")
        self.validate_button.setMinimumHeight(40)
        self.validate_button.setCursor(
            Qt.CursorShape.PointingHandCursor
        )
        self.validate_button.clicked.connect(
            self._validate_target
        )

        self.run_button = QPushButton("Run Assessment")
        self.run_button.setObjectName("RunAssessmentButton")
        self.run_button.setMinimumHeight(40)
        self.run_button.setCursor(
            Qt.CursorShape.PointingHandCursor
        )
        self.run_button.setEnabled(False)
        self.run_button.clicked.connect(
            self._run_assessment
        )

        button_layout.addWidget(self.validate_button)
        button_layout.addWidget(self.run_button)

        configuration_layout.addWidget(configuration_heading)
        configuration_layout.addWidget(profile_label)
        configuration_layout.addWidget(self.profile_combo)
        configuration_layout.addWidget(target_label)
        configuration_layout.addWidget(self.target_input)
        configuration_layout.addLayout(button_layout)

        layout.addWidget(configuration_card)

        # ---------------------------------------------------------
        # Authorization preview
        # ---------------------------------------------------------

        preview_card = QFrame()
        preview_card.setObjectName("Card")

        preview_layout = QVBoxLayout(preview_card)
        preview_layout.setContentsMargins(24, 22, 24, 22)
        preview_layout.setSpacing(12)

        preview_heading = QLabel("Authorization Preview")
        preview_heading.setObjectName("CardHeading")

        self.status_label = QLabel(
            "Waiting for target validation."
        )
        self.status_label.setObjectName("Muted")
        self.status_label.setWordWrap(True)

        self.normalized_url_label = QLabel(
            "Normalized URL: —"
        )
        self.normalized_url_label.setObjectName("CardDescription")
        self.normalized_url_label.setWordWrap(True)
        self.normalized_url_label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )

        self.hostname_label = QLabel("Hostname: —")
        self.hostname_label.setObjectName("CardDescription")
        self.hostname_label.setWordWrap(True)
        self.hostname_label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )

        self.addresses_label = QLabel(
            "Approved addresses: —"
        )
        self.addresses_label.setObjectName("CardDescription")
        self.addresses_label.setWordWrap(True)
        self.addresses_label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )

        preview_layout.addWidget(preview_heading)
        preview_layout.addWidget(self.status_label)
        preview_layout.addWidget(self.normalized_url_label)
        preview_layout.addWidget(self.hostname_label)
        preview_layout.addWidget(self.addresses_label)

        layout.addWidget(preview_card)

        # ---------------------------------------------------------
        # Assessment execution and results
        # ---------------------------------------------------------

        assessment_card = QFrame()
        assessment_card.setObjectName("Card")

        assessment_layout = QVBoxLayout(assessment_card)
        assessment_layout.setContentsMargins(24, 22, 24, 22)
        assessment_layout.setSpacing(12)

        assessment_heading = QLabel("Assessment Results")
        assessment_heading.setObjectName("CardHeading")

        self.execution_status_label = QLabel(
            "No assessment has been executed."
        )
        self.execution_status_label.setObjectName("Muted")
        self.execution_status_label.setWordWrap(True)

        self.progress_bar = QProgressBar()
        self.progress_bar.setObjectName("AssessmentProgress")
        self.progress_bar.setRange(0, 0)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setMaximumHeight(8)
        self.progress_bar.hide()

        self.findings_output = QPlainTextEdit()
        self.findings_output.setObjectName("AssessmentFindings")
        self.findings_output.setReadOnly(True)
        self.findings_output.setPlaceholderText(
            "Assessment findings will appear here."
        )
        self.findings_output.setMinimumHeight(180)

        assessment_layout.addWidget(assessment_heading)
        assessment_layout.addWidget(self.execution_status_label)
        assessment_layout.addWidget(self.progress_bar)
        assessment_layout.addWidget(self.findings_output)

        layout.addWidget(assessment_card)
        layout.addStretch()

        # ---------------------------------------------------------
        # Configuration change handling
        # ---------------------------------------------------------

        self.profile_combo.currentIndexChanged.connect(
            self._invalidate_preview
        )
        self.target_input.textChanged.connect(
            self._invalidate_preview
        )

        self._update_controls()

    # =============================================================
    # Profile management
    # =============================================================

    def _load_profiles(self):
        self.profile_combo.blockSignals(True)
        self.profile_combo.clear()

        try:
            profiles = self.store.list_profiles()

            for profile in profiles:
                self.profile_combo.addItem(
                    profile.name,
                    profile,
                )

            if profiles:
                self.status_label.setText(
                    "Select a target URL and validate it against "
                    "the selected authorization profile."
                )
            else:
                self.status_label.setText(
                    "No authorization profiles exist. Create one "
                    "under Authorized Targets first."
                )

        except Exception:
            self.status_label.setText(
                "Authorization profiles could not be loaded. "
                "Check the authorization profile storage."
            )

        finally:
            self.profile_combo.blockSignals(False)
            self._update_controls()

    @staticmethod
    def _build_policy(profile) -> TargetPolicy:
        return TargetPolicy(
            authorized_hosts=frozenset(
                profile.authorized_hosts
            ),
            authorized_networks=tuple(
                profile.authorized_networks
            ),
            allow_loopback=profile.allow_loopback,
        )

    # =============================================================
    # Control state
    # =============================================================

    def _worker_running(self) -> bool:
        return (
            self._worker is not None
            and self._worker.isRunning()
        )

    def _update_controls(self):
        running = self._worker is not None

        has_profile = self.profile_combo.currentIndex() >= 0
        has_url = bool(self.target_input.text().strip())

        self.validate_button.setEnabled(
            has_profile and has_url and not running
        )

        self.run_button.setEnabled(
            self._approved_target is not None
            and self._preview_profile is not None
            and not running
        )

        self.profile_combo.setEnabled(not running)
        self.target_input.setEnabled(not running)

    def _set_status(self, message: str, object_name="Muted"):
        self.status_label.setText(message)
        self.status_label.setObjectName(object_name)

        self.status_label.style().unpolish(self.status_label)
        self.status_label.style().polish(self.status_label)

    def _clear_preview(self):
        self._approved_target = None
        self._preview_profile = None
        self._preview_url = None
        self._pending_preview_profile = None
        self._pending_preview_url = None

        self.normalized_url_label.setText(
            "Normalized URL: —"
        )
        self.hostname_label.setText("Hostname: —")
        self.addresses_label.setText(
            "Approved addresses: —"
        )

    def _invalidate_preview(self, *_):
        self._clear_preview()

        self._set_status(
            "Configuration changed. Validate the target again."
        )

        self.execution_status_label.setText(
            "Assessment invalidated. No current assessment results."
        )
        self.execution_status_label.setObjectName("Muted")

        self.findings_output.clear()

        self._update_controls()

    # =============================================================
    # Authorization preview
    # =============================================================

    def _validate_target(self):
        if self._worker_running():
            return

        profile = self.profile_combo.currentData()
        url = self.target_input.text().strip()

        if profile is None:
            self._set_status(
                "Select an authorization profile first."
            )
            return

        if not url:
            self._set_status(
                "Enter a target URL first."
            )
            return

        policy = self._build_policy(profile)

        self._clear_preview()

        self.execution_status_label.setText(
            "Assessment invalidated. No current assessment results."
        )
        self.execution_status_label.setObjectName("Muted")
        self.findings_output.clear()

        self._set_status(
            "Validating authorization and resolving target addresses..."
        )

        self._update_controls()

        self._pending_preview_profile = profile
        self._pending_preview_url = url

        worker = AuthorizationPreviewWorker(url, policy)
        self._worker = worker

        self._update_controls()

        worker.succeeded.connect(
            self._on_validation_succeeded
        )
        worker.failed.connect(
            self._on_validation_failed
        )
        worker.finished.connect(
            self._on_worker_finished
        )

        worker.start()

    def _on_validation_succeeded(
        self,
        approved: ApprovedTarget,
    ):
        pending_profile = self._pending_preview_profile
        pending_url = self._pending_preview_url

        current_profile = self.profile_combo.currentData()
        current_url = self.target_input.text().strip()

        if (
            pending_profile is None
            or pending_url is None
            or current_profile != pending_profile
            or current_url != pending_url
        ):
            self._clear_preview()
            self._set_status(
                "Configuration changed during authorization. "
                "Validate the target again."
            )
            self._update_controls()
            return

        self._pending_preview_profile = None
        self._pending_preview_url = None

        self._approved_target = approved
        self._preview_profile = pending_profile
        self._preview_url = pending_url

        self.normalized_url_label.setText(
            f"Normalized URL: {approved.normalized_url}"
        )

        self.hostname_label.setText(
            f"Hostname: {approved.hostname}"
        )

        addresses = "\n".join(
            f"• {address}"
            for address in approved.approved_addresses
        )

        self.addresses_label.setText(
            f"Approved addresses:\n{addresses}"
        )

        self._set_status(
            "Target authorization successful. This is a preview. "
            "The target will be independently reauthorized when "
            "the assessment starts.",
            "StatusReady",
        )

        self._update_controls()

    def _on_validation_failed(self, message: str):
        pending_profile = self._pending_preview_profile
        pending_url = self._pending_preview_url

        current_profile = self.profile_combo.currentData()
        current_url = self.target_input.text().strip()

        configuration_changed = (
            pending_profile is None
            or pending_url is None
            or current_profile != pending_profile
            or current_url != pending_url
        )

        self._clear_preview()

        if configuration_changed:
            self._set_status(
                "Configuration changed during authorization. "
                "Validate the target again."
            )
        else:
            self._set_status(
                f"Authorization failed: {message}"
            )

        self._update_controls()

    # =============================================================
    # Assessment execution
    # =============================================================

    def _run_assessment(self):
        if self._worker_running():
            return

        if self._approved_target is None:
            self._set_status(
                "Validate the target before launching an assessment."
            )
            return

        preview_profile = self._preview_profile
        preview_url = self._preview_url

        if preview_profile is None or preview_url is None:
            self._invalidate_preview()
            return

        current_url = self.target_input.text().strip()

        if current_url != preview_url:
            self._invalidate_preview()
            return

        selected_profile = self.profile_combo.currentData()

        if selected_profile is None:
            self._invalidate_preview()
            self._set_status(
                "Select an authorization profile before launching."
            )
            return

        try:
            # Always retrieve the latest persisted profile.
            current_profile = self.store.get_profile(
                selected_profile.name
            )

        except AuthorizationStoreError:
            self._clear_preview()
            self._set_status(
                "Authorization storage could not be verified. "
                "Reload the profiles and validate again."
            )
            self._update_controls()
            return

        if current_profile is None:
            self._clear_preview()
            self._set_status(
                "The authorization profile no longer exists. "
                "Select another profile and validate again."
            )
            self._update_controls()
            return

        if current_profile != preview_profile:
            self._clear_preview()
            self._set_status(
                "The authorization profile changed after preview. "
                "Validate the target again."
            )
            self._update_controls()
            return

        policy = self._build_policy(current_profile)

        self.execution_status_label.setText(
            "Assessment running. Revalidating authorization and "
            "connecting to the approved target..."
        )
        self.execution_status_label.setObjectName("StatusReady")

        self.findings_output.clear()
        self.findings_output.setPlainText(
            "Assessment in progress...\n"
            "The HTTP response body is not retained."
        )

        self.progress_bar.show()

        self._update_controls()

        worker = AssessmentExecutionWorker(
            current_url,
            policy,
        )

        self._worker = worker

        self._update_controls()

        worker.succeeded.connect(
            self._on_assessment_succeeded
        )
        worker.failed.connect(
            self._on_assessment_failed
        )
        worker.finished.connect(
            self._on_worker_finished
        )

        worker.start()

    def _on_assessment_succeeded(self, result):
        self.progress_bar.hide()

        status = result.status.value

        self.execution_status_label.setText(
            f"Assessment finished: {status.upper()}"
        )

        self.execution_status_label.setObjectName(
            "StatusReady"
            if status == "completed"
            else "Muted"
        )

        self.execution_status_label.style().unpolish(
            self.execution_status_label
        )
        self.execution_status_label.style().polish(
            self.execution_status_label
        )

        if result.status.value == "failed":
            message = (
                result.error.message
                if result.error is not None
                else "Assessment failed."
            )

            self.findings_output.setPlainText(
                f"Assessment failed.\n\n{message}"
            )
            return

        findings = result.findings

        if not findings:
            self.findings_output.setPlainText(
                "Assessment completed successfully.\n\n"
                "No findings were identified by the active analyzers."
            )
            return

        sections = [
            f"Assessment completed: {len(findings)} finding(s).",
            "",
        ]

        for index, finding in enumerate(findings, start=1):
            severity = getattr(
                finding.severity,
                "value",
                str(finding.severity),
            )

            classification = getattr(
                finding.classification,
                "value",
                str(finding.classification),
            )

            sections.extend(
                [
                    f"[{index}] {finding.title}",
                    f"Severity: {severity}",
                    f"Classification: {classification}",
                    f"Confidence: {finding.confidence}",
                    f"Analyzer: {finding.analyzer}",
                    "",
                    f"Description:\n{finding.description}",
                    "",
                    f"Evidence:\n{finding.evidence}",
                    "",
                    f"Remediation:\n{finding.remediation}",
                    "",
                    "-" * 55,
                    "",
                ]
            )

        self.findings_output.setPlainText(
            "\n".join(sections)
        )

    def _on_assessment_failed(self, message: str):
        self.progress_bar.hide()

        self.execution_status_label.setText(
            "Assessment could not be completed."
        )

        self.execution_status_label.setObjectName("Muted")

        self.findings_output.setPlainText(message)

    # =============================================================
    # Worker lifecycle
    # =============================================================

    def _on_worker_finished(self):
        worker = self.sender()

        if worker is not None and worker is self._worker:
            self._worker = None

        self.progress_bar.hide()

        self._update_controls()
