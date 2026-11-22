from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QPushButton,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from webhawk.gui.theme import APP_STYLESHEET
from webhawk.gui.pages.authorized_targets import AuthorizedTargetsPage
from webhawk.gui.pages.assessment import AssessmentPage


class DashboardPage(QWidget):
    """Initial WebHawk dashboard."""

    def __init__(self):
        super().__init__()

        layout = QVBoxLayout(self)
        layout.setContentsMargins(32, 28, 32, 28)
        layout.setSpacing(22)

        heading = QLabel("Security Overview")
        heading.setObjectName("PageTitle")

        subtitle = QLabel(
            "Monitor your authorized web application security assessments."
        )
        subtitle.setObjectName("PageSubtitle")

        layout.addWidget(heading)
        layout.addWidget(subtitle)

        cards_layout = QHBoxLayout()
        cards_layout.setSpacing(16)

        cards = [
            (
                "ASSESSMENT ENGINE",
                "Ready",
                "Existing assessment pipeline available",
                "StatusReady",
            ),
            (
                "AUTHORIZATION",
                "Required",
                "Targets must be explicitly approved",
                "CardHeading",
            ),
            (
                "ANALYSIS MODULES",
                "3 Active",
                "HSTS, Cookies and CORS",
                "CardHeading",
            ),
        ]

        for title, value, description, value_style in cards:
            card = QFrame()
            card.setObjectName("Card")

            card_layout = QVBoxLayout(card)
            card_layout.setContentsMargins(19, 18, 19, 18)
            card_layout.setSpacing(12)

            title_label = QLabel(title)
            title_label.setObjectName("CardTitle")

            value_label = QLabel(value)
            value_label.setObjectName(value_style)

            description_label = QLabel(description)
            description_label.setObjectName("CardDescription")
            description_label.setWordWrap(True)

            card_layout.addWidget(title_label)
            card_layout.addWidget(value_label)
            card_layout.addWidget(description_label)
            card_layout.addStretch()

            cards_layout.addWidget(card)

        layout.addLayout(cards_layout)

        activity_card = QFrame()
        activity_card.setObjectName("Card")

        activity_layout = QVBoxLayout(activity_card)
        activity_layout.setContentsMargins(22, 20, 22, 20)
        activity_layout.setSpacing(12)

        activity_title = QLabel("Recent Activity")
        activity_title.setObjectName("CardHeading")

        activity_message = QLabel(
            "No assessments have been performed in this session."
        )
        activity_message.setObjectName("Muted")

        activity_layout.addWidget(activity_title)
        activity_layout.addWidget(activity_message)

        layout.addWidget(activity_card)
        layout.addStretch()


class PlaceholderPage(QWidget):
    """Placeholder for sections implemented in later milestones."""

    def __init__(self, title: str, description: str):
        super().__init__()

        layout = QVBoxLayout(self)
        layout.setContentsMargins(32, 28, 32, 28)
        layout.setSpacing(14)

        heading = QLabel(title)
        heading.setObjectName("PageTitle")

        subtitle = QLabel(description)
        subtitle.setObjectName("PageSubtitle")
        subtitle.setWordWrap(True)

        card = QFrame()
        card.setObjectName("Card")

        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(24, 24, 24, 24)

        message = QLabel("This workspace is under development.")
        message.setObjectName("CardHeading")

        details = QLabel(
            "Its functionality will be implemented and tested "
            "in a subsequent development milestone."
        )
        details.setObjectName("CardDescription")
        details.setWordWrap(True)

        card_layout.addWidget(message)
        card_layout.addWidget(details)

        layout.addWidget(heading)
        layout.addWidget(subtitle)
        layout.addWidget(card)
        layout.addStretch()


class WebHawkMainWindow(QMainWindow):
    """Main WebHawk desktop application window."""

    NAVIGATION = [
        ("Dashboard", "Overview"),
        ("Assessment", "Configure and launch assessments"),
        ("Findings", "Review assessment findings"),
        ("Evidence", "Inspect technical evidence"),
        ("Authorized Targets", "Manage approved assessment scope"),
        ("Settings", "Application configuration"),
    ]

    def __init__(self):
        super().__init__()

        self.setWindowTitle("WebHawk")
        self.resize(1280, 800)
        self.setMinimumSize(1050, 680)
        self.setStyleSheet(APP_STYLESHEET)

        self.navigation_buttons = []

        central_widget = QWidget()
        central_layout = QHBoxLayout(central_widget)
        central_layout.setContentsMargins(0, 0, 0, 0)
        central_layout.setSpacing(0)

        sidebar = self._build_sidebar()
        content = self._build_content()

        central_layout.addWidget(sidebar)
        central_layout.addWidget(content, 1)

        self.setCentralWidget(central_widget)

        self.statusBar().showMessage("WebHawk | Ready")

        self.navigation_buttons[0].setChecked(True)

    def _build_sidebar(self):
        sidebar = QFrame()
        sidebar.setObjectName("Sidebar")
        sidebar.setFixedWidth(235)

        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(17, 27, 17, 20)
        layout.setSpacing(9)

        brand_layout = QHBoxLayout()
        brand_layout.setSpacing(0)

        brand = QLabel("WEB")
        brand.setObjectName("Brand")

        accent = QLabel("HAWK")
        accent.setObjectName("BrandAccent")

        brand_layout.addWidget(brand)
        brand_layout.addWidget(accent)
        brand_layout.addStretch()

        subtitle = QLabel("WEB SECURITY PLATFORM")
        subtitle.setObjectName("BrandSubtitle")

        layout.addLayout(brand_layout)
        layout.addWidget(subtitle)
        layout.addSpacing(28)

        section_label = QLabel("WORKSPACE")
        section_label.setObjectName("Muted")
        layout.addWidget(section_label)
        layout.addSpacing(7)

        for index, (title, _) in enumerate(self.NAVIGATION):
            button = QPushButton(title)
            button.setObjectName("NavButton")
            button.setCheckable(True)
            button.setCursor(Qt.CursorShape.PointingHandCursor)

            button.clicked.connect(
                lambda checked=False, page=index: self._navigate(page)
            )

            self.navigation_buttons.append(button)
            layout.addWidget(button)

        layout.addStretch()

        version = QLabel("WEBHAWK  •  VERSION 0.1.0")
        version.setObjectName("Muted")
        version.setAlignment(Qt.AlignmentFlag.AlignCenter)

        layout.addWidget(version)

        return sidebar

    def _build_content(self):
        content = QFrame()
        content.setObjectName("ContentArea")

        layout = QVBoxLayout(content)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        top_bar = QFrame()
        top_bar.setObjectName("TopBar")
        top_bar.setFixedHeight(57)

        top_layout = QHBoxLayout(top_bar)
        top_layout.setContentsMargins(25, 0, 25, 0)

        section_label = QLabel("WEB APPLICATION SECURITY")
        section_label.setObjectName("Muted")

        top_layout.addWidget(section_label)
        top_layout.addStretch()

        platform_label = QLabel("LOCAL WORKSTATION")
        platform_label.setObjectName("StatusReady")

        top_layout.addWidget(platform_label)

        self.pages = QStackedWidget()

        self.pages.addWidget(DashboardPage())

        self.pages.addWidget(AssessmentPage())

        self.pages.addWidget(
            PlaceholderPage(
                "Findings",
                "Review security observations and potential weaknesses.",
            )
        )

        self.pages.addWidget(
            PlaceholderPage(
                "Evidence",
                "Inspect evidence associated with assessment findings.",
            )
        )

        self.pages.addWidget(AuthorizedTargetsPage())

        self.pages.addWidget(
            PlaceholderPage(
                "Settings",
                "Configure WebHawk application preferences.",
            )
        )

        layout.addWidget(top_bar)
        layout.addWidget(self.pages, 1)

        return content

    def _navigate(self, index: int):
        self.pages.setCurrentIndex(index)

        for button_index, button in enumerate(self.navigation_buttons):
            button.setChecked(button_index == index)

        section = self.NAVIGATION[index][0]
        self.statusBar().showMessage(f"WebHawk | {section}")

    def closeEvent(self, event):
        assessment_page = self.pages.widget(1)

        if assessment_page._worker_running():
            self.statusBar().showMessage(
                "An operation is still running. "
                "Wait for it to finish before closing WebHawk."
            )
            event.ignore()
            return

        event.accept()


def create_main_window():
    return WebHawkMainWindow()
