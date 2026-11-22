APP_STYLESHEET = """
QMainWindow {
    background-color: #0B1120;
}

QWidget {
    color: #E2E8F0;
    font-family: "Segoe UI";
    font-size: 10pt;
}

QFrame#Sidebar {
    background-color: #0F172A;
    border-right: 1px solid #1E293B;
}

QLabel#Brand {
    color: #F8FAFC;
    font-size: 21pt;
    font-weight: 800;
}

QLabel#BrandAccent {
    color: #22D3EE;
    font-size: 21pt;
    font-weight: 800;
}

QLabel#BrandSubtitle {
    color: #64748B;
    font-size: 8pt;
    letter-spacing: 2px;
}

QPushButton#NavButton {
    background-color: transparent;
    color: #94A3B8;
    text-align: left;
    border: none;
    border-radius: 7px;
    padding: 12px 15px;
    font-size: 10pt;
    font-weight: 600;
}

QPushButton#NavButton:hover {
    background-color: #1E293B;
    color: #F8FAFC;
}

QPushButton#NavButton:checked {
    background-color: #164E63;
    color: #67E8F9;
    border-left: 3px solid #22D3EE;
}

QFrame#ContentArea {
    background-color: #0B1120;
}

QLabel#PageTitle {
    color: #F8FAFC;
    font-size: 23pt;
    font-weight: 700;
}

QLabel#PageSubtitle {
    color: #94A3B8;
    font-size: 10pt;
}

QFrame#Card {
    background-color: #111C30;
    border: 1px solid #263449;
    border-radius: 11px;
}

QLabel#CardTitle {
    color: #94A3B8;
    font-size: 9pt;
    font-weight: 600;
}

QLabel#CardHeading {
    color: #F8FAFC;
    font-size: 13pt;
    font-weight: 700;
}

QLabel#CardDescription {
    color: #94A3B8;
    font-size: 9pt;
}

QLabel#StatusReady {
    color: #34D399;
    font-weight: 700;
}

QLabel#Muted {
    color: #64748B;
}

QFrame#TopBar {
    background-color: #0B1120;
    border-bottom: 1px solid #1E293B;
}

QStatusBar {
    background-color: #0F172A;
    color: #94A3B8;
    border-top: 1px solid #1E293B;
}
"""
