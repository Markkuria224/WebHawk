import sys

from PySide6.QtWidgets import QApplication

from webhawk.gui.main_window import create_main_window


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("WebHawk")
    app.setOrganizationName("WebHawk")

    window = create_main_window()
    window.show()

    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
