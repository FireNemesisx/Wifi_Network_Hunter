"""
Network Hunter: Hybrid Network Asset & Attack Surface Manager.
Entry point for the desktop application.
"""

import sys
import logging
from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import Qt

from gui.main_window import MainWindow

# Configure global application logging
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] [%(name)s]: %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger("NetworkHunter.Main")


def main():
    """Application main entry point."""
    logger.info("Initializing Network Hunter Application...")

    # Enable High DPI scaling
    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )

    app = QApplication(sys.argv)
    app.setApplicationName("NetworkHunter")
    app.setOrganizationName("SecurityOps")

    # Instantiate Main GUI Window
    window = MainWindow()
    window.show()

    logger.info("Main Window initialized and visible.")
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
