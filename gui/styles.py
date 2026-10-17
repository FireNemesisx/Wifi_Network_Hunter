"""
Modern High-Tech Cyberpunk / Dark SOC Style Sheet for Network Hunter.
Provides unified styling, color tokens, and widgets custom styling.
"""

DARK_THEME_QSS = """
/* Base Window and Panels */
QMainWindow, QWidget {
    background-color: #0b0f19;
    color: #e2e8f0;
    font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, Helvetica, Arial, sans-serif;
    font-size: 13px;
}

/* Group Boxes & Containers */
QGroupBox {
    border: 1px solid #1f293d;
    border-radius: 8px;
    margin-top: 12px;
    padding-top: 10px;
    font-weight: 600;
    color: #94a3b8;
    background-color: #111827;
}

QGroupBox::title {
    subcontrol-origin: margin;
    subcontrol-position: top left;
    padding: 0 8px;
    color: #38bdf8;
}

/* Headers & Labels */
QLabel {
    color: #cbd5e1;
}

QLabel#titleLabel {
    font-size: 18px;
    font-weight: 700;
    color: #38bdf8;
    letter-spacing: 0.5px;
}

QLabel#subtitleLabel {
    font-size: 11px;
    color: #64748b;
}

QLabel#statValue {
    font-size: 22px;
    font-weight: 700;
    color: #f8fafc;
}

QLabel#statLabel {
    font-size: 11px;
    font-weight: 600;
    color: #94a3b8;
    text-transform: uppercase;
}

/* Stat Cards */
QFrame.statCard {
    background-color: #111827;
    border: 1px solid #1f293d;
    border-radius: 8px;
    padding: 10px;
}

QFrame.statCard:hover {
    border-color: #38bdf8;
}

/* Warning & Banner Bar */
QFrame#privilegeWarningBanner {
    background-color: #2a1b07;
    border: 1px solid #d97706;
    border-radius: 6px;
    padding: 6px 12px;
}

/* Inputs & Combos */
QLineEdit, QComboBox, QSpinBox {
    background-color: #172033;
    border: 1px solid #2d3b55;
    border-radius: 6px;
    padding: 6px 10px;
    color: #f1f5f9;
    selection-background-color: #0284c7;
}

QLineEdit:focus, QComboBox:focus, QSpinBox:focus {
    border: 1px solid #38bdf8;
    background-color: #1e293b;
}

QComboBox::drop-down {
    border: none;
    width: 20px;
}

QComboBox QAbstractItemView {
    background-color: #172033;
    border: 1px solid #2d3b55;
    selection-background-color: #0284c7;
    color: #f8fafc;
    padding: 4px;
}

/* Push Buttons */
QPushButton {
    background-color: #1e293b;
    border: 1px solid #334155;
    border-radius: 6px;
    padding: 7px 14px;
    font-weight: 600;
    color: #f8fafc;
}

QPushButton:hover {
    background-color: #334155;
    border-color: #475569;
}

QPushButton:pressed {
    background-color: #0f172a;
}

QPushButton:disabled {
    background-color: #0f172a;
    border-color: #1e293b;
    color: #475569;
}

/* Primary Action Buttons */
QPushButton#primaryBtn {
    background-color: #0284c7;
    border: 1px solid #38bdf8;
    color: #ffffff;
}

QPushButton#primaryBtn:hover {
    background-color: #0369a1;
}

/* Sniffer Active Toggle Button */
QPushButton#snifferBtn {
    background-color: #064e3b;
    border: 1px solid #059669;
    color: #a7f3d0;
}

QPushButton#snifferBtn:hover {
    background-color: #047857;
}

QPushButton#snifferBtn[active="true"] {
    background-color: #059669;
    border-color: #34d399;
    color: #ffffff;
}

/* Danger Button */
QPushButton#dangerBtn {
    background-color: #7f1d1d;
    border: 1px solid #ef4444;
    color: #fecaca;
}

QPushButton#dangerBtn:hover {
    background-color: #991b1b;
}

/* Table Widget (High-Density SOC Grid) */
QTableWidget {
    background-color: #0d131f;
    border: 1px solid #1e293b;
    border-radius: 8px;
    gridline-color: #162032;
    selection-background-color: #1e3a5f;
    selection-color: #ffffff;
    font-size: 12px;
}

QTableWidget::item {
    padding: 6px 8px;
    border-bottom: 1px solid #141d2e;
}

QTableWidget::item:selected {
    background-color: #1e3a5f;
}

QHeaderView::section {
    background-color: #111827;
    color: #94a3b8;
    padding: 8px;
    font-weight: 600;
    border: none;
    border-bottom: 2px solid #1f293d;
    border-right: 1px solid #162032;
    font-size: 11px;
    text-transform: uppercase;
}

/* Tabs */
QTabWidget::pane {
    border: 1px solid #1f293d;
    border-radius: 8px;
    background-color: #0d131f;
    top: -1px;
}

QTabBar::tab {
    background-color: #111827;
    color: #94a3b8;
    border: 1px solid #1f293d;
    border-bottom: none;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
    padding: 8px 16px;
    margin-right: 4px;
    font-weight: 600;
}

QTabBar::tab:selected {
    background-color: #0d131f;
    color: #38bdf8;
    border-top: 2px solid #38bdf8;
}

QTabBar::tab:hover:!selected {
    background-color: #172033;
    color: #cbd5e1;
}

/* Progress Bar */
QProgressBar {
    background-color: #172033;
    border: 1px solid #2d3b55;
    border-radius: 4px;
    text-align: center;
    color: #f1f5f9;
    font-size: 11px;
    height: 14px;
}

QProgressBar::chunk {
    background-color: #0284c7;
    border-radius: 3px;
}

/* Scrollbars */
QScrollBar:vertical {
    border: none;
    background: #0b0f19;
    width: 8px;
    margin: 0px;
}

QScrollBar::handle:vertical {
    background: #27354f;
    min-height: 20px;
    border-radius: 4px;
}

QScrollBar::handle:vertical:hover {
    background: #38bdf8;
}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}

QScrollBar:horizontal {
    border: none;
    background: #0b0f19;
    height: 8px;
    margin: 0px;
}

QScrollBar::handle:horizontal {
    background: #27354f;
    min-width: 20px;
    border-radius: 4px;
}

QScrollBar::handle:horizontal:hover {
    background: #38bdf8;
}

QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
    width: 0px;
}

/* Status Bar */
QStatusBar {
    background-color: #070a12;
    color: #64748b;
    border-top: 1px solid #162032;
    font-size: 11px;
}
"""

# OS Color Palettes for badges and nodes
OS_COLORS = {
    "Windows": "#0078d7",
    "Linux": "#f59e0b",
    "Linux / Android / Apple": "#10b981",
    "Apple iOS / macOS": "#a855f7",
    "macOS": "#a855f7",
    "Apple iOS": "#c084fc",
    "Android": "#22c55e",
    "Embedded / IoT": "#ec4899",
    "Network Infrastructure (Cisco/BSD)": "#06b6d4",
    "Unknown": "#64748b"
}
