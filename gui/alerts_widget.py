"""
Gerçek Zamanlı Güvenlik Uyarıları Çekmecesi & Alarm Kayıt Bileşeni.
Yabancı (Rogue) cihaz varışları, ARP Zehirleme (MitM) saldırıları ve
varsayılan kimlik doğrulama zafiyetlerini önem derecelerine göre filtreler ve JSON olarak dışa aktarır.
"""

import json
from typing import List

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
    QPushButton, QLabel, QHeaderView, QFileDialog, QMessageBox, QAbstractItemView
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QFont

from core.models import SecurityAlert


SEVERITY_COLORS = {
    "CRITICAL": "#ef4444",
    "HIGH": "#f97316",
    "WARNING": "#eab308",
    "INFO": "#38bdf8"
}

SEVERITY_TR = {
    "CRITICAL": "KRİTİK",
    "HIGH": "YÜKSEK",
    "WARNING": "UYARI",
    "INFO": "BİLGİ"
}


class AlertsWidget(QWidget):
    """
    Güvenlik Alarmları Paneli.
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        self._alerts: List[SecurityAlert] = []
        self._current_filter = "ALL"
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(8)

        # Başlık ve Filtre Araç Çubuğu
        toolbar = QHBoxLayout()

        title = QLabel("Güvenlik & Anomali Tespit Akışı")
        title.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        title.setStyleSheet("color: #f8fafc;")
        toolbar.addWidget(title)

        toolbar.addSpacing(15)

        # Filtre Butonları
        self.btn_all = QPushButton("Tümü")
        self.btn_crit = QPushButton("Kritik (0)")
        self.btn_high = QPushButton("Yüksek (0)")

        self.btn_all.setFixedHeight(26)
        self.btn_crit.setFixedHeight(26)
        self.btn_high.setFixedHeight(26)

        self.btn_crit.setStyleSheet("color: #ef4444; font-weight: bold;")
        self.btn_high.setStyleSheet("color: #f97316; font-weight: bold;")

        self.btn_all.clicked.connect(lambda: self.set_filter("ALL"))
        self.btn_crit.clicked.connect(lambda: self.set_filter("CRITICAL"))
        self.btn_high.clicked.connect(lambda: self.set_filter("HIGH"))

        toolbar.addWidget(self.btn_all)
        toolbar.addWidget(self.btn_crit)
        toolbar.addWidget(self.btn_high)

        toolbar.addStretch()

        export_btn = QPushButton("Kayıtları Dışa Aktar")
        export_btn.setFixedHeight(26)
        export_btn.clicked.connect(self.export_alerts)
        toolbar.addWidget(export_btn)

        clear_btn = QPushButton("Temizle")
        clear_btn.setFixedHeight(26)
        clear_btn.clicked.connect(self.clear_alerts)
        toolbar.addWidget(clear_btn)

        layout.addLayout(toolbar)

        # Alarmlar Tablosu
        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels([
            "Zaman", "Önem Derecesi", "Başlık / Tehdit Türü", "Hedef Varlık", "Açıklama"
        ])
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.setShowGrid(False)

        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)

        layout.addWidget(self.table)

    def add_alert(self, alert: SecurityAlert):
        """Yeni güvenlik alarmını listeye ekler ve tabloyu günceller."""
        self._alerts.insert(0, alert)
        self._update_filter_counts()
        self._refresh_table()

    def set_filter(self, severity_filter: str):
        """Önem derecesi filtresini uygular."""
        self._current_filter = severity_filter
        self._refresh_table()

    def _update_filter_counts(self):
        crit_count = sum(1 for a in self._alerts if a.severity == "CRITICAL")
        high_count = sum(1 for a in self._alerts if a.severity == "HIGH")
        self.btn_crit.setText(f"Kritik ({crit_count})")
        self.btn_high.setText(f"Yüksek ({high_count})")

    def _refresh_table(self):
        """Aktif filtreye göre satırları yeniden oluşturur."""
        filtered = [
            a for a in self._alerts
            if self._current_filter == "ALL" or a.severity == self._current_filter
        ]

        self.table.setRowCount(len(filtered))
        for row, alert in enumerate(filtered):
            # Zaman
            time_item = QTableWidgetItem(alert.timestamp.strftime("%H:%M:%S"))
            time_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            time_item.setForeground(QColor("#94a3b8"))
            self.table.setItem(row, 0, time_item)

            # Önem Derecesi
            sev_tr = SEVERITY_TR.get(alert.severity, alert.severity)
            sev_item = QTableWidgetItem(f"[{sev_tr}]")
            sev_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            sev_item.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
            sev_color = SEVERITY_COLORS.get(alert.severity, "#38bdf8")
            sev_item.setForeground(QColor(sev_color))
            self.table.setItem(row, 1, sev_item)

            # Başlık
            title_item = QTableWidgetItem(alert.title)
            title_item.setFont(QFont("Segoe UI", 9, QFont.Weight.DemiBold))
            title_item.setForeground(QColor("#f8fafc"))
            self.table.setItem(row, 2, title_item)

            # Hedef Varlık
            target = f"{alert.target_ip or ''} {f'({alert.target_mac})' if alert.target_mac else ''}".strip()
            target_item = QTableWidgetItem(target or "Alt Ağ (Subnet)")
            target_item.setForeground(QColor("#38bdf8"))
            self.table.setItem(row, 3, target_item)

            # Açıklama
            desc_item = QTableWidgetItem(alert.description)
            desc_item.setForeground(QColor("#cbd5e1"))
            self.table.setItem(row, 4, desc_item)

    def clear_alerts(self):
        """Tüm alarmları temizler."""
        self._alerts.clear()
        self._update_filter_counts()
        self._refresh_table()

    def export_alerts(self):
        """Alarmları JSON dosyası olarak dışa aktarır."""
        if not self._alerts:
            QMessageBox.information(self, "Dışa Aktarma", "Dışa aktarılacak herhangi bir güvenlik alarmı bulunamadı.")
            return

        filepath, _ = QFileDialog.getSaveFileName(
            self, "Güvenlik Alarmlarını Kaydet", "guvenlik_alarmlari.json", "JSON Dosyaları (*.json)"
        )
        if filepath:
            try:
                data = [a.to_dict() for a in self._alerts]
                with open(filepath, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
                QMessageBox.information(self, "Başarılı", f"{len(data)} adet güvenlik alarmı başarıyla dışa aktarıldı.")
            except Exception as e:
                QMessageBox.critical(self, "Hata", f"Alarmlar dışa aktarılırken hata oluştu: {e}")
