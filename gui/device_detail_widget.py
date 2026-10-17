"""
Ayrıntılı Cihaz İnceleme Paneli Bileşeni.
Seçilen varlığa ait derinlemesine telemetri verilerini, DHCP Option 55 imzasını,
açık portları, servis bannerlarını ve tespit soy ağacını (lineage) görüntüler.
"""

from typing import Optional

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame,
    QGridLayout, QTextEdit, QPushButton
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont

from core.models import DeviceAsset
from gui.styles import OS_COLORS


class DeviceDetailWidget(QWidget):
    """
    Seçili ağ cihazının tüm güvenlik ve protokol niteliklerini gösteren detay paneli.
    """
    asset_status_changed = pyqtSignal(object)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.current_asset: Optional[DeviceAsset] = None
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(10)

        # Başlık ve Güven Durumu Butonu
        header = QHBoxLayout()
        self.title_label = QLabel("Ayrıntılı analiz için tablodan bir cihaz seçin")
        self.title_label.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        self.title_label.setStyleSheet("color: #38bdf8;")
        header.addWidget(self.title_label)

        header.addStretch()

        self.trust_btn = QPushButton("Rogue Durumunu Değiştir")
        self.trust_btn.setFixedHeight(28)
        self.trust_btn.setVisible(False)
        self.trust_btn.clicked.connect(self._toggle_rogue)
        header.addWidget(self.trust_btn)

        layout.addLayout(header)

        # Bilgi Izgarası (Grid)
        self.grid_frame = QFrame()
        self.grid_frame.setStyleSheet("background-color: #111827; border: 1px solid #1f293d; border-radius: 6px; padding: 10px;")
        grid = QGridLayout(self.grid_frame)
        grid.setHorizontalSpacing(18)
        grid.setVerticalSpacing(8)

        self.lbl_ip = QLabel("-")
        self.lbl_mac = QLabel("-")
        self.lbl_vendor = QLabel("-")
        self.lbl_hostname = QLabel("-")
        self.lbl_os = QLabel("-")
        self.lbl_latency = QLabel("-")
        self.lbl_first_seen = QLabel("-")
        self.lbl_last_seen = QLabel("-")
        self.lbl_dhcp_fp = QLabel("-")
        self.lbl_methods = QLabel("-")

        fields = [
            ("IP Adresi:", self.lbl_ip, 0, 0),
            ("MAC Adresi:", self.lbl_mac, 0, 2),
            ("Donanım Üreticisi:", self.lbl_vendor, 1, 0),
            ("Cihaz Adı (Hostname):", self.lbl_hostname, 1, 2),
            ("İşletim Sistemi Ailesi:", self.lbl_os, 2, 0),
            ("Gecikme (RTT Süresi):", self.lbl_latency, 2, 2),
            ("İlk Keşif Zamanı:", self.lbl_first_seen, 3, 0),
            ("Son Görülme Zamanı:", self.lbl_last_seen, 3, 2),
            ("DHCP Parmak İzi (Opt 55):", self.lbl_dhcp_fp, 4, 0),
            ("Keşif Yöntemleri:", self.lbl_methods, 4, 2),
        ]

        for title, val_lbl, r, c in fields:
            t_lbl = QLabel(title)
            t_lbl.setStyleSheet("color: #94a3b8; font-weight: 600; font-size: 11px;")
            val_lbl.setStyleSheet("color: #f1f5f9; font-size: 12px;")
            grid.addWidget(t_lbl, r, c)
            grid.addWidget(val_lbl, r, c + 1)

        layout.addWidget(self.grid_frame)

        # Açık Portlar ve Servisler Bölümü
        ports_title = QLabel("Keşfedilen Açık Portlar & Servis Bannerları")
        ports_title.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        ports_title.setStyleSheet("color: #cbd5e1; margin-top: 4px;")
        layout.addWidget(ports_title)

        self.services_text = QTextEdit()
        self.services_text.setReadOnly(True)
        self.services_text.setStyleSheet(
            "background-color: #0b0f19; border: 1px solid #1f293d; color: #38bdf8; "
            "font-family: 'Consolas', monospace; font-size: 12px; border-radius: 6px;"
        )
        self.services_text.setFixedHeight(115)
        layout.addWidget(self.services_text)

    def display_asset(self, asset: DeviceAsset):
        """Seçilen cihazın telemetri verilerini ekranda görüntüler."""
        self.current_asset = asset
        self.trust_btn.setVisible(True)

        name = asset.hostname or asset.ip_address
        status_tag = " [YETKİSİZ / ROGUE CİHAZ]" if asset.is_rogue else ""
        self.title_label.setText(f"{name} ({asset.ip_address}){status_tag}")
        self.title_label.setStyleSheet("color: #ef4444;" if asset.is_rogue else "color: #38bdf8;")

        self.lbl_ip.setText(asset.ip_address)
        self.lbl_mac.setText(asset.mac_address)
        self.lbl_vendor.setText(asset.vendor)
        self.lbl_hostname.setText(asset.hostname or "Belirtilmemiş")
        
        os_color = OS_COLORS.get(asset.os_family, "#cbd5e1")
        self.lbl_os.setText(asset.os_family)
        self.lbl_os.setStyleSheet(f"color: {os_color}; font-weight: bold;")

        self.lbl_latency.setText(f"{asset.latency_ms:.1f} ms" if asset.latency_ms > 0 else "< 1 ms")
        self.lbl_first_seen.setText(asset.first_seen.strftime("%d.%m.%Y %H:%M:%S"))
        self.lbl_last_seen.setText(asset.last_seen.strftime("%d.%m.%Y %H:%M:%S"))
        self.lbl_dhcp_fp.setText(asset.dhcp_fingerprint or "Yakalanmadı")
        self.lbl_methods.setText(", ".join(asset.detection_methods) if asset.detection_methods else "Pasif Dinleme")

        if asset.is_rogue:
            self.trust_btn.setText("Yetkili Varlık Olarak Onayla")
            self.trust_btn.setStyleSheet("background-color: #059669; color: white;")
        else:
            self.trust_btn.setText("Yabancı (Rogue) Olarak İşaretle")
            self.trust_btn.setStyleSheet("background-color: #7f1d1d; color: #fecaca;")

        if asset.open_ports:
            lines = []
            for port in asset.open_ports:
                banner = asset.services.get(port, "Açık")
                lines.append(f"Port {port:<5}/tcp  ->  {banner}")
            self.services_text.setPlainText("\n".join(lines))
        else:
            self.services_text.setPlainText("Bu cihazda henüz tespit edilmiş açık port bulunmamaktadır.")

    def _toggle_rogue(self):
        """Mevcut cihazın yabancı (rogue) durumunu tersine çevirir."""
        if self.current_asset:
            self.current_asset.is_rogue = not self.current_asset.is_rogue
            self.display_asset(self.current_asset)
            self.asset_status_changed.emit(self.current_asset)
