"""
Network Hunter Ana Kullanıcı Arayüzü Konsolu (PyQt6).
Pasif Sniffer, Adaptif Aktif Tarayıcı ve Veri Korelasyon Motorunu
iş parçacığı güvenli sinyallerle yöneten yüksek yoğunluklu SOC kontrol merkezi.
"""

import sys
import socket
import logging
from typing import Optional, List, Tuple

from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTableWidget, QTableWidgetItem, QLabel, QPushButton, QComboBox,
    QLineEdit, QSpinBox, QProgressBar, QTabWidget, QSplitter,
    QFrame, QHeaderView, QAbstractItemView, QMessageBox, QStatusBar
)
from PyQt6.QtCore import Qt, pyqtSlot
from PyQt6.QtGui import QColor, QFont

from core.models import DeviceAsset, ScanConfig
from core.correlation import CorrelationEngine
from core.sniffer import PassiveSnifferThread
from core.scanner import ActiveScannerThread
from core.oui_lookup import lookup_vendor
from gui.styles import DARK_THEME_QSS, OS_COLORS
from gui.topology_widget import TopologyWidget
from gui.alerts_widget import AlertsWidget
from gui.device_detail_widget import DeviceDetailWidget
from utils.privileges import is_admin, get_elevation_instructions
from utils.network_info import get_interface_details, get_default_gateway, get_system_arp_cache

logger = logging.getLogger("NetworkHunter.MainWindow")


class MainWindow(QMainWindow):
    """
    Network Hunter ana masaüstü penceresi.
    """
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Network Hunter // Hibrit Ağ Varlık & Saldırı Yüzeyi Yöneticisi")
        self.resize(1360, 890)
        self.setMinimumSize(1040, 700)
        self.setStyleSheet(DARK_THEME_QSS)

        # Çekirdek Motorlar
        self.correlation = CorrelationEngine()
        self.sniffer_thread: Optional[PassiveSnifferThread] = None
        self.scanner_thread: Optional[ActiveScannerThread] = None

        # Ağ Arayüzleri ve Ağ Geçidi
        self.interfaces = get_interface_details()
        self.default_gw, self.default_iface = get_default_gateway()

        # Arayüzü İnşa Et
        self._setup_ui()
        self._connect_signals()

        # Yetki Kontrolü
        self._check_admin_status()

        # Başlangıç cihazlarını yükle (Yerel makine, Ağ Geçidi ve ARP önbelleği)
        self._initialize_baseline()

        # Zero-Touch Pasif Sniffer'ı otomatik başlat
        self._toggle_sniffer()

    def _setup_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(14, 12, 14, 8)
        main_layout.setSpacing(10)

        # 1. Başlık ve Yetki Rozeti
        main_layout.addLayout(self._create_header_bar())

        # Yetki Bilgilendirme Afişi (Standart Kullanıcı Modu)
        self.privilege_banner = QFrame()
        self.privilege_banner.setObjectName("privilegeWarningBanner")
        banner_layout = QHBoxLayout(self.privilege_banner)
        banner_layout.setContentsMargins(8, 6, 8, 6)
        self.privilege_label = QLabel()
        self.privilege_label.setStyleSheet("color: #f59e0b; font-size: 11px;")
        banner_layout.addWidget(self.privilege_label)
        banner_layout.addStretch()
        info_btn = QPushButton("Yetki Rehberi")
        info_btn.setFixedHeight(22)
        info_btn.setStyleSheet("font-size: 10px; padding: 2px 8px; background: #d97706; color: white;")
        info_btn.clicked.connect(self._show_elevation_help)
        banner_layout.addWidget(info_btn)
        main_layout.addWidget(self.privilege_banner)
        self.privilege_banner.setVisible(False)

        # 2. Kontrol Araç Çubuğu
        main_layout.addWidget(self._create_control_panel())

        # 3. İstatistik Kartları Çubuğu
        main_layout.addLayout(self._create_stats_bar())

        # 4. Merkez Bölücü (Splitter): Üst Tablo & Alt Sekmeler
        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.setHandleWidth(4)

        # Üst Panel: Yüksek Yoğunluklu Varlık Tablosu ve Arama
        table_container = QWidget()
        table_layout = QVBoxLayout(table_container)
        table_layout.setContentsMargins(0, 0, 0, 0)
        table_layout.setSpacing(6)

        search_bar = QHBoxLayout()
        search_label = QLabel("Cihaz Filtrele:")
        search_label.setStyleSheet("color: #94a3b8; font-weight: 600;")
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("IP, MAC, Donanım Üreticisi, Hostname veya İşletim Sistemi ara...")
        self.search_input.textChanged.connect(self._filter_assets_table)
        search_bar.addWidget(search_label)
        search_bar.addWidget(self.search_input)

        refresh_btn = QPushButton("Hızlı Yenile")
        refresh_btn.setFixedHeight(28)
        refresh_btn.clicked.connect(self._fast_refresh_arp)
        search_bar.addWidget(refresh_btn)

        table_layout.addLayout(search_bar)

        self.table = self._create_assets_table()
        table_layout.addWidget(self.table)
        splitter.addWidget(table_container)

        # Alt Panel: Sekmeler (Topoloji Haritası, Güvenlik Alarmları, Cihaz İnceleme)
        self.tabs = QTabWidget()
        
        self.topology_widget = TopologyWidget()
        self.alerts_widget = AlertsWidget()
        self.detail_widget = DeviceDetailWidget()

        self.tabs.addTab(self.topology_widget, "Ağ Topolojisi Haritası")
        self.tabs.addTab(self.alerts_widget, "Güvenlik Uyarıları Akışı")
        self.tabs.addTab(self.detail_widget, "Ayrıntılı Cihaz Analizi")

        splitter.addWidget(self.tabs)
        splitter.setSizes([450, 350])
        main_layout.addWidget(splitter)

        # 5. Durum Çubuğu
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_label = QLabel("Sistem Hazır")
        self.packet_count_label = QLabel("Yakalanan Paket: 0")
        self.status_bar.addWidget(self.status_label, 1)
        self.status_bar.addPermanentWidget(self.packet_count_label)

    def _create_header_bar(self) -> QHBoxLayout:
        header = QHBoxLayout()

        title_box = QVBoxLayout()
        title = QLabel("NETWORK HUNTER")
        title.setObjectName("titleLabel")
        subtitle = QLabel("HİBRİT L2/L3 KEŞİF VE SALDIRI YÜZEYİ İSTİHBARATI")
        subtitle.setObjectName("subtitleLabel")
        title_box.addWidget(title)
        title_box.addWidget(subtitle)
        header.addLayout(title_box)

        header.addStretch()

        self.admin_badge = QLabel("YETKİ DENETLENİYOR...")
        self.admin_badge.setStyleSheet(
            "padding: 4px 10px; border-radius: 4px; font-weight: bold; font-size: 11px;"
        )
        header.addWidget(self.admin_badge)

        return header

    def _create_control_panel(self) -> QFrame:
        panel = QFrame()
        panel.setStyleSheet("background-color: #111827; border: 1px solid #1f293d; border-radius: 8px; padding: 6px;")
        layout = QHBoxLayout(panel)
        layout.setContentsMargins(10, 8, 10, 8)
        layout.setSpacing(12)

        # Ağ Arayüzü Seçimi
        layout.addWidget(QLabel("Ağ Arayüzü:"))
        self.iface_combo = QComboBox()
        self.iface_combo.setMinimumWidth(190)
        for iface in self.interfaces:
            display_name = f"{iface['name']} ({iface['ip']})"
            self.iface_combo.addItem(display_name, iface)
        self.iface_combo.currentIndexChanged.connect(self._on_interface_changed)
        layout.addWidget(self.iface_combo)

        # Subnet Girişi
        layout.addWidget(QLabel("Alt Ağ (Subnet):"))
        self.subnet_input = QLineEdit()
        self.subnet_input.setFixedWidth(130)
        if self.interfaces:
            self.subnet_input.setText(self.interfaces[0]["subnet"])
        else:
            self.subnet_input.setText("192.168.1.0/24")
        layout.addWidget(self.subnet_input)

        # Hız Sınırı (PPS)
        layout.addWidget(QLabel("Hız (PPS):"))
        self.pps_spin = QSpinBox()
        self.pps_spin.setRange(10, 100)
        self.pps_spin.setValue(100)
        self.pps_spin.setToolTip("Ağ tıkanıklığını önlemek için saniyedeki paket limiti (en fazla 100).")
        layout.addWidget(self.pps_spin)

        # Pasif Sniffer Aç/Kapa
        self.sniffer_btn = QPushButton("Pasif Sniffer Başlat")
        self.sniffer_btn.setObjectName("snifferBtn")
        self.sniffer_btn.clicked.connect(self._toggle_sniffer)
        layout.addWidget(self.sniffer_btn)

        # L2 ARP Taraması
        self.arp_sweep_btn = QPushButton("L2 ARP Taraması")
        self.arp_sweep_btn.setObjectName("primaryBtn")
        self.arp_sweep_btn.clicked.connect(self._start_arp_sweep)
        layout.addWidget(self.arp_sweep_btn)

        # Kritik Port Taraması
        self.port_scan_btn = QPushButton("Kritik Portları Tara")
        self.port_scan_btn.clicked.connect(self._start_port_scan)
        layout.addWidget(self.port_scan_btn)

        # Tam Keşif
        self.full_recon_btn = QPushButton("Tam Keşif Taraması")
        self.full_recon_btn.clicked.connect(self._start_full_recon)
        layout.addWidget(self.full_recon_btn)

        # İlerleme Çubuğu
        self.progress_bar = QProgressBar()
        self.progress_bar.setFixedWidth(100)
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)

        return panel

    def _create_stats_bar(self) -> QHBoxLayout:
        bar = QHBoxLayout()
        bar.setSpacing(12)

        def make_card(title: str, default_val: str, color: str = "#38bdf8") -> Tuple[QFrame, QLabel]:
            card = QFrame()
            card.setProperty("class", "statCard")
            card_layout = QVBoxLayout(card)
            card_layout.setContentsMargins(10, 6, 10, 6)
            card_layout.setSpacing(2)

            lbl = QLabel(title)
            lbl.setObjectName("statLabel")
            val = QLabel(default_val)
            val.setObjectName("statValue")
            val.setStyleSheet(f"color: {color};")

            card_layout.addWidget(lbl)
            card_layout.addWidget(val)
            return card, val

        card_total, self.stat_total = make_card("TOPLAM CİHAZ", "0", "#38bdf8")
        card_online, self.stat_online = make_card("AKTİF ÇEVRİMİÇİ", "0", "#10b981")
        card_rogues, self.stat_rogues = make_card("YABANCI (ROGUE) CİHAZ", "0", "#ef4444")
        card_alerts, self.stat_alerts = make_card("GÜVENLİK ALARMLARI", "0", "#f59e0b")

        bar.addWidget(card_total)
        bar.addWidget(card_online)
        bar.addWidget(card_rogues)
        bar.addWidget(card_alerts)

        return bar

    def _create_assets_table(self) -> QTableWidget:
        table = QTableWidget()
        headers = [
            "DURUM", "IP ADRESİ", "MAC ADRESİ", "ÜRETİCİ",
            "CİHAZ ADI (HOSTNAME)", "İŞLETİM SİSTEMİ", "AÇIK PORTLAR", "GECİKME", "SON GÖRÜLME"
        ]
        table.setColumnCount(len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.verticalHeader().setVisible(False)
        table.setSortingEnabled(True)

        header = table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(7, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(8, QHeaderView.ResizeMode.ResizeToContents)

        table.itemSelectionChanged.connect(self._on_table_row_selected)
        return table

    def _connect_signals(self):
        self.correlation.asset_added.connect(self._on_asset_discovered)
        self.correlation.asset_updated.connect(self._on_asset_discovered)
        self.correlation.alert_generated.connect(self.alerts_widget.add_alert)
        self.correlation.stats_updated.connect(self._on_stats_updated)
        self.detail_widget.asset_status_changed.connect(self._on_asset_discovered)

    def _check_admin_status(self):
        admin = is_admin()
        if admin:
            self.admin_badge.setText("YÖNETİCİ YETKİSİ: AKTİF")
            self.admin_badge.setStyleSheet("background-color: #064e3b; color: #34d399; padding: 4px 10px; border-radius: 4px; font-weight: bold;")
        else:
            self.admin_badge.setText("KISITLI YETKİ (STANDART KULLANICI)")
            self.admin_badge.setStyleSheet("background-color: #451a03; color: #fbbf24; padding: 4px 10px; border-radius: 4px; font-weight: bold;")
            self.privilege_banner.setVisible(True)
            self.privilege_label.setText(
                "Bilgilendirme: Yönetici izinleri olmadan çalışıyor. Ham paket yakalama ve L2 ARP operasyonları Adaptif Geri Çekilme Modunda işletilmektedir."
            )

    def _show_elevation_help(self):
        msg = get_elevation_instructions()
        QMessageBox.information(self, "Yönetici İzinleri ve Npcap Rehberi", msg)

    def _initialize_baseline(self):
        """
        Başlangıçta mevcut ağın temel varlıklarını yükler:
        1. Yerel bilgisayar (Bu Cihaz)
        2. Ağ Geçidi (Router)
        3. İşletim sisteminin ARP önbelleğindeki tüm canlı cihazlar
        """
        # 1. Yerel Bilgisayarı Ekle
        try:
            local_hostname = socket.gethostname()
            iface_data = self.iface_combo.currentData()
            if iface_data and iface_data.get("ip"):
                local_ip = iface_data["ip"]
                local_mac = iface_data.get("mac", "00:00:00:00:00:00")
                self.correlation.process_telemetry({
                    "ip_address": local_ip,
                    "mac_address": local_mac,
                    "hostname": f"{local_hostname} (Bu Cihaz)",
                    "vendor": lookup_vendor(local_mac),
                    "os_family": "Windows" if sys.platform == "win32" else "Linux",
                    "source": "Yerel Arayüz"
                })
        except Exception as e:
            logger.debug(f"Yerel varlık eklenirken hata: {e}")

        # 2. Ağ Geçidini Ayarla
        if self.default_gw:
            self.topology_widget.set_gateway(self.default_gw)
            self.correlation.security.set_gateway(self.default_gw, None)

        # 3. Sistem ARP Önbelleğindeki Canlı Cihazları Yükle
        self._fast_refresh_arp()

        # Önceki oturumdan kalan önbellek varlıkları
        for asset in self.correlation.get_all_assets():
            self._render_asset_row(asset)
            self.topology_widget.update_asset(asset)

    def _fast_refresh_arp(self):
        """Sistem ARP tablosunu tarayıp yeni cihazları korelasyona iletir."""
        arp_entries = get_system_arp_cache()
        for ip, mac in arp_entries:
            hostname = None
            if self.default_gw and ip == self.default_gw:
                hostname = "Varsayılan Ağ Geçidi (Router)"
            self.correlation.process_telemetry({
                "ip_address": ip,
                "mac_address": mac,
                "hostname": hostname,
                "vendor": lookup_vendor(mac),
                "source": "Sistem ARP Önbelleği"
            })
        self.status_label.setText(f"Ağ önbelleği yenilendi. {len(arp_entries)} varlık işlendi.")

    def _on_interface_changed(self, index: int):
        iface = self.iface_combo.currentData()
        if iface:
            self.subnet_input.setText(iface.get("subnet", "192.168.1.0/24"))
            if iface.get("gateway"):
                self.topology_widget.set_gateway(iface["gateway"])
                self.correlation.security.set_gateway(iface["gateway"], None)

    # -------------------------------------------------------------
    # Sniffer ve Tarayıcı Koordinasyonu
    # -------------------------------------------------------------
    def _toggle_sniffer(self):
        if self.sniffer_thread and self.sniffer_thread.isRunning():
            self.status_label.setText("Pasif sniffer durduruluyor...")
            self.sniffer_thread.stop()
            self.sniffer_btn.setText("Pasif Sniffer Başlat")
            self.sniffer_btn.setProperty("active", "false")
            self.sniffer_btn.style().unpolish(self.sniffer_btn)
            self.sniffer_btn.style().polish(self.sniffer_btn)
        else:
            iface_data = self.iface_combo.currentData()
            iface_name = iface_data["name"] if iface_data else None

            self.sniffer_thread = PassiveSnifferThread(interface=iface_name)
            self.sniffer_thread.host_observed.connect(self.correlation.process_telemetry)
            self.sniffer_thread.packet_count.connect(lambda c: self.packet_count_label.setText(f"Yakalanan Paket: {c}"))
            self.sniffer_thread.status_changed.connect(self.status_label.setText)
            self.sniffer_thread.error_occurred.connect(lambda err: self.status_label.setText(f"Sniffer Uyarısı: {err}"))
            self.sniffer_thread.start()

            self.sniffer_btn.setText("Pasif Sniffer Durdur")
            self.sniffer_btn.setProperty("active", "true")
            self.sniffer_btn.style().unpolish(self.sniffer_btn)
            self.sniffer_btn.style().polish(self.sniffer_btn)

    def _start_arp_sweep(self):
        self._run_active_scan(mode="L2_SWEEP")

    def _start_port_scan(self):
        assets = self.correlation.get_all_assets()
        targets = [a.ip_address for a in assets if a.ip_address != "0.0.0.0"]
        if not targets:
            QMessageBox.information(self, "Port Taraması", "Taranacak aktif cihaz bulunamadı. Önce L2 ARP Taraması başlatın!")
            return
        self._run_active_scan(mode="TARGETED_PORTS", targets=targets)

    def _start_full_recon(self):
        self._run_active_scan(mode="FULL")

    def _run_active_scan(self, mode: str, targets: Optional[List[str]] = None):
        if self.scanner_thread and self.scanner_thread.isRunning():
            QMessageBox.warning(self, "Tarayıcı Meşgul", "Şu anda devam eden bir aktif tarama operasyonu bulunmaktadır.")
            return

        subnet = self.subnet_input.text().strip()
        pps = self.pps_spin.value()
        iface_data = self.iface_combo.currentData()
        iface_name = iface_data["name"] if iface_data else None

        config = ScanConfig(
            subnet=subnet,
            interface=iface_name,
            rate_limit_pps=pps,
            enable_banner_grab=True
        )

        self.scanner_thread = ActiveScannerThread(
            config=config,
            target_hosts=targets or [],
            mode=mode
        )
        self.scanner_thread.scan_started.connect(self._on_scan_started)
        self.scanner_thread.host_discovered.connect(self.correlation.process_telemetry)
        self.scanner_thread.ports_updated.connect(self.correlation.update_ports)
        self.scanner_thread.progress_updated.connect(self._on_scan_progress)
        self.scanner_thread.scan_finished.connect(self._on_scan_finished)
        self.scanner_thread.scan_error.connect(lambda err: QMessageBox.warning(self, "Tarama Hatası", err))

        self.scanner_thread.start()

    def _on_scan_started(self, msg: str):
        self.status_label.setText(msg)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)

    def _on_scan_progress(self, current: int, total: int):
        if total > 0:
            self.progress_bar.setMaximum(total)
            self.progress_bar.setValue(current)

    def _on_scan_finished(self, count: int):
        self.progress_bar.setVisible(False)
        self.status_label.setText(f"Aktif tarama tamamlandı. {count} cihaz işlendi.")

    # -------------------------------------------------------------
    # Tablo Oluşturma ve Filtreleme
    # -------------------------------------------------------------
    @pyqtSlot(DeviceAsset)
    def _on_asset_discovered(self, asset: DeviceAsset):
        self._render_asset_row(asset)
        self.topology_widget.update_asset(asset)

    def _render_asset_row(self, asset: DeviceAsset):
        key = asset.mac_address if asset.mac_address else asset.ip_address

        row = -1
        for r in range(self.table.rowCount()):
            mac_item = self.table.item(r, 2)
            ip_item = self.table.item(r, 1)
            if (mac_item and mac_item.text() == asset.mac_address and asset.mac_address != "") or \
               (ip_item and ip_item.text() == asset.ip_address):
                row = r
                break

        if row == -1:
            row = self.table.rowCount()
            self.table.insertRow(row)

        # Durum
        if asset.is_rogue:
            status_text = "YABANCI (ROGUE)"
            status_color = "#ef4444"
        elif asset.status == "Online":
            status_text = "Çevrimiçi"
            status_color = "#10b981"
        else:
            status_text = "Çevrimdışı"
            status_color = "#64748b"

        status_item = QTableWidgetItem(status_text)
        status_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        status_item.setForeground(QColor(status_color))
        if asset.is_rogue:
            status_item.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
        self.table.setItem(row, 0, status_item)

        # IP Adresi
        ip_item = QTableWidgetItem(asset.ip_address)
        ip_item.setForeground(QColor("#f8fafc"))
        self.table.setItem(row, 1, ip_item)

        # MAC Adresi
        mac_item = QTableWidgetItem(asset.mac_address)
        mac_item.setForeground(QColor("#38bdf8"))
        self.table.setItem(row, 2, mac_item)

        # Donanım Üreticisi
        vendor_item = QTableWidgetItem(asset.vendor)
        vendor_item.setForeground(QColor("#cbd5e1"))
        self.table.setItem(row, 3, vendor_item)

        # Cihaz Adı
        host_item = QTableWidgetItem(asset.hostname or "-")
        host_item.setForeground(QColor("#cbd5e1"))
        self.table.setItem(row, 4, host_item)

        # İşletim Sistemi
        os_item = QTableWidgetItem(asset.os_family)
        os_color = OS_COLORS.get(asset.os_family, "#cbd5e1")
        os_item.setForeground(QColor(os_color))
        os_item.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
        self.table.setItem(row, 5, os_item)

        # Açık Portlar
        ports_str = ", ".join(str(p) for p in asset.open_ports) if asset.open_ports else "-"
        ports_item = QTableWidgetItem(ports_str)
        ports_item.setForeground(QColor("#a78bfa"))
        self.table.setItem(row, 6, ports_item)

        # Gecikme
        latency_str = f"{asset.latency_ms:.1f} ms" if asset.latency_ms > 0 else "< 1 ms"
        latency_item = QTableWidgetItem(latency_str)
        latency_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        latency_item.setForeground(QColor("#94a3b8"))
        self.table.setItem(row, 7, latency_item)

        # Son Görülme
        seen_str = asset.last_seen.strftime("%H:%M:%S")
        seen_item = QTableWidgetItem(seen_str)
        seen_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        seen_item.setForeground(QColor("#64748b"))
        self.table.setItem(row, 8, seen_item)

        ip_item.setData(Qt.ItemDataRole.UserRole, asset)

    def _on_table_row_selected(self):
        selected_rows = self.table.selectedItems()
        if not selected_rows:
            return
        row = selected_rows[0].row()
        ip_item = self.table.item(row, 1)
        if ip_item:
            asset = ip_item.data(Qt.ItemDataRole.UserRole)
            if asset:
                self.detail_widget.display_asset(asset)

    def _filter_assets_table(self, query: str):
        query = query.strip().lower()
        for r in range(self.table.rowCount()):
            match = False
            for c in range(self.table.columnCount()):
                item = self.table.item(r, c)
                if item and query in item.text().lower():
                    match = True
                    break
            self.table.setRowHidden(r, not match)

    @pyqtSlot(dict)
    def _on_stats_updated(self, stats: dict):
        self.stat_total.setText(str(stats.get("total_hosts", 0)))
        self.stat_online.setText(str(stats.get("online_hosts", 0)))
        self.stat_rogues.setText(str(stats.get("rogue_hosts", 0)))
        self.stat_alerts.setText(str(stats.get("alert_count", 0)))

    # -------------------------------------------------------------
    # Kapanış ve Temizleme
    # -------------------------------------------------------------
    def closeEvent(self, event):
        """Arka plan iş parçacıklarını güvenle durdurur ve önbelleği kaydeder."""
        self.status_label.setText("Arka plan servisleri kapatılıyor...")
        if self.sniffer_thread and self.sniffer_thread.isRunning():
            self.sniffer_thread.stop()
        if self.scanner_thread and self.scanner_thread.isRunning():
            self.scanner_thread.cancel()

        self.correlation.save_cache()
        event.accept()
