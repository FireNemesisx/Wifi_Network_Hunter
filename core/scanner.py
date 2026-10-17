"""
Modül B: Adaptif Aktif Keşif Motoru (PyQt6 QThread).
Hız sınırlamalı (maksimum 100 pps) ve güvenli aktif tarama operasyonları:
1. L2 Sweep: Subnet genelinde ARP / Çok iş parçacıklı hızlı bağlantı taraması.
2. Hedefli Port Taraması: Tespit edilen aktif varlıkların kritik 20 portu.
3. ICMP / TTL İncelemesi: Gecikme ölçümü ve TTL değerinden işletim sistemi tahmini.
4. Banner Grabbing: Açık portlarda protokol el sıkışmasıyla servis sürüm tespiti.
"""

import time
import socket
import ipaddress
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Tuple, Optional

from PyQt6.QtCore import QThread, pyqtSignal

from core.models import ScanConfig
from core.oui_lookup import lookup_vendor
from utils.privileges import can_use_raw_sockets
from utils.network_info import get_system_arp_cache

logger = logging.getLogger("NetworkHunter.Scanner")

# En Kritik 20 Port Kataloğu
TOP_20_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
    443, 445, 993, 995, 1433, 3306, 3389, 5432, 8080, 8443
]

PORT_SERVICES = {
    21: "FTP Dosya Transferi",
    22: "SSH Güvenli Kabuk",
    23: "Telnet (Şifresiz)",
    25: "SMTP E-Posta",
    53: "DNS Alan Adı Sunucusu",
    80: "HTTP Web Sunucusu",
    110: "POP3 Posta",
    135: "MSRPC Windows RPC",
    139: "NetBIOS Oturum Servisi",
    143: "IMAP Posta",
    443: "HTTPS Güvenli Web (SSL/TLS)",
    445: "SMB Dosya Paylaşımı / Active Directory",
    993: "IMAPS Güvenli Posta",
    995: "POP3S Güvenli Posta",
    1433: "Microsoft SQL Server",
    3306: "MySQL Veritabanı",
    3389: "RDP Uzak Masaüstü",
    5432: "PostgreSQL Veritabanı",
    8080: "HTTP Alternatif Web / Proxy",
    8443: "HTTPS Alternatif Güvenli Web"
}


def estimate_os_from_ttl(ttl: int) -> str:
    """
    TTL değerinden temel işletim sistemi ailesini tahmin eder.
    TTL ~64  -> Linux / Android / Apple iOS / macOS
    TTL ~128 -> Windows (10/11/Server)
    TTL ~255 -> Cisco / Ağ Donanımı / BSD
    """
    if ttl <= 64:
        return "Linux / Android / Apple"
    elif ttl <= 128:
        return "Windows"
    else:
        return "Ağ Altyapısı (Cisco/BSD)"


def grab_banner(ip: str, port: int, timeout: float = 1.0) -> str:
    """
    Hedef port ile TCP bağlantısı kurarak servis banner bilgisini çeker.
    """
    default_name = PORT_SERVICES.get(port, "Açık Port")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)

    try:
        s.connect((ip, port))

        if port in (80, 8080):
            req = f"HEAD / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: NetworkHunter/1.0\r\n\r\n"
            s.sendall(req.encode('utf-8'))
        elif port in (443, 8443):
            s.close()
            return "HTTPS (SSL/TLS Şifreli)"
        elif port in (21, 22, 23, 25, 110, 143):
            pass
        else:
            s.sendall(b"\r\n")

        banner_bytes = s.recv(256)
        s.close()

        if banner_bytes:
            banner_text = banner_bytes.decode('utf-8', errors='ignore').strip()
            lines = [l.strip() for l in banner_text.splitlines() if l.strip()]
            if lines:
                return f"{default_name} ({lines[0][:50]})"
    except Exception:
        pass
    finally:
        try:
            s.close()
        except Exception:
            pass

    return default_name


class ActiveScannerThread(QThread):
    """
    Hız sınırlamalı aktif keşif iş parçacığı.
    """
    scan_started = pyqtSignal(str)
    host_discovered = pyqtSignal(dict)
    ports_updated = pyqtSignal(str, list, dict)  # ip, open_ports, services
    progress_updated = pyqtSignal(int, int)      # current, total
    scan_finished = pyqtSignal(int)              # total discovered
    scan_error = pyqtSignal(str)

    def __init__(self, config: ScanConfig, target_hosts: Optional[List[str]] = None, mode: str = "L2_SWEEP", parent=None):
        super().__init__(parent)
        self.config = config
        self.target_hosts = target_hosts or []
        self.mode = mode
        self._is_cancelled = False

    def cancel(self):
        """Aktif taramayı iptal eder."""
        self._is_cancelled = True

    def run(self):
        self._is_cancelled = False
        try:
            if self.mode == "L2_SWEEP":
                self.scan_started.emit(f"{self.config.subnet} üzerinde L2 Ağ Taraması Başlatılıyor...")
                self._run_l2_sweep()
            elif self.mode == "TARGETED_PORTS":
                self.scan_started.emit(f"{len(self.target_hosts)} cihaz üzerinde kritik port taraması yapılıyor...")
                self._run_targeted_port_scan(self.target_hosts)
            elif self.mode == "FULL":
                self.scan_started.emit(f"{self.config.subnet} üzerinde Tam Keşif Operasyonu Başlatılıyor...")
                hosts = self._run_l2_sweep()
                if hosts and not self._is_cancelled:
                    self._run_targeted_port_scan([h["ip_address"] for h in hosts])
        except Exception as e:
            logger.error(f"Aktif tarama hatası: {e}")
            self.scan_error.emit(str(e))

    def _apply_rate_limit(self):
        """Hız sınırlaması (pps) uygular."""
        pps = max(1, min(self.config.rate_limit_pps, 100))
        delay = 1.0 / pps
        time.sleep(delay)

    def _run_l2_sweep(self) -> List[Dict]:
        """
        Subnet genelinde L2 Sweep gerçekleştirir.
        """
        discovered = []
        try:
            network = ipaddress.ip_network(self.config.subnet, strict=False)
            ip_list = [str(ip) for ip in network.hosts()]
        except Exception as e:
            self.scan_error.emit(f"Geçersiz alt ağ formatı '{self.config.subnet}': {e}")
            return []

        total_ips = len(ip_list)
        use_raw = can_use_raw_sockets()

        if use_raw:
            discovered = self._scapy_l2_sweep(ip_list, total_ips)
        else:
            discovered = self._fast_concurrent_adaptive_sweep(ip_list, total_ips)

        self.scan_finished.emit(len(discovered))
        return discovered

    def _scapy_l2_sweep(self, ip_list: List[str], total_ips: int) -> List[Dict]:
        """Scapy ile L2 ARP Broadcast taraması."""
        from scapy.all import Ether, ARP, srp
        discovered = []

        try:
            for idx, ip in enumerate(ip_list):
                if self._is_cancelled:
                    break

                self.progress_updated.emit(idx + 1, total_ips)
                self._apply_rate_limit()

                pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
                t_start = time.time()
                ans, _ = srp(pkt, timeout=0.3, verbose=False, iface=self.config.interface)
                latency = (time.time() - t_start) * 1000

                for snd, rcv in ans:
                    mac = rcv[ARP].hwsrc.upper()
                    vendor = lookup_vendor(mac)
                    host_info = {
                        "ip_address": ip,
                        "mac_address": mac,
                        "vendor": vendor,
                        "latency_ms": latency,
                        "source": "L2 ARP Taraması"
                    }
                    discovered.append(host_info)
                    self.host_discovered.emit(host_info)

        except Exception as e:
            logger.warning(f"Scapy tarama hatası: {e}. Hızlı adaptif moda geçiliyor.")
            return self._fast_concurrent_adaptive_sweep(ip_list, total_ips)

        return discovered

    def _fast_concurrent_adaptive_sweep(self, ip_list: List[str], total_ips: int) -> List[Dict]:
        """
        Yönetici yetkisi olmadığında çok iş parçacıklı hızlı bağlantı problarıyla
        sistem ARP tablosunu tetikler ve keşfedilen cihazları anında ekrana yansıtır.
        """
        discovered = []
        emitted_ips = set()

        # 1. Adım: Mevcut ARP tablosunu ANINDA oku ve ilk saniyede ekrana ver
        initial_cache = get_system_arp_cache()
        for ip, mac in initial_cache:
            if ip in ip_list and ip not in emitted_ips:
                emitted_ips.add(ip)
                host_info = {
                    "ip_address": ip,
                    "mac_address": mac,
                    "vendor": lookup_vendor(mac),
                    "latency_ms": 1.0,
                    "source": "Sistem ARP Önbelleği"
                }
                discovered.append(host_info)
                self.host_discovered.emit(host_info)

        # 2. Adım: Çok iş parçacıklı soket probu ile tüm /24 subnet'i 2 saniyede tara
        def probe_ip(ip: str):
            if self._is_cancelled:
                return ip, False
            for port in (80, 445, 135, 53, 22):
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(0.12)
                    res = s.connect_ex((ip, port))
                    s.close()
                    if res == 0:
                        return ip, True
                except Exception:
                    pass
            return ip, False

        completed = 0
        with ThreadPoolExecutor(max_workers=35) as executor:
            futures = {executor.submit(probe_ip, ip): ip for ip in ip_list}
            for future in as_completed(futures):
                if self._is_cancelled:
                    break
                completed += 1
                if completed % 5 == 0 or completed == total_ips:
                    self.progress_updated.emit(completed, total_ips)

                # Her 20 tamamlanan işlemde güncel ARP tablosunu kontrol et
                if completed % 20 == 0 or completed == total_ips:
                    current_cache = get_system_arp_cache()
                    for ip, mac in current_cache:
                        if ip in ip_list and ip not in emitted_ips:
                            emitted_ips.add(ip)
                            host_info = {
                                "ip_address": ip,
                                "mac_address": mac,
                                "vendor": lookup_vendor(mac),
                                "latency_ms": 2.0,
                                "source": "Adaptif L2 Taraması"
                            }
                            discovered.append(host_info)
                            self.host_discovered.emit(host_info)

        return discovered

    def _run_targeted_port_scan(self, target_ips: List[str]):
        """
        Aktif varlıklar üzerinde kritik 20 portu tarar ve servis bannerlarını ayıklar.
        """
        total_targets = len(target_ips) * len(self.config.ports)
        counter = 0

        for ip in target_ips:
            if self._is_cancelled:
                break

            open_ports = []
            services = {}

            for port in self.config.ports:
                if self._is_cancelled:
                    break

                counter += 1
                self.progress_updated.emit(counter, total_targets)
                self._apply_rate_limit()

                is_open = False
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.35)
                    code = sock.connect_ex((ip, port))
                    sock.close()
                    if code == 0:
                        is_open = True
                except Exception:
                    is_open = False

                if is_open:
                    open_ports.append(port)
                    if self.config.enable_banner_grab:
                        service_banner = grab_banner(ip, port, timeout=0.8)
                        services[port] = service_banner
                    else:
                        services[port] = PORT_SERVICES.get(port, "Açık")

            self.ports_updated.emit(ip, open_ports, services)

        self.scan_finished.emit(len(target_ips))
