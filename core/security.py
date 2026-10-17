"""
Module D: Security & Anomaly Detection Engine.
Monitors the local network for security anomalies:
1. Rogue Device Alert: Flags MAC addresses with no historical presence in the local cache.
2. ARP Spoofing / MitM Detector: Monitors ARP bindings for rapid multi-IP mapping or Gateway MAC changes.
3. Default Credential Checker: Safely audits common default credentials (e.g., admin:admin, root:root) on administrative interfaces.
"""

import time
import base64
import socket
import logging
from typing import Dict, List, Set, Optional, Tuple
from collections import defaultdict

from core.models import SecurityAlert, DeviceAsset

logger = logging.getLogger("NetworkHunter.Security")

# Common default credentials dictionary for administrative services
DEFAULT_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "1234"),
    ("root", "root"),
    ("root", "admin"),
]


class SecurityEngine:
    """
    Analyzes telemetry events from passive and active modules to detect attacks,
    rogue devices, and security vulnerabilities.
    """

    def __init__(self, gateway_ip: Optional[str] = None):
        self.gateway_ip = gateway_ip
        self.gateway_mac: Optional[str] = None
        
        # Historical MAC cache (populated from assets_cache.json)
        self.historical_macs: Set[str] = set()

        # Tracking for ARP Poisoning: mac -> list of (ip, timestamp)
        self._mac_ip_history: Dict[str, List[Tuple[str, float]]] = defaultdict(list)
        
        # Gateway change tracker
        self._gateway_lock_established = False

    def set_historical_macs(self, macs: Set[str]):
        """Load known historical MACs from local storage cache."""
        self.historical_macs = set(m.upper() for m in macs)

    def set_gateway(self, ip: Optional[str], mac: Optional[str]):
        """Establish baseline gateway IP and MAC address."""
        if ip:
            self.gateway_ip = ip
        if mac:
            self.gateway_mac = mac.upper()
            self._gateway_lock_established = True
            logger.info(f"Baseline Gateway Locked: IP={self.gateway_ip}, MAC={self.gateway_mac}")

    def inspect_device_arrival(self, asset: DeviceAsset) -> Optional[SecurityAlert]:
        """
        Check if an arriving device is a rogue unknown device.
        """
        mac = asset.mac_address.upper()
        if not mac or mac in ("00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"):
            return None

        # Ağ Geçidi (Router) ve yerel bilgisayar güvenilir temel altyapıdır
        if (self.gateway_mac and mac == self.gateway_mac) or (self.gateway_ip and asset.ip_address == self.gateway_ip):
            asset.is_rogue = False
            self.historical_macs.add(mac)
            return None

        if "(Bu Cihaz)" in (asset.hostname or "") or "Yerel Arayüz" in asset.detection_methods:
            asset.is_rogue = False
            self.historical_macs.add(mac)
            return None

        # Check if MAC was in historical cache
        if mac not in self.historical_macs:
            asset.is_rogue = True
            self.historical_macs.add(mac)
            
            return SecurityAlert(
                severity="HIGH",
                alert_type="ROGUE_DEVICE",
                title="Yabancı / Yetkisiz (Rogue) Cihaz Tespit Edildi",
                description=(
                    f"MAC adresi {mac} ve IP adresi {asset.ip_address} olan yeni cihazın yerel "
                    f"önbellekte geçmiş bir kaydı bulunmuyor. Üretici: {asset.vendor}."
                ),
                target_ip=asset.ip_address,
                target_mac=mac
            )
        return None

    def inspect_arp_event(self, ip: str, mac: str) -> List[SecurityAlert]:
        """
        Gelen ARP olayını ARP Zehirleme, MitM ve Ağ Geçidi Değişimi yönünden analiz eder.
        """
        alerts = []
        now = time.time()
        mac = mac.upper()

        # 1. Ağ Geçidi MAC Değişimi Kontrolü
        if self.gateway_ip and ip == self.gateway_ip:
            if not self.gateway_mac:
                self.gateway_mac = mac
                self._gateway_lock_established = True
                logger.info(f"Ağ geçidi MAC referansı kilitlendi: {mac}")
            elif self.gateway_mac != mac:
                alerts.append(SecurityAlert(
                    severity="CRITICAL",
                    alert_type="GATEWAY_MAC_CHANGE",
                    title="KRİTİK: Ağ Geçidi (Gateway) MAC Zehirlemesi / Değişimi!",
                    description=(
                        f"Varsayılan Ağ Geçidinin ({self.gateway_ip}) MAC adresi referans {self.gateway_mac} "
                        f"değerinden {mac} adresine değişti! Bu durum aktif bir Ortadaki Adam "
                        f"(Man-in-the-Middle / ARP Poisoning) saldırısına işaret etmektedir."
                    ),
                    target_ip=ip,
                    target_mac=mac
                ))

        # 2. Çoklu IP Sahiplenme Kontrolü
        history = self._mac_ip_history[mac]
        history = [(h_ip, ts) for (h_ip, ts) in history if (now - ts) < 15.0]
        history.append((ip, now))
        self._mac_ip_history[mac] = history

        unique_ips = set(h_ip for (h_ip, _) in history)
        if len(unique_ips) >= 3 and mac != self.gateway_mac:
            alerts.append(SecurityAlert(
                severity="CRITICAL",
                alert_type="ARP_SPOOFING",
                title="Olası ARP Zehirleme / Çoklu IP Sahiplenme",
                description=(
                    f"{mac} MAC adresi son 15 saniyede {len(unique_ips)} farklı IP adresi sahiplendi "
                    f"({', '.join(list(unique_ips)[:4])}). Olası ARP Spoofing veya yetkisiz DHCP faaliyeti."
                ),
                target_ip=ip,
                target_mac=mac
            ))

        return alerts

    def check_default_credentials(self, ip: str, port: int, timeout: float = 1.0) -> Optional[SecurityAlert]:
        """
        Yönetim servislerinde yaygın varsayılan kimlik bilgilerini güvenle denetler.
        """
        if port not in (80, 8080, 8443):
            return None

        for username, password in DEFAULT_CREDENTIALS:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(timeout)
                s.connect((ip, port))

                auth_str = f"{username}:{password}"
                encoded_auth = base64.b64encode(auth_str.encode()).decode()
                
                req = (
                    f"GET / HTTP/1.1\r\n"
                    f"Host: {ip}\r\n"
                    f"Authorization: Basic {encoded_auth}\r\n"
                    f"User-Agent: NetworkHunter-Audit/1.0\r\n"
                    f"Connection: close\r\n\r\n"
                )
                s.sendall(req.encode())
                resp = s.recv(512).decode('latin1', errors='ignore')
                s.close()

                if "HTTP/1.1 200 OK" in resp or "HTTP/1.0 200 OK" in resp:
                    return SecurityAlert(
                        severity="CRITICAL",
                        alert_type="DEFAULT_CREDENTIALS",
                        title="Varsayılan Kimlik Bilgisi Zafiyeti",
                        description=(
                            f"{ip}:{port} üzerindeki yönetim arayüzü fabrika varsayılanı "
                            f"'{username}:{password}' kimlik bilgilerini kabul etmektedir."
                        ),
                        target_ip=ip
                    )
            except Exception:
                pass

        return None
