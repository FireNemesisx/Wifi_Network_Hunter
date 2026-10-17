"""
Module C: Data Correlation & Deduplication Engine.
Resolves conflicting telemetry data between Passive and Active modules using the priority hierarchy:
- IP & MAC: Trust L2 ARP / Passive ARP (100% local accuracy).
- Hostname: Trust Passive mDNS / NetBIOS over Reverse DNS lookup.
- OS Fingerprint: Trust Passive DHCP Option 55 first; fall back to TTL + Port Signature.
- Open Ports: Trust Active Scanning results.

Maintains thread-safe in-memory asset state and persistent local cache.
"""

import json
import os
import socket
import logging
from datetime import datetime
from typing import Dict, List, Optional
from threading import Lock

from PyQt6.QtCore import QObject, pyqtSignal

from core.models import DeviceAsset, SecurityAlert
from core.oui_lookup import lookup_vendor
from core.security import SecurityEngine

logger = logging.getLogger("NetworkHunter.Correlation")

CACHE_FILE_NAME = "assets_cache.json"


class CorrelationEngine(QObject):
    """
    Central state management, deduplication, and correlation engine.
    Thread-safe and communicates with UI via PyQt signals.
    """
    asset_added = pyqtSignal(DeviceAsset)
    asset_updated = pyqtSignal(DeviceAsset)
    alert_generated = pyqtSignal(SecurityAlert)
    stats_updated = pyqtSignal(dict)

    def __init__(self, cache_dir: Optional[str] = None, parent=None):
        super().__init__(parent)
        self._lock = Lock()
        self._assets: Dict[str, DeviceAsset] = {}  # mac_address -> DeviceAsset
        self._ip_to_mac: Dict[str, str] = {}       # ip_address -> mac_address
        self._alerts: List[SecurityAlert] = []
        
        self.cache_path = os.path.join(cache_dir or os.getcwd(), CACHE_FILE_NAME)
        self.security = SecurityEngine()

        # Load historical cache to identify known devices
        self.load_cache()

    def process_telemetry(self, data: dict):
        """
        Ingest telemetry events from Sniffer or Scanner and apply correlation rules.
        """
        ip = data.get("ip_address")
        mac = data.get("mac_address", "").upper() if data.get("mac_address") else None
        hostname = data.get("hostname")
        os_family = data.get("os_family")
        dhcp_fp = data.get("dhcp_fingerprint")
        vendor = data.get("vendor")
        latency = data.get("latency_ms", 0.0)
        source = data.get("source", "Unknown")

        # Fallback: If MAC is not provided but IP exists, check if we know the MAC for this IP
        with self._lock:
            if not mac and ip in self._ip_to_mac:
                mac = self._ip_to_mac[ip]

            if not mac and not ip:
                return

            # Primary key is MAC address on local L2 network
            lookup_key = mac if mac else ip

            is_new = lookup_key not in self._assets
            if is_new:
                # Create new asset
                asset = DeviceAsset(
                    ip_address=ip or "0.0.0.0",
                    mac_address=mac or "00:00:00:00:00:00",
                    vendor=vendor or lookup_vendor(mac) if mac else "Unknown",
                    hostname=hostname,
                    os_family=os_family or "Unknown",
                    dhcp_fingerprint=dhcp_fp,
                    latency_ms=latency,
                    first_seen=datetime.now(),
                    last_seen=datetime.now(),
                    detection_methods=[source] if source else []
                )
                
                # Check for Rogue Device arrival
                alert = self.security.inspect_device_arrival(asset)
                if alert:
                    self._alerts.append(alert)
                    self.alert_generated.emit(alert)

                self._assets[lookup_key] = asset
                if ip and mac:
                    self._ip_to_mac[ip] = mac

                self.asset_added.emit(asset)
            else:
                # Update existing asset following priority hierarchy
                asset = self._assets[lookup_key]
                asset.last_seen = datetime.now()
                asset.status = "Online"

                if latency > 0:
                    asset.latency_ms = latency

                if source and source not in asset.detection_methods:
                    asset.detection_methods.append(source)

                # 1. IP & MAC Correlation (L2 ARP takes highest precedence)
                if ip and asset.ip_address != ip:
                    asset.ip_address = ip
                    if mac:
                        self._ip_to_mac[ip] = mac

                if mac and asset.mac_address in ("00:00:00:00:00:00", ""):
                    asset.mac_address = mac
                    if not asset.vendor or asset.vendor == "Unknown":
                        asset.vendor = lookup_vendor(mac)

                # 2. Hostname Correlation: Passive mDNS/NetBIOS/DHCP preferred over empty/DNS
                if hostname:
                    if not asset.hostname or source in ("mDNS", "NetBIOS", "LLMNR", "DHCP Option 55"):
                        asset.hostname = hostname

                # 3. OS Fingerprint Priority: DHCP Option 55 > TTL / Scanner > Heuristic
                if os_family and os_family != "Unknown":
                    if not asset.os_family or asset.os_family == "Unknown":
                        asset.os_family = os_family
                    elif source == "DHCP Option 55":
                        # Highest precedence
                        asset.os_family = os_family

                if dhcp_fp:
                    asset.dhcp_fingerprint = dhcp_fp

                self.asset_updated.emit(asset)

            # Security Anomaly Inspection (ARP Spoofing / MitM)
            if ip and mac:
                arp_alerts = self.security.inspect_arp_event(ip, mac)
                for a in arp_alerts:
                    self._alerts.append(a)
                    self.alert_generated.emit(a)

        self._emit_stats()

    def update_ports(self, ip: str, open_ports: List[int], services: Dict[int, str]):
        """
        Update open ports and banner information from Active Engine.
        """
        with self._lock:
            mac = self._ip_to_mac.get(ip)
            lookup_key = mac if mac else ip

            if lookup_key in self._assets:
                asset = self._assets[lookup_key]
                asset.open_ports = sorted(list(set(asset.open_ports + open_ports)))
                asset.services.update(services)
                asset.last_seen = datetime.now()

                # Infer OS heuristic from open ports if still unknown
                if asset.os_family in ("Unknown", "Linux / Android / Apple"):
                    if 135 in open_ports or 445 in open_ports or 3389 in open_ports:
                        asset.os_family = "Windows"
                    elif 22 in open_ports and 445 not in open_ports and 135 not in open_ports:
                        asset.os_family = "Linux"

                # Check default credentials if enabled
                for p in open_ports:
                    cred_alert = self.security.check_default_credentials(ip, p)
                    if cred_alert:
                        self._alerts.append(cred_alert)
                        self.alert_generated.emit(cred_alert)

                self.asset_updated.emit(asset)

        self._emit_stats()

    def get_all_assets(self) -> List[DeviceAsset]:
        """Return list of all current assets."""
        with self._lock:
            return list(self._assets.values())

    def get_all_alerts(self) -> List[SecurityAlert]:
        """Return list of all recorded security alerts."""
        with self._lock:
            return list(self._alerts)

    def _emit_stats(self):
        """Emit summary statistics for UI dashboard cards."""
        with self._lock:
            total = len(self._assets)
            online = sum(1 for a in self._assets.values() if a.status == "Online")
            rogues = sum(1 for a in self._assets.values() if a.is_rogue)
            alerts = len(self._alerts)

        self.stats_updated.emit({
            "total_hosts": total,
            "online_hosts": online,
            "rogue_hosts": rogues,
            "alert_count": alerts
        })

    def save_cache(self):
        """Persist current assets to local JSON cache."""
        try:
            with self._lock:
                serialized = [a.to_dict() for a in self._assets.values()]
            with open(self.cache_path, "w", encoding="utf-8") as f:
                json.dump(serialized, f, indent=2)
            logger.info(f"Saved {len(serialized)} assets to local cache: {self.cache_path}")
        except Exception as e:
            logger.warning(f"Failed to save asset cache: {e}")

    def load_cache(self):
        """Load known assets from local JSON cache."""
        if not os.path.exists(self.cache_path):
            return

        try:
            with open(self.cache_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            historical_macs = set()
            with self._lock:
                for item in data:
                    asset = DeviceAsset.from_dict(item)
                    asset.status = "Offline"  # Baseline until seen active
                    if not asset.vendor or asset.vendor in ("Unknown", "Bilinmiyor"):
                        asset.vendor = lookup_vendor(asset.mac_address)
                    lookup_key = asset.mac_address if asset.mac_address else asset.ip_address
                    self._assets[lookup_key] = asset
                    if asset.ip_address and asset.mac_address:
                        self._ip_to_mac[asset.ip_address] = asset.mac_address
                    if asset.mac_address:
                        historical_macs.add(asset.mac_address.upper())

            self.security.set_historical_macs(historical_macs)
            logger.info(f"Loaded {len(self._assets)} assets from local cache.")
        except Exception as e:
            logger.warning(f"Failed to load asset cache: {e}")
