"""
Data models and schemas for Network Hunter.
Defines DeviceAsset, SecurityAlert, and ScanConfig dataclasses.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional
import uuid


@dataclass
class DeviceAsset:
    """
    Represents a discovered network asset with unified passive and active telemetry.
    """
    ip_address: str
    mac_address: str
    vendor: str = "Unknown"
    hostname: Optional[str] = None
    os_family: str = "Unknown"  # Windows, Linux, Android, iOS, Network, Embedded
    open_ports: List[int] = field(default_factory=list)
    services: Dict[int, str] = field(default_factory=dict)  # {80: "HTTP/1.1 Apache", 22: "OpenSSH_8.2"}
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    latency_ms: float = 0.0
    is_rogue: bool = False
    dhcp_fingerprint: Optional[str] = None
    ttl: Optional[int] = None
    detection_methods: List[str] = field(default_factory=list)
    status: str = "Online"

    def to_dict(self) -> dict:
        """Serialize asset to dictionary for local cache persistence or export."""
        return {
            "ip_address": self.ip_address,
            "mac_address": self.mac_address,
            "vendor": self.vendor,
            "hostname": self.hostname,
            "os_family": self.os_family,
            "open_ports": self.open_ports,
            "services": {str(k): v for k, v in self.services.items()},
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "latency_ms": round(self.latency_ms, 2),
            "is_rogue": self.is_rogue,
            "dhcp_fingerprint": self.dhcp_fingerprint,
            "ttl": self.ttl,
            "detection_methods": self.detection_methods,
            "status": self.status
        }

    @classmethod
    def from_dict(cls, data: dict) -> "DeviceAsset":
        """Reconstruct DeviceAsset from a dictionary."""
        first_seen = datetime.fromisoformat(data["first_seen"]) if isinstance(data.get("first_seen"), str) else datetime.now()
        last_seen = datetime.fromisoformat(data["last_seen"]) if isinstance(data.get("last_seen"), str) else datetime.now()
        services = {int(k): v for k, v in data.get("services", {}).items()}
        
        return cls(
            ip_address=data.get("ip_address", ""),
            mac_address=data.get("mac_address", ""),
            vendor=data.get("vendor", "Unknown"),
            hostname=data.get("hostname"),
            os_family=data.get("os_family", "Unknown"),
            open_ports=data.get("open_ports", []),
            services=services,
            first_seen=first_seen,
            last_seen=last_seen,
            latency_ms=data.get("latency_ms", 0.0),
            is_rogue=data.get("is_rogue", False),
            dhcp_fingerprint=data.get("dhcp_fingerprint"),
            ttl=data.get("ttl"),
            detection_methods=data.get("detection_methods", []),
            status=data.get("status", "Online")
        )


@dataclass
class SecurityAlert:
    """
    Represents an event triggered by the Security & Anomaly Detection Engine.
    """
    severity: str  # "INFO", "WARNING", "HIGH", "CRITICAL"
    alert_type: str  # "ROGUE_DEVICE", "ARP_SPOOFING", "GATEWAY_MAC_CHANGE", "DEFAULT_CREDENTIALS", "ANOMALY"
    title: str
    description: str
    target_ip: Optional[str] = None
    target_mac: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "severity": self.severity,
            "alert_type": self.alert_type,
            "title": self.title,
            "description": self.description,
            "target_ip": self.target_ip,
            "target_mac": self.target_mac,
            "timestamp": self.timestamp.isoformat()
        }


@dataclass
class ScanConfig:
    """
    Configuration parameters for active network sweeps and port probes.
    """
    subnet: str = "192.168.1.0/24"
    interface: Optional[str] = None
    rate_limit_pps: int = 100  # Max packets per second (strict safety cap)
    ports: List[int] = field(default_factory=lambda: [
        21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
        443, 445, 993, 995, 1433, 3306, 3389, 5432, 8080, 8443
    ])
    enable_banner_grab: bool = True
    enable_default_cred_check: bool = False
    timeout: float = 1.5
