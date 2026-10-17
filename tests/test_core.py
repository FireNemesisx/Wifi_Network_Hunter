"""
Unit tests for Network Hunter core engines:
- Models serialization
- OUI lookup
- Correlation priority hierarchy
- Rogue device detection
- ARP spoofing / MitM detection
- Network info detection
"""

import unittest
from datetime import datetime
from core.models import DeviceAsset, SecurityAlert, ScanConfig
from core.oui_lookup import lookup_vendor
from core.security import SecurityEngine
from core.correlation import CorrelationEngine
from core.sniffer import identify_dhcp_os
from utils.network_info import calculate_subnet_cidr


class TestNetworkHunterCore(unittest.TestCase):

    def test_oui_lookup(self):
        self.assertEqual(lookup_vendor("00:17:F2:11:22:33"), "Apple")
        self.assertEqual(lookup_vendor("00-15-5D-AA-BB-CC"), "Microsoft (Hyper-V)")
        self.assertEqual(lookup_vendor("B8:27:EB:01:02:03"), "Raspberry Pi")
        self.assertEqual(lookup_vendor("18:FE:34:11:22:33"), "Espressif (ESP32/8266)")
        self.assertEqual(lookup_vendor("00:00:00:00:00:00"), "Bilinmiyor")

    def test_dhcp_fingerprint_identification(self):
        # Windows DHCP Option 55 signature
        win_sig = "1,15,3,6,44,46,47,31,33,121,249,43"
        self.assertEqual(identify_dhcp_os(win_sig), "Windows")

        # Apple signature
        apple_sig = "1,3,6,15,119,252"
        self.assertEqual(identify_dhcp_os(apple_sig), "Apple iOS / macOS")

        # Vendor class override
        self.assertEqual(identify_dhcp_os("1,2,3", vendor_class="MSFT 5.0"), "Windows")
        self.assertEqual(identify_dhcp_os("1,2,3", vendor_class="android-dhcp-13"), "Android")

    def test_subnet_cidr_calculation(self):
        cidr = calculate_subnet_cidr("192.168.1.45", "255.255.255.0")
        self.assertEqual(cidr, "192.168.1.0/24")

        cidr2 = calculate_subnet_cidr("10.0.0.15", "255.255.0.0")
        self.assertEqual(cidr2, "10.0.0.0/16")

    def test_device_asset_serialization(self):
        asset = DeviceAsset(
            ip_address="192.168.1.100",
            mac_address="00:17:F2:11:22:33",
            vendor="Apple",
            hostname="MacBook-Pro",
            os_family="Apple iOS / macOS",
            open_ports=[22, 80],
            services={22: "OpenSSH_8.9", 80: "Apache"}
        )
        d = asset.to_dict()
        self.assertEqual(d["ip_address"], "192.168.1.100")
        self.assertEqual(d["vendor"], "Apple")
        self.assertEqual(d["open_ports"], [22, 80])

        restored = DeviceAsset.from_dict(d)
        self.assertEqual(restored.ip_address, asset.ip_address)
        self.assertEqual(restored.mac_address, asset.mac_address)
        self.assertEqual(restored.services[22], "OpenSSH_8.9")

    def test_rogue_device_detection(self):
        sec = SecurityEngine()
        # Known historical MAC
        sec.set_historical_macs({"00:11:22:33:44:55"})

        known_dev = DeviceAsset(ip_address="192.168.1.10", mac_address="00:11:22:33:44:55")
        alert = sec.inspect_device_arrival(known_dev)
        self.assertIsNone(alert)
        self.assertFalse(known_dev.is_rogue)

        # Brand new rogue MAC
        rogue_dev = DeviceAsset(ip_address="192.168.1.55", mac_address="AA:BB:CC:DD:EE:FF")
        alert = sec.inspect_device_arrival(rogue_dev)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.alert_type, "ROGUE_DEVICE")
        self.assertEqual(alert.severity, "HIGH")
        self.assertTrue(rogue_dev.is_rogue)

    def test_arp_gateway_spoofing_detection(self):
        sec = SecurityEngine(gateway_ip="192.168.1.1")
        # Baseline gateway MAC locked
        sec.set_gateway("192.168.1.1", "00:AA:BB:CC:DD:EE")

        # Legitimate traffic from gateway
        alerts = sec.inspect_arp_event("192.168.1.1", "00:AA:BB:CC:DD:EE")
        self.assertEqual(len(alerts), 0)

        # Attacker tries to poison gateway IP with different MAC
        alerts = sec.inspect_arp_event("192.168.1.1", "DE:AD:BE:EF:00:01")
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].alert_type, "GATEWAY_MAC_CHANGE")
        self.assertEqual(alerts[0].severity, "CRITICAL")

    def test_correlation_priority_hierarchy(self):
        import tempfile
        engine = CorrelationEngine(cache_dir=tempfile.mkdtemp())

        # Step 1: Passive ARP registers host
        engine.process_telemetry({
            "ip_address": "192.168.1.50",
            "mac_address": "00:17:F2:AA:BB:CC",
            "source": "Passive ARP"
        })
        assets = engine.get_all_assets()
        self.assertEqual(len(assets), 1)
        asset = assets[0]
        self.assertEqual(asset.vendor, "Apple")
        self.assertEqual(asset.os_family, "Unknown")

        # Step 2: Passive mDNS provides hostname
        engine.process_telemetry({
            "ip_address": "192.168.1.50",
            "hostname": "macbook-work",
            "source": "mDNS"
        })
        self.assertEqual(asset.hostname, "macbook-work")

        # Step 3: DHCP Option 55 fingerprint takes highest OS precedence
        engine.process_telemetry({
            "mac_address": "00:17:F2:AA:BB:CC",
            "os_family": "Apple iOS / macOS",
            "dhcp_fingerprint": "1,3,6,15,119,252",
            "source": "DHCP Option 55"
        })
        self.assertEqual(asset.os_family, "Apple iOS / macOS")

        # Step 4: Active scan discovers open ports
        engine.update_ports("192.168.1.50", [22, 443], {22: "OpenSSH_8.9", 443: "HTTPS"})
        self.assertEqual(asset.open_ports, [22, 443])
        self.assertEqual(asset.services[22], "OpenSSH_8.9")


if __name__ == "__main__":
    unittest.main()
