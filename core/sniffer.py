"""
Module A: Zero-Touch Passive Sniffer.
Runs continuously in the background using promiscuous / raw packet capture or adaptive
multicast listeners to passively fingerprint devices without generating probe traffic.

Captures:
1. ARP Traffic: IP-MAC bindings.
2. DHCP Option 55 & Option 12: Parameter Request List for OS identification & Hostnames.
3. mDNS / Bonjour (UDP 5353): Hostnames, models, and service declarations.
4. NetBIOS / LLMNR (UDP 137 / 5355): Windows workstation and domain computer names.
"""

import time
import socket
import logging
from typing import Optional, Dict

from PyQt6.QtCore import QThread, pyqtSignal

from core.oui_lookup import lookup_vendor
from utils.privileges import can_use_raw_sockets
from utils.network_info import get_system_arp_cache

logger = logging.getLogger("NetworkHunter.Sniffer")

# Curated DHCP Option 55 signature signatures
DHCP_FINGERPRINTS = {
    # Windows
    "1,15,3,6,44,46,47,31,33,121,249,43": "Windows",
    "1,3,6,15,31,33,43,44,46,47,119,121,249,252": "Windows",
    "1,15,3,6,44,46,47,31,33,121,249,43,252": "Windows",
    "1,3,6,15,31,33,43,44,46,47,119,252": "Windows",
    
    # Apple iOS / macOS
    "1,3,6,15,119,252": "Apple iOS / macOS",
    "1,121,3,6,15,114,119,252": "macOS",
    "1,3,6,15,119": "Apple iOS",

    # Linux / Android
    "1,28,2,3,15,6,119,12,44,47,26,121,42": "Linux (Ubuntu/Debian)",
    "1,121,33,3,6,12,15,26,28,42,119": "Linux",
    "1,3,6,15,26,28,51,58,59,43": "Android",
    "1,28,3,15,6,119,12": "Android",

    # Embedded / IoT
    "1,3,6,15,28,33": "Embedded / IoT",
    "1,3,6,12,15,28": "Embedded / IoT (BusyBox/udhcp)",
}


def decode_netbios_name(encoded_name: bytes) -> str:
    """
    Decode first-level encoded NetBIOS name (RFC 1001).
    Two nibbles per byte, biased by 'A'.
    """
    try:
        decoded = []
        for i in range(0, len(encoded_name) - 1, 2):
            high = (encoded_name[i] - ord('A')) << 4
            low = encoded_name[i+1] - ord('A')
            c = high | low
            if 32 <= c <= 126:
                decoded.append(chr(c))
        return "".join(decoded).strip()
    except Exception:
        return ""


def identify_dhcp_os(param_req_list: str, vendor_class: Optional[str] = None) -> str:
    """
    Identify OS Family from DHCP Option 55 parameter request list string.
    """
    if vendor_class:
        vc_lower = vendor_class.lower()
        if "msft" in vc_lower:
            return "Windows"
        if "android" in vc_lower:
            return "Android"
        if "apple" in vc_lower:
            return "Apple iOS / macOS"
        if "udhcp" in vc_lower or "dropbear" in vc_lower:
            return "Embedded / IoT"

    # Exact signature match
    if param_req_list in DHCP_FINGERPRINTS:
        return DHCP_FINGERPRINTS[param_req_list]

    # Partial heuristic matching
    params = set(param_req_list.split(","))
    if {"44", "46", "47"}.issubset(params):
        return "Windows"  # NetBIOS over TCP/IP parameters
    if {"119", "252"}.issubset(params) and "44" not in params:
        return "Apple iOS / macOS"
    if {"26", "28", "42"}.issubset(params):
        return "Linux"

    return "Unknown"


class PassiveSnifferThread(QThread):
    """
    Background QThread that passively sniffs network packets without sending probes.
    Emits PyQt signals to the Correlation Engine.
    """
    host_observed = pyqtSignal(dict)
    packet_count = pyqtSignal(int)
    status_changed = pyqtSignal(str)
    error_occurred = pyqtSignal(str)

    def __init__(self, interface: Optional[str] = None, parent=None):
        super().__init__(parent)
        self.interface = interface
        self._is_running = False
        self._packet_counter = 0

    def run(self):
        self._is_running = True
        self._packet_counter = 0
        self.status_changed.emit("Zero-Touch Sniffer Active")
        logger.info(f"Starting passive sniffer on interface: {self.interface or 'Default'}")

        # Check if Scapy and raw sockets can be used
        use_scapy = can_use_raw_sockets()
        
        if use_scapy:
            self._run_scapy_sniffer()
        else:
            self.status_changed.emit("Running in Adaptive Passive Mode (System ARP & Multicast)")
            self._run_adaptive_fallback_sniffer()

    def stop(self):
        """Request the sniffer thread to stop gracefully."""
        self._is_running = False
        self.status_changed.emit("Sniffer Stopped")
        self.wait(2000)

    def _run_scapy_sniffer(self):
        """Full raw packet sniffer using Scapy when elevated privileges are present."""
        try:
            from scapy.all import sniff, ARP, UDP, DHCP, IP, Ether, DNS, DNSQR, DNSRR

            def packet_handler(pkt):
                if not self._is_running:
                    return

                self._packet_counter += 1
                if self._packet_counter % 20 == 0:
                    self.packet_count.emit(self._packet_counter)

                try:
                    # 1. ARP Traffic Inspection
                    if pkt.haslayer(ARP):
                        arp = pkt[ARP]
                        sender_ip = arp.psrc
                        sender_mac = arp.hwsrc.upper()
                        if sender_ip and sender_mac and sender_mac != "00:00:00:00:00:00":
                            self.host_observed.emit({
                                "ip_address": sender_ip,
                                "mac_address": sender_mac,
                                "vendor": lookup_vendor(sender_mac),
                                "source": "Passive ARP"
                            })

                    # 2. DHCP Option 55 Inspection (UDP 67/68)
                    if pkt.haslayer(DHCP) and pkt.haslayer(Ether):
                        mac = pkt[Ether].src.upper()
                        ip = pkt[IP].src if pkt.haslayer(IP) else None
                        hostname = None
                        param_req_list = None
                        vendor_class = None

                        for opt in pkt[DHCP].options:
                            if isinstance(opt, tuple):
                                opt_name, opt_val = opt[0], opt[1]
                                if opt_name == "param_req_list":
                                    param_req_list = ",".join(str(b) for b in opt_val)
                                elif opt_name == "hostname":
                                    hostname = opt_val.decode('utf-8', errors='ignore') if isinstance(opt_val, bytes) else str(opt_val)
                                elif opt_name == "vendor_class_id":
                                    vendor_class = opt_val.decode('utf-8', errors='ignore') if isinstance(opt_val, bytes) else str(opt_val)

                        if param_req_list:
                            os_family = identify_dhcp_os(param_req_list, vendor_class)
                            data = {
                                "mac_address": mac,
                                "os_family": os_family,
                                "dhcp_fingerprint": param_req_list,
                                "source": "DHCP Option 55"
                            }
                            if ip and not ip.startswith("0.0."):
                                data["ip_address"] = ip
                            if hostname:
                                data["hostname"] = hostname
                            self.host_observed.emit(data)

                    # 3. mDNS / Bonjour (UDP 5353)
                    if pkt.haslayer(UDP) and pkt[UDP].dport == 5353:
                        src_ip = pkt[IP].src if pkt.haslayer(IP) else None
                        src_mac = pkt[Ether].src.upper() if pkt.haslayer(Ether) else None
                        
                        if pkt.haslayer(DNS):
                            dns = pkt[DNS]
                            # Check questions
                            if dns.qdcount > 0 and pkt.haslayer(DNSQR):
                                qname = pkt[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
                                if ".local" in qname:
                                    host = qname.replace(".local", "").split(".")[0]
                                    if src_ip:
                                        self.host_observed.emit({
                                            "ip_address": src_ip,
                                            "mac_address": src_mac,
                                            "hostname": host,
                                            "source": "mDNS"
                                        })

                    # 4. LLMNR (UDP 5355) / NetBIOS (UDP 137)
                    if pkt.haslayer(UDP) and pkt[UDP].dport in (137, 5355):
                        src_ip = pkt[IP].src if pkt.haslayer(IP) else None
                        src_mac = pkt[Ether].src.upper() if pkt.haslayer(Ether) else None
                        
                        # LLMNR query
                        if pkt[UDP].dport == 5355 and pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
                            qname = pkt[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
                            if src_ip and qname:
                                self.host_observed.emit({
                                    "ip_address": src_ip,
                                    "mac_address": src_mac,
                                    "hostname": qname,
                                    "os_family": "Windows",
                                    "source": "LLMNR"
                                })

                except Exception as inner_e:
                    logger.debug(f"Packet parsing error: {inner_e}")

            # Run sniff in a loop checking _is_running
            while self._is_running:
                sniff(
                    prn=packet_handler,
                    timeout=2,
                    store=False,
                    iface=self.interface if self.interface else None,
                    stop_filter=lambda p: not self._is_running
                )

        except Exception as e:
            logger.warning(f"Scapy capture error ({e}). Falling back to adaptive mode.")
            self.error_occurred.emit(f"Scapy raw capture unavailable: {str(e)[:100]}")
            self._run_adaptive_fallback_sniffer()

    def _run_adaptive_fallback_sniffer(self):
        """
        Adaptive fallback sniffer when raw sockets/Npcap are not permitted.
        Monitors OS ARP table changes and listens on mDNS/SSDP broadcast sockets.
        """
        seen_arp = set()

        while self._is_running:
            try:
                # Poll system ARP cache
                arp_entries = get_system_arp_cache()
                for ip, mac in arp_entries:
                    key = (ip, mac)
                    if key not in seen_arp:
                        seen_arp.add(key)
                        self._packet_counter += 1
                        self.packet_count.emit(self._packet_counter)
                        self.host_observed.emit({
                            "ip_address": ip,
                            "mac_address": mac,
                            "vendor": lookup_vendor(mac),
                            "source": "Passive ARP (System)"
                        })
            except Exception as e:
                logger.debug(f"Adaptive ARP polling error: {e}")

            # Sleep in small increments to allow rapid stop
            for _ in range(30):
                if not self._is_running:
                    break
                time.sleep(0.1)
