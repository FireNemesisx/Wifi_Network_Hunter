"""
Network information and interface discovery utilities.
Provides tools to inspect local interfaces, subnets, default gateway,
and parse the system ARP cache.
"""

import sys
import socket
import struct
import subprocess
import re
import psutil
import logging
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("NetworkHunter.NetworkInfo")


def get_default_gateway() -> Tuple[Optional[str], Optional[str]]:
    """
    Find the default gateway IP and the associated local interface name.
    
    Returns:
        Tuple[Optional[str], Optional[str]]: (gateway_ip, interface_name)
    """
    gateway_ip = None
    iface_name = None

    try:
        if sys.platform == "win32":
            # Parse route print or ipconfig
            cmd = ["route", "print", "0.0.0.0"]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
            # Find line with 0.0.0.0 0.0.0.0 <gateway> <interface>
            for line in res.stdout.splitlines():
                parts = line.strip().split()
                if len(parts) >= 4 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                    gateway_ip = parts[2]
                    local_ip = parts[3]
                    # Find which interface has this local_ip
                    for name, addrs in psutil.net_if_addrs().items():
                        for addr in addrs:
                            if addr.family == socket.AF_INET and addr.address == local_ip:
                                iface_name = name
                                break
                    break
        else:
            # Linux: parse ip route
            cmd = ["ip", "route", "show", "default"]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
            for line in res.stdout.splitlines():
                parts = line.strip().split()
                if len(parts) >= 3 and parts[0] == "default" and parts[1] == "via":
                    gateway_ip = parts[2]
                    if len(parts) >= 5 and parts[3] == "dev":
                        iface_name = parts[4]
                    break
    except Exception as e:
        logger.warning(f"Failed to get default gateway via route command: {e}")

    # Fallback using a dummy UDP socket connect to determine outbound local IP
    if not gateway_ip:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()

            # Guess gateway by replacing last octet with .1
            octets = local_ip.split(".")
            gateway_ip = f"{octets[0]}.{octets[1]}.{octets[2]}.1"

            for name, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == socket.AF_INET and addr.address == local_ip:
                        iface_name = name
                        break
        except Exception as e:
            logger.debug(f"Outbound UDP fallback failed: {e}")

    return gateway_ip, iface_name


def get_interface_details() -> List[Dict]:
    """
    Enumerate active network interfaces with IP, MAC, netmask, and subnet CIDR.
    
    Returns:
        List[Dict]: List of interface information dictionaries.
    """
    interfaces = []
    default_gw, default_iface = get_default_gateway()

    try:
        net_addrs = psutil.net_if_addrs()
        net_stats = psutil.net_if_stats()

        for name, addrs in net_addrs.items():
            # Check if interface is up and has an IPv4 address
            stats = net_stats.get(name)
            is_up = stats.isup if stats else True

            # Filter out virtual/loopback interfaces if not up
            if not is_up and "loopback" in name.lower():
                continue

            ip_v4 = None
            netmask = None
            mac_addr = None

            for addr in addrs:
                if addr.family == socket.AF_INET:
                    # Ignore loopback 127.0.0.1
                    if not addr.address.startswith("127."):
                        ip_v4 = addr.address
                        netmask = addr.netmask
                elif hasattr(psutil, 'AF_LINK') and addr.family == psutil.AF_LINK:
                    mac_addr = addr.address
                elif sys.platform == "win32" and addr.family == -1:
                    mac_addr = addr.address

            if ip_v4:
                # Calculate subnet CIDR
                subnet = calculate_subnet_cidr(ip_v4, netmask or "255.255.255.0")
                is_default = (name == default_iface)
                interfaces.append({
                    "name": name,
                    "ip": ip_v4,
                    "netmask": netmask or "255.255.255.0",
                    "mac": mac_addr or "00:00:00:00:00:00",
                    "subnet": subnet,
                    "is_default": is_default,
                    "gateway": default_gw if is_default else None
                })
    except Exception as e:
        logger.error(f"Error enumerating interfaces: {e}")

    # Sort so default interface is first
    interfaces.sort(key=lambda x: not x["is_default"])
    return interfaces


def calculate_subnet_cidr(ip: str, netmask: str) -> str:
    """
    Compute CIDR notation (e.g. '192.168.1.0/24') from an IP and netmask.
    """
    try:
        ip_int = struct.unpack("!I", socket.inet_aton(ip))[0]
        mask_int = struct.unpack("!I", socket.inet_aton(netmask))[0]
        network_int = ip_int & mask_int
        network_ip = socket.inet_ntoa(struct.pack("!I", network_int))
        cidr_prefix = bin(mask_int).count("1")
        return f"{network_ip}/{cidr_prefix}"
    except Exception:
        # Default fallback to /24
        parts = ip.split(".")
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"


def get_system_arp_cache() -> List[Tuple[str, str]]:
    """
    Query the operating system's local ARP cache directly without sending raw packets.
    Works reliably across Windows, Linux, and macOS without administrator privileges.
    
    Returns:
        List[Tuple[str, str]]: List of (ip_address, mac_address) tuples.
    """
    results = []
    try:
        cmd = ["arp", "-a"]
        output = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
        
        # Regex to match IPv4 and MAC (XX-XX-XX-XX-XX-XX or XX:XX:XX:XX:XX:XX)
        # Windows format: 192.168.1.1       00-11-22-33-44-55     dynamic
        # Linux format:   ? (192.168.1.1) at 00:11:22:33:44:55 [ether] on eth0
        pattern = re.compile(
            r"(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)\s+.*?\s+([0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2})"
        )
        for line in output.splitlines():
            match = pattern.search(line)
            if match:
                ip = match.group(1)
                raw_mac = match.group(2).replace("-", ":").upper()
                # Ignore broadcast/multicast MACs and 127.0.0.1 or 255.255.255.255
                if ip.startswith("127.") or ip.startswith("224.") or ip.startswith("239.") or ip.endswith(".255"):
                    continue
                if raw_mac in ("FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00"):
                    continue
                results.append((ip, raw_mac))
    except Exception as e:
        logger.warning(f"Error reading system ARP cache: {e}")
        
    return results
