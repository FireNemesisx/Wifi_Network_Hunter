"""
Privilege and capability checker utilities for Network Hunter.
Checks whether the process has administrator/root permissions,
or raw socket / CAP_NET_RAW capabilities for Scapy packet injection.
"""

import os
import sys
import ctypes
import logging

logger = logging.getLogger("NetworkHunter.Privileges")


def is_admin() -> bool:
    """
    Check if the current process has administrative / root privileges.
    
    Returns:
        bool: True if running as Windows Administrator or Linux root (euid == 0),
              False otherwise.
    """
    try:
        if sys.platform == "win32":
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except Exception as e:
        logger.warning(f"Failed to check admin status: {e}")
        return False


def can_use_raw_sockets() -> bool:
    """
    Test if the process can create a raw socket or if Npcap/WinPcap/libpcap is available.
    
    Returns:
        bool: True if raw network operations are permitted.
    """
    if not is_admin():
        return False

    try:
        import scapy.config
        # Check if pcap service or raw socket can be initialized
        if sys.platform == "win32":
            # On Windows, Scapy uses Npcap / WinPcap
            import scapy.arch.windows
            return True
        else:
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            s.close()
            return True
    except Exception as e:
        logger.debug(f"Raw socket capability test failed: {e}")
        return False


def get_elevation_instructions() -> str:
    """
    Yönetici yetkileri ve Npcap kurulum rehberini Türkçe döndürür.
    """
    if sys.platform == "win32":
        return (
            "Windows Yönetici Yetkileri Eksik!\n\n"
            "Tam paket yakalama (Promiscuous ARP Sniffer, DHCP Parmak İzi, SYN Taramaları) "
            "için yükseltilmiş yönetici izinleri ve Npcap sürücüsü gereklidir.\n\n"
            "Tüm özellikleri tam kapasiteyle etkinleştirmek için:\n"
            "1. Network Hunter uygulamasını kapatın.\n"
            "2. PowerShell veya Terminal simgesine sağ tıklayıp 'Yönetici olarak çalıştır'ı seçin.\n"
            "3. Npcap'in (https://npcap.com) 'WinPcap API-compatible Mode' seçeneğiyle kurulu olduğundan emin olun.\n\n"
            "Uygulama şu anda Adaptif Geri Çekilme Modunda (Sistem ARP Tablosu ve Standart Soketler) kesintisiz çalışmaya devam etmektedir."
        )
    else:
        return (
            "Root / CAP_NET_RAW Yetkisi Eksik!\n\n"
            "Ham soket paket yakalama için root veya CAP_NET_RAW yetkisi gerekir.\n\n"
            "Uygulamayı yetkili çalıştırmak için:\n"
            "    sudo python main.py\n\n"
            "Uygulama şu anda Adaptif Geri Çekilme Modunda çalışmaktadır."
        )
