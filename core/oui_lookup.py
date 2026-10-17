"""
OUI (Organizationally Unique Identifier) Hardware Vendor Lookup.
Maps MAC address prefixes (OUI) to vendor names for instant hardware classification.
"""

from typing import Dict, Optional

# Curated list of prominent hardware vendors by OUI (First 3 octets)
OUI_DATABASE: Dict[str, str] = {
    # Apple
    "00:17:F2": "Apple", "00:1E:52": "Apple", "00:23:12": "Apple", "00:26:08": "Apple",
    "04:0C:CE": "Apple", "0C:4D:E9": "Apple", "14:10:9F": "Apple", "28:CF:E9": "Apple",
    "3C:07:54": "Apple", "40:6C:8F": "Apple", "48:60:5F": "Apple", "50:BC:96": "Apple",
    "5C:95:AE": "Apple", "60:F8:1D": "Apple", "70:56:81": "Apple", "7C:04:D0": "Apple",
    "88:66:5A": "Apple", "98:01:A7": "Apple", "A4:83:E7": "Apple", "AC:BC:32": "Apple",
    "BC:D1:1F": "Apple", "C0:B6:58": "Apple", "CC:25:EF": "Apple", "DC:A9:04": "Apple",
    "E4:E4:AB": "Apple", "F0:18:98": "Apple", "F8:27:93": "Apple",

    # Intel
    "00:13:02": "Intel", "00:15:00": "Intel", "00:1B:21": "Intel", "00:21:5C": "Intel",
    "00:24:D7": "Intel", "08:11:96": "Intel", "24:77:03": "Intel", "34:13:E8": "Intel",
    "3C:FD:FE": "Intel", "48:51:B7": "Intel", "58:91:CF": "Intel", "68:05:CA": "Intel",
    "78:2B:CB": "Intel", "80:86:F2": "Intel", "8C:8D:28": "Intel", "A0:88:B4": "Intel",
    "AC:72:89": "Intel", "B4:96:91": "Intel", "C8:5B:76": "Intel", "D4:25:8B": "Intel",

    # Microsoft
    "00:15:5D": "Microsoft (Hyper-V)", "00:1D:D8": "Microsoft", "00:50:F2": "Microsoft",
    "28:18:78": "Microsoft", "48:E9:F1": "Microsoft", "50:1A:C5": "Microsoft",
    "60:45:BD": "Microsoft", "7C:1E:52": "Microsoft", "98:5F:D3": "Microsoft",
    "B4:AE:2B": "Microsoft", "C4:9D:ED": "Microsoft", "DC:98:40": "Microsoft",

    # Raspberry Pi Foundation
    "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi", "E4:5F:01": "Raspberry Pi",
    "28:CD:C1": "Raspberry Pi",

    # Espressif (ESP8266 / ESP32 IoT)
    "18:FE:34": "Espressif (ESP32/8266)", "24:0A:C4": "Espressif (ESP32/8266)",
    "24:6F:28": "Espressif (ESP32/8266)", "30:AE:A4": "Espressif (ESP32/8266)",
    "3C:61:05": "Espressif (ESP32/8266)", "4C:11:AE": "Espressif (ESP32/8266)",
    "5C:CF:7F": "Espressif (ESP32/8266)", "60:01:94": "Espressif (ESP32/8266)",
    "68:C6:3A": "Espressif (ESP32/8266)", "7C:DF:A1": "Espressif (ESP32/8266)",
    "84:CC:A8": "Espressif (ESP32/8266)", "84:F3:EB": "Espressif (ESP32/8266)",
    "A0:20:A6": "Espressif (ESP32/8266)", "AC:67:B2": "Espressif (ESP32/8266)",
    "BC:DD:C2": "Espressif (ESP32/8266)", "C4:4F:33": "Espressif (ESP32/8266)",

    # Cisco Systems
    "00:00:0C": "Cisco", "00:01:42": "Cisco", "00:01:C7": "Cisco", "00:04:4D": "Cisco",
    "00:0B:46": "Cisco", "00:1B:54": "Cisco", "00:22:55": "Cisco", "00:26:0B": "Cisco",
    "04:FE:7F": "Cisco", "18:8B:45": "Cisco", "28:AC:9E": "Cisco", "58:F3:9C": "Cisco",
    "70:81:05": "Cisco", "88:5A:92": "Cisco", "A4:93:4C": "Cisco", "BC:16:65": "Cisco",

    # TP-Link
    "00:1D:0F": "TP-Link", "00:23:CD": "TP-Link", "14:CF:92": "TP-Link", "1C:3B:F3": "TP-Link",
    "30:68:93": "TP-Link", "30:B5:C2": "TP-Link", "50:C7:BF": "TP-Link", "54:AF:97": "TP-Link",
    "60:32:B1": "TP-Link", "70:4F:57": "TP-Link", "74:DA:38": "TP-Link", "84:16:F9": "TP-Link",
    "90:F6:52": "TP-Link", "A8:57:4E": "TP-Link", "C0:25:E9": "TP-Link", "D8:07:B6": "TP-Link",
    "E8:48:B8": "TP-Link", "F4:EC:38": "TP-Link",

    # Zyxel / Keenetic / AirTies / Sagemcom / ZTE
    "00:19:CB": "Zyxel", "00:A0:C5": "Zyxel", "40:4A:03": "Zyxel", "50:67:AE": "Zyxel",
    "50:FF:20": "Keenetic", "04:BF:6D": "Keenetic", "E4:18:6B": "Keenetic",
    "00:18:E7": "AirTies", "18:28:61": "AirTies", "F4:8E:38": "AirTies",
    "00:1D:19": "Arcadyan", "7C:03:D8": "Arcadyan", "84:9C:A6": "Arcadyan",
    "00:26:44": "Sagemcom", "70:9F:26": "Sagemcom", "E4:5D:51": "Sagemcom",
    "00:1E:73": "ZTE", "00:22:93": "ZTE", "48:28:2F": "ZTE", "78:31:2B": "ZTE",

    # Samsung
    "00:07:AB": "Samsung", "00:12:47": "Samsung", "00:16:6C": "Samsung", "08:08:C2": "Samsung",
    "14:49:E0": "Samsung", "18:22:7E": "Samsung", "24:4B:81": "Samsung", "30:CD:A7": "Samsung",
    "38:0B:40": "Samsung", "44:78:3E": "Samsung", "50:85:69": "Samsung", "5C:2E:59": "Samsung",
    "64:1C:AE": "Samsung", "78:47:1D": "Samsung", "84:25:DB": "Samsung", "94:65:2D": "Samsung",
    "A0:82:1F": "Samsung", "B0:72:BF": "Samsung", "BC:44:86": "Samsung", "CC:07:AB": "Samsung",

    # Google
    "00:1A:11": "Google", "18:D6:C7": "Google", "3C:5A:B4": "Google", "54:60:09": "Google",
    "70:3E:AC": "Google", "94:EB:CD": "Google", "A4:77:33": "Google", "B4:F1:DA": "Google",
    "D8:6C:63": "Google", "F4:03:04": "Google", "F8:8F:C2": "Google",

    # Xiaomi
    "04:CF:8C": "Xiaomi", "14:F6:5A": "Xiaomi", "18:59:36": "Xiaomi", "28:6C:07": "Xiaomi",
    "34:80:B3": "Xiaomi", "3C:A6:F6": "Xiaomi", "58:44:98": "Xiaomi", "64:CC:2E": "Xiaomi",
    "78:11:DC": "Xiaomi", "8C:BE:BE": "Xiaomi", "98:FA:E3": "Xiaomi", "A4:74:9F": "Xiaomi",
    "AC:C1:EE": "Xiaomi", "C4:0B:CB": "Xiaomi", "E4:AA:EC": "Xiaomi", "F4:8E:92": "Xiaomi",

    # Dell
    "00:14:22": "Dell", "00:18:8B": "Dell", "00:21:70": "Dell", "14:18:77": "Dell",
    "18:03:73": "Dell", "24:B6:FD": "Dell", "34:17:EB": "Dell", "48:4D:7E": "Dell",
    "74:86:7A": "Dell", "84:7B:EB": "Dell", "90:B1:1C": "Dell", "B8:AC:6F": "Dell",
    "D4:BE:D9": "Dell", "EC:F4:BB": "Dell",

    # HP
    "00:08:02": "HP", "00:1B:78": "HP", "00:25:B3": "HP", "08:2E:5F": "HP",
    "14:58:D0": "HP", "18:A9:58": "HP", "28:92:4A": "HP", "3C:D9:2B": "HP",
    "40:A8:F0": "HP", "58:20:B1": "HP", "64:51:06": "HP", "9C:8E:99": "HP",
    "B4:99:BA": "HP", "C8:CB:B8": "HP", "E4:11:5B": "HP",

    # Huawei
    "00:1E:10": "Huawei", "00:25:68": "Huawei", "04:25:C5": "Huawei", "08:19:A6": "Huawei",
    "10:1B:54": "Huawei", "20:08:89": "Huawei", "38:4C:90": "Huawei", "48:57:02": "Huawei",
    "60:DE:44": "Huawei", "78:6A:89": "Huawei", "88:28:B3": "Huawei", "AC:E2:15": "Huawei",
    "CC:96:A0": "Huawei", "E0:19:54": "Huawei", "FC:48:EF": "Huawei",

    # Asus
    "00:15:F2": "Asus", "00:1E:8C": "Asus", "04:92:26": "Asus", "08:60:6E": "Asus",
    "10:BF:48": "Asus", "1C:87:2C": "Asus", "2C:4D:54": "Asus", "38:D5:47": "Asus",
    "40:16:7E": "Asus", "54:A0:50": "Asus", "60:A4:4C": "Asus", "70:4D:7B": "Asus",
    "9C:5C:8E": "Asus", "AC:22:0B": "Asus", "BC:EE:7B": "Asus", "F0:79:59": "Asus",

    # Netgear
    "00:09:5B": "Netgear", "00:0F:B5": "Netgear", "00:14:6C": "Netgear", "00:18:4D": "Netgear",
    "00:1F:33": "Netgear", "08:BD:43": "Netgear", "10:DA:43": "Netgear", "20:0C:C8": "Netgear",
    "28:C6:8E": "Netgear", "44:94:FC": "Netgear", "6C:B0:CE": "Netgear", "84:1B:5E": "Netgear",
    "9C:3D:CF": "Netgear", "B0:7F:B9": "Netgear", "C0:3F:0E": "Netgear", "E0:46:9A": "Netgear",

    # Ubiquiti Networks
    "00:15:6D": "Ubiquiti", "00:27:22": "Ubiquiti", "04:18:D6": "Ubiquiti", "24:A4:3C": "Ubiquiti",
    "44:D9:E7": "Ubiquiti", "68:72:51": "Ubiquiti", "74:83:C2": "Ubiquiti", "78:8A:20": "Ubiquiti",
    "80:2A:A8": "Ubiquiti", "AC:8B:A9": "Ubiquiti", "B4:FB:E4": "Ubiquiti", "DC:9F:DB": "Ubiquiti",
    "E0:63:DA": "Ubiquiti", "F0:9F:C2": "Ubiquiti",

    # Virtualization (VMware, VirtualBox, QEMU)
    "00:05:69": "VMware", "00:0C:29": "VMware", "00:50:56": "VMware",
    "08:00:27": "Oracle VirtualBox",
    "52:54:00": "QEMU / KVM Virtual NIC",

    # Amazon
    "00:FC:8B": "Amazon", "18:74:2E": "Amazon", "34:D2:70": "Amazon", "38:F7:3D": "Amazon",
    "40:B4:CD": "Amazon (Echo/Fire)", "44:65:0D": "Amazon", "68:37:E9": "Amazon",
    "74:75:48": "Amazon", "AC:63:BE": "Amazon", "CC:A7:C1": "Amazon",

    # Sony
    "00:04:1F": "Sony", "00:13:A9": "Sony", "00:1D:BA": "Sony", "00:24:8D": "Sony",
    "28:0D:FC": "Sony PlayStation", "70:9E:29": "Sony", "A8:E3:EE": "Sony PlayStation",
    "D4:4B:5E": "Sony", "F8:46:1C": "Sony",

    # Intel & LG
    "4C:5F:70": "Intel Corporate", "C4:36:6C": "LG Electronics / Innotek",

    # Realtek
    "00:E0:4C": "Realtek", "52:54:4C": "Realtek",
}


def is_locally_administered_mac(mac: str) -> bool:
    """
    IEEE 802 standardı: En anlamlı ilk baytın 2. biti 1 ise yerel olarak atanmış (rastgele) adrestir.
    Hex formatta 2. karakter 2, 6, A veya E'dir (örneğin x2, x6, xA, xE).
    iOS (Özel Wi-Fi Adresi), Android 10+ ve Windows 11 rastgele MAC özelliğidir.
    """
    if len(mac) >= 2:
        second_char = mac[1].upper()
        return second_char in ("2", "6", "A", "E")
    return False


def lookup_vendor(mac: str) -> str:
    """
    MAC adresinden OUI donanım üreticisini tespit eder.
    Rastgele/Gizli MAC adreslerini tanır.
    """
    if not mac:
        return "Bilinmiyor"
        
    normalized = mac.replace("-", ":").upper()
    parts = normalized.split(":")
    if len(parts) >= 3:
        oui = f"{parts[0]}:{parts[1]}:{parts[2]}"
        if oui in OUI_DATABASE:
            return OUI_DATABASE[oui]

    # Mobil cihazların özel / rastgele MAC kontrolü
    if is_locally_administered_mac(normalized):
        return "Özel / Rastgele MAC (Akıllı Telefon / Tablet)"

    return "Bilinmiyor"
