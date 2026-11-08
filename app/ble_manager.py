import asyncio
import hashlib
import json
import logging
import os
import re
import struct
import time
import urllib.error
import urllib.request
from collections import deque
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Deque, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("sensor_scanner.ble_manager")

try:
    from bleak import BleakClient, BleakScanner
    from bleak.backends.device import BLEDevice
    from bleak.backends.scanner import AdvertisementData

    BLEAK_AVAILABLE = True
except Exception:
    BleakClient = None  # type: ignore
    BleakScanner = None  # type: ignore
    BLEDevice = Any  # type: ignore
    AdvertisementData = Any  # type: ignore
    BLEAK_AVAILABLE = False

try:
    from TheengsDecoder import decodeBLE as theengs_decode_ble

    THEENGS_AVAILABLE = True
except Exception:
    theengs_decode_ble = None
    THEENGS_AVAILABLE = False


# Common Bluetooth SIG Company Identifiers
BLE_COMPANY_IDS: Dict[int, str] = {
    0x0001: "Nokia",
    0x0002: "Intel",
    0x0006: "Microsoft",
    0x000A: "Qualcomm",
    0x000F: "Broadcom",
    0x004C: "Apple",
    0x0059: "Nordic Semiconductor",
    0x0075: "Samsung",
    0x0087: "Garmin",
    0x00E0: "Google",
    0x010F: "HiSilicon",
    0x012D: "Sony",
    0x0131: "Cypress",
    0x0157: "Huami / Amazfit",
    0x0171: "Amazon",
    0x01DA: "Logitech",
    0x02E5: "Espressif",
    0x02FF: "Silicon Labs",
    0x0310: "Sensi / Emerson",
    0x038F: "Xiaomi",
    0x0499: "Ruuvi Innovations",
    0x058E: "Meta",
    0x0590: "Pur3 / Espruino",
    0x060F: "Signify / Philips Hue",
    0x06FE: "Zeekr / Geely",
    0x0768: "Peloton",
    0x0822: "Shelly / Allterco",
    0x0953: "IKEA of Sweden",
    0x09A3: "Plejd",
    0xEC88: "Govee",
}

# Common 16-bit Bluetooth SIG & Vendor Service UUIDs
BLE_SERVICE_UUIDS: Dict[str, str] = {
    "1800": "Generic Access",
    "1801": "Generic Attribute",
    "180A": "Device Information",
    "180F": "Battery Service",
    "1812": "HID (Human Interface Device)",
    "181A": "Environmental Sensing",
    "181C": "BTHome v1 / User Data",
    "0211": "Tesla VCSEC Service",
    "1122": "Tesla Vehicle BLE Key",
    "FCD2": "BTHome v2",
    "FD44": "Apple FindMy Network",
    "FD5A": "Samsung SmartThings Find",
    "FD6F": "Exposure Notification",
    "FDFD": "Zeekr/Geely Digital Key",
    "FE78": "Garmin BLE Service",
    "FE95": "Xiaomi MiBeacon",
    "FE9F": "Google Fast Pair",
    "FEAA": "Google Eddystone",
    "FEAF": "Nest",
    "FEED": "Tile Tracker",
    "FEF3": "Google Nearby Share",
    "CF1D96FE-9461-5C4A-8668-75584696A730": "Daikin / Smart HVAC BLE Provisioning Service",
}

KNOWN_FULL_GATT_SERVICE_UUIDS: Dict[str, str] = {
    "cf1d96fe-9461-5c4a-8668-75584696a730": "Daikin / Smart HVAC BLE Provisioning Service",
    "00000211-b2d1-43f0-9b88-960cebf8b91e": "Tesla VCSEC Vehicle Security Service",
}

TESLA_NODE_NAMES: Dict[str, str] = {
    "C": "Controller (C)",
    "D": "Driver (D)",
    "P": "Passenger (P)",
    "R": "Rear (R)",
    "F": "Frunk (F)",
    "B": "Body (B)",
}

TESLA_BEACON_RE = re.compile(r"^S[0-9a-fA-F]{15,17}[A-Za-z0-9]$")
MAC_LIKE_NAME_RE = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$")

KNOWN_IBEACON_UUIDS: Dict[str, str] = {
    "E20A39F4-73F5-4BC4-1864-17D1AD07A962": "IoT / AirLocate Standard SDK Beacon",
    "74278BDA-B644-4520-8F0C-720EAF059935": "Tesla / Estimote Default UUID",
    "50765CB7-D9EA-4E21-99A4-FA879613A492": "Smart Home / Media Beacon",
}

BUILTIN_OUI_VENDORS: Dict[str, str] = {
    "A4:C1:38": "Telink Semiconductor (Xiaomi/ATC/Tuya)",
    "54:EF:44": "Lumi United Technology (Aqara)",
    "04:CF:8C": "Xiaomi Communications",
    "28:6C:07": "Xiaomi Communications",
    "78:11:DC": "Xiaomi Communications",
    "58:2D:34": "Qingping / ClearGrass",
    "24:62:AB": "Espressif Inc.",
    "24:0A:C4": "Espressif Inc.",
    "30:AE:A4": "Espressif Inc.",
    "3C:71:BF": "Espressif Inc.",
    "7C:9E:BD": "Espressif Inc.",
    "84:CC:A8": "Espressif Inc.",
    "94:B9:7E": "Espressif Inc.",
    "A0:20:A6": "Espressif Inc.",
    "AC:67:B2": "Espressif Inc.",
    "BC:DD:C2": "Espressif Inc.",
    "C4:4F:33": "Espressif Inc.",
    "CC:50:E3": "Espressif Inc.",
    "DC:4F:22": "Espressif Inc.",
    "E8:DB:84": "Espressif Inc.",
    "EC:FA:BC": "Espressif Inc.",
    "F4:CF:A2": "Espressif Inc.",
    "00:1E:C0": "Microchip Technology",
    "D8:80:39": "Microchip Technology",
    "00:0B:57": "Silicon Laboratories",
    "60:A4:23": "Silicon Laboratories",
    "84:2E:14": "Silicon Laboratories",
    "90:FD:9F": "Silicon Laboratories",
    "00:12:4B": "Texas Instruments",
    "24:71:89": "Texas Instruments",
    "54:6C:0E": "Texas Instruments",
    "B0:B4:48": "Texas Instruments",
    "F0:F8:F2": "Texas Instruments",
    "D0:B5:C2": "Texas Instruments",
    "C8:FD:19": "Plejd AB",
    "E8:EB:1B": "Plejd AB",
    "34:94:54": "Shelly / Allterco Robotics",
    "E8:68:E7": "Shelly / Allterco Robotics",
    "C4:D8:D5": "Ruuvi Innovations",
    "EC:FE:7E": "BlueRadios / Estimote",
    "00:07:80": "Bluegiga / Silicon Labs",
    "38:8C:50": "LG Electronics",
    "A8:23:FE": "LG Electronics",
    "CC:2D:83": "LG Electronics",
    "28:39:5E": "Samsung Electronics",
    "64:1C:AE": "Samsung Electronics",
    "8C:79:F5": "Samsung Electronics",
    "D0:03:DF": "Samsung Electronics",
    "F8:04:2E": "Samsung Electronics",
    "54:2A:1B": "Sonos, Inc.",
    "78:28:CA": "Sonos, Inc.",
    "94:9F:3E": "Sonos, Inc.",
    "00:17:88": "Signify (Philips Hue)",
    "EC:B5:FA": "Signify (Philips Hue)",
}

GATT_IDENTITY_CHARS: Dict[str, str] = {
    "00002a00-0000-1000-8000-00805f9b34fb": "gatt_name",
    "00002a01-0000-1000-8000-00805f9b34fb": "gatt_appearance",
    "00002a29-0000-1000-8000-00805f9b34fb": "gatt_manufacturer",
    "00002a24-0000-1000-8000-00805f9b34fb": "gatt_model",
    "00002a25-0000-1000-8000-00805f9b34fb": "gatt_serial",
    "00002a26-0000-1000-8000-00805f9b34fb": "gatt_firmware",
    "00002a27-0000-1000-8000-00805f9b34fb": "gatt_hardware",
    "00002a28-0000-1000-8000-00805f9b34fb": "gatt_software",
    "00002a19-0000-1000-8000-00805f9b34fb": "battery_pct",
}

GATT_CHAR_DESCRIPTIONS: Dict[str, str] = {
    "2A00": "Device Name",
    "2A01": "Appearance",
    "2A04": "Peripheral Preferred Connection Parameters",
    "2A05": "Service Changed",
    "2A19": "Battery Level",
    "2A23": "System ID",
    "2A24": "Model Number String",
    "2A25": "Serial Number String",
    "2A26": "Firmware Revision String",
    "2A27": "Hardware Revision String",
    "2A28": "Software Revision String",
    "2A29": "Manufacturer Name String",
    "2A2A": "IEEE 11073-20601 Regulatory Certification",
    "2A50": "PnP ID",
    "2AA6": "Central Address Resolution",
}


def _decode_printable_ascii(raw_bytes: bytes) -> Optional[str]:
    if not raw_bytes:
        return None
    cleaned = raw_bytes.replace(b"\x00", b"").strip()
    if not cleaned:
        return None
    try:
        txt = cleaned.decode("utf-8", errors="strict").strip()
        if txt and all(c.isprintable() or c in ("\t", "\n", "\r") for c in txt):
            return txt
    except Exception:
        pass
    return None


def compute_tesla_ble_prefix(tesla_vin: Optional[str]) -> str:
    """
    Computes the 17-character Tesla BLE Beacon prefix ('S' + first 16 hex chars of SHA-1(VIN)).
    """
    vin_clean = (tesla_vin or "").strip().upper()
    if len(vin_clean) < 5:
        return ""
    vin_hash = hashlib.sha1(vin_clean.encode("utf-8")).hexdigest()[:16].lower()
    return f"S{vin_hash}"


ROTATING_BLE_SERVICE_UUID_PREFIXES = (
    "0000fea0",  # Google Cast / Sony HT-A9 / B&O / Chromecast
    "0000fe9f",  # Google Fast Pair / Nearby
    "0000fe2c",  # Google Fast Pair Service
    "0000fd5a",  # Samsung SmartThings / Find
    "0000fd69",  # Samsung Continuity
    "0000feaf",  # Nest
)

SENSOR_BLE_SERVICE_UUID_PREFIXES = (
    "0000181a",  # Environmental Sensing (ATC / PVVX / Mi)
    "0000fcd2",  # BTHome v2
    "0000181c",  # BTHome v1 / User Data
    "0000fe95",  # Xiaomi MiBeacon
    "0000fdcd",  # Qingping
    "0000180f",  # Battery Service
    "0000fee0",  # Xiaomi / Huami
    "0000fff0",  # Inkbird / ThermoPro
)

FIXED_MAC_SENSOR_MODELS = {
    "ATC-Thermometer",
    "Govee-BLE",
    "Plejd-Mesh",
    "Enhauto-S3XY",
    "BTHome-v2",
    "BTHome-v1",
    "Xiaomi-MiBeacon",
    "Qingping-BLE",
    "RuuviTag-BLE",
    "Inkbird-BLE",
    "SwitchBot-BLE",
    "ThermoPro-BLE",
    "Shelly-BLE",
}

VOLVO_VEHICLE_MODELS = {"ES90", "EX30", "EX90", "EX40", "EC40", "EX60"}

SENSOR_NAME_WITH_MAC_SUFFIX_RE = re.compile(
    r"^(ATC_|LYWSD|GVH|IHOMENT_|GOVEE_|LUMI|MIJIA|CGD1|CGG1|QINGPING|RUUVI|BTHOME)",
    re.IGNORECASE,
)


def analyze_mac_type(
    mac: str,
    mac_vendor: Optional[str] = None,
    is_sensor: bool = False,
    service_data: Optional[Dict[str, Any]] = None,
) -> str:
    """
    Analyzes a BLE MAC address along with OUI vendor and service_data context.
    Only classifies as 'IEEE Public (Fast)' if the OUI prefix is a known registered
    hardware OUI (and not a rotating service like 0xFEA0) or a real measurement sensor.
    """
    srv_dict = service_data if isinstance(service_data, dict) else {}
    has_rotating_srv = any(
        str(u).lower().startswith(ROTATING_BLE_SERVICE_UUID_PREFIXES)
        for u in srv_dict.keys()
    )
    if has_rotating_srv and not is_sensor:
        return "Random Private (Roterande)"

    try:
        first_byte = int(str(mac).split(":")[0], 16)
        top_two = first_byte & 0xC0
        is_locally_administered = bool(first_byte & 0x02)
        if top_two == 0xC0 and is_locally_administered:
            return "Random Static"
        if is_sensor or (mac_vendor and not has_rotating_srv):
            if not is_locally_administered:
                return "IEEE Public (Fast)"
        return "Random Private (Roterande)"
    except Exception:
        return "Random Private (Roterande)"


def compute_ble_device_id(
    mac: str,
    mac_vendor: Optional[str],
    local_name: Optional[str],
    service_data: Optional[Dict[str, Any]],
    manufacturer_data: Optional[Dict[str, Any]],
    ibeacon_info: Optional[Dict[str, Any]],
    is_sensor: bool,
    model: Optional[str] = None,
    manufacturer_id: Optional[str] = None,
    service_uuids: Optional[List[str]] = None,
) -> Tuple[str, Optional[str]]:
    """
    Computes a deterministic BLE device_id and optional fingerprint_source.
    - Case A: Real measurement sensors & known fixed-OUI hardware sensors (ATC, BTHome, Mi, Inkbird, Govee, Plejd, Tesla S...C) -> keep MAC or Tesla name.
    - Case B: Passive BLE devices with static service_data (>= 8 hex chars / 4 bytes, e.g. 0000fea0 on HT-A9) -> FP<10-char SHA1>.
    - Case C: iBeacons with rotating MAC -> IB<10-char SHA1>.
    - Case D: Rotating MAC with local_name + manufacturer_data (>= 12 hex chars / 6 bytes) -> FP<10-char SHA1>.
    - Case E: Naked rotating MAC beacon with non-empty local_name (e.g. ES90, ACER, SteelSeries) -> FP<10-char SHA1>.
    - Case F: All other devices -> MAC without colons.
    """
    mac_clean = re.sub(r"[^0-9A-Fa-f]", "", str(mac or "")).upper()
    ln = str(local_name or "").strip()
    mod = str(model or "").strip()

    # Case A1: Tesla Vehicles (unique S<16-hex><endpoint> local_name)
    if mod == "Tesla-Vehicle-BLE" or (ln and TESLA_BEACON_RE.match(ln)):
        return (ln if ln else mac_clean), None

    srv_dict = service_data if isinstance(service_data, dict) else {}
    has_rotating_service = any(
        str(u).lower().startswith(ROTATING_BLE_SERVICE_UUID_PREFIXES)
        for u in srv_dict.keys()
    )

    # Case A2: Real measurement sensors & known fixed-OUI hardware sensors
    if is_sensor or mod in FIXED_MAC_SENSOR_MODELS:
        return (mac_clean or "UNKNOWN"), None

    # Case B: Devices with static service_data identity (e.g. 0000fea0-... on HT-A9, Google Cast, Fast Pair where is_beacon_only is True)
    if srv_dict and (not mac_vendor or has_rotating_service):
        for uuid_key in sorted(srv_dict.keys(), key=lambda x: str(x).lower()):
            uuid_norm = str(uuid_key).strip().lower()
            if uuid_norm.startswith(SENSOR_BLE_SERVICE_UUID_PREFIXES):
                continue
            raw_val = srv_dict[uuid_key]
            if isinstance(raw_val, (bytes, bytearray)):
                srv_hex = bytes(raw_val).hex().upper()
            else:
                srv_hex = re.sub(r"[^0-9A-Fa-f]", "", str(raw_val or "")).upper()
            if len(srv_hex) >= 8:
                fp = hashlib.sha1(f"{ln}:{uuid_norm}:{srv_hex}".encode("utf-8")).hexdigest()[:10].upper()
                return f"FP{fp}", f"Service Data ({uuid_norm[:8]})"

    # If the device has a verified fixed OUI vendor and no rotating service_data, keep its MAC
    if mac_vendor and not has_rotating_service:
        return (mac_clean or "UNKNOWN"), None

    # Case C: iBeacons with rotating MAC (no known fixed OUI)
    ib_dict = ibeacon_info if isinstance(ibeacon_info, dict) else {}
    ib_uuid = str(ib_dict.get("ibeacon_uuid") or "").strip().upper()
    if ib_uuid:
        ib_major = str(ib_dict.get("major") if ib_dict.get("major") is not None else "")
        ib_minor = str(ib_dict.get("minor") if ib_dict.get("minor") is not None else "")
        fp = hashlib.sha1(f"IBEACON:{ib_uuid}:{ib_major}:{ib_minor}".encode("utf-8")).hexdigest()[:10].upper()
        return f"IB{fp}", f"iBeacon ({ib_uuid[:8]})"

    # Case D: Rotating MAC with local_name + manufacturer_data (>= 12 hex chars / 6 bytes)
    mfg_dict = manufacturer_data if isinstance(manufacturer_data, dict) else {}
    if ln and mfg_dict:
        for mfg_key in sorted(mfg_dict.keys(), key=lambda x: str(x).upper()):
            raw_mfg = mfg_dict[mfg_key]
            if isinstance(raw_mfg, (bytes, bytearray)):
                mfg_hex = bytes(raw_mfg).hex().upper()
            else:
                mfg_hex = re.sub(r"[^0-9A-Fa-f]", "", str(raw_mfg or "")).upper()
            if len(mfg_hex) >= 12:
                mfg_id_str = str(mfg_key).strip().upper()
                fp = hashlib.sha1(f"MFG:{ln}:{mfg_id_str}:{mfg_hex}".encode("utf-8")).hexdigest()[:10].upper()
                return f"FP{fp}", f"Manufacturer Data ({mfg_id_str})"

    # Case E: Naked rotating MAC beacon with non-empty local_name (e.g. ES90, ACER, SteelSeries Arctis Nova 5)
    if len(ln) >= 2 and not SENSOR_NAME_WITH_MAC_SUFFIX_RE.match(ln):
        mfg_id_val = str(manufacturer_id or ib_dict.get("manufacturer_id") or "").strip().upper()
        srv_uuids_raw = service_uuids if service_uuids is not None else ib_dict.get("service_uuids")
        srv_uuids_sorted = ",".join(sorted(str(u).strip().lower() for u in (srv_uuids_raw or []) if u))
        sig_base = f"NAMED_ROTATING:{mod}:{ln.upper()}:{mfg_id_val}:{srv_uuids_sorted}"
        fp = hashlib.sha1(sig_base.encode("utf-8")).hexdigest()[:10].upper()
        return f"FP{fp}", f"Roterande MAC ({ln})"

    # Case F: All other devices -> MAC without colons
    return (mac_clean or "UNKNOWN"), None


def decode_apple_continuity(data: bytes) -> Tuple[Optional[str], Optional[str]]:
    """
    Decodes Apple Continuity (Company ID 0x004C) sub-type byte into (apple_type, suggested_model).
    """
    if not data:
        return None, None
    sub_type = data[:1].hex().upper()
    if sub_type == "01":
        return "iOS Background App (Overflow)", None
    if sub_type == "02":
        return "iBeacon", "iBeacon-BLE"
    if sub_type == "05":
        return "Apple AirDrop", "Apple-AirDrop"
    if sub_type == "07":
        return "AirPods / Beats", "Apple-AirPods"
    if sub_type in ("09", "0A"):
        return "AirPlay / Apple TV", "Apple-AirPlay"
    if sub_type == "0C":
        return "Apple Handoff", None
    if sub_type == "10":
        return "Apple Nearby (iPhone/iPad/Mac)", None
    if sub_type == "12":
        return "Apple FindMy / AirTag", "Apple-AirTag"
    return f"Apple Continuity (0x{sub_type})", None


def lookup_ble_service_names(srv_uuids: List[str], srv_data: Dict[str, bytes]) -> Optional[str]:
    """
    Maps 16-bit or 128-bit BLE Service UUIDs to human-readable service descriptions.
    """
    found: List[str] = []
    all_uuids = list(srv_uuids or []) + list((srv_data or {}).keys())
    for raw_u in all_uuids:
        u = str(raw_u).strip().upper()
        short_hex = ""
        if len(u) == 4:
            short_hex = u
        elif u.startswith("0X") and len(u) == 6:
            short_hex = u[2:]
        elif "-" in u:
            first_seg = u.split("-")[0]
            if len(first_seg) == 8 and first_seg.startswith("0000"):
                short_hex = first_seg[4:]
        if short_hex and short_hex in BLE_SERVICE_UUIDS:
            label = f"{BLE_SERVICE_UUIDS[short_hex]} (0x{short_hex})"
            if label not in found:
                found.append(label)
        elif u.lower() in KNOWN_FULL_GATT_SERVICE_UUIDS:
            label = KNOWN_FULL_GATT_SERVICE_UUIDS[u.lower()]
            if label not in found:
                found.append(label)
        elif "00000211-B2D1-43F0-9B88-960CEBF8B91E" in u:
            label = "Tesla VCSEC Service (0x0211)"
            if label not in found:
                found.append(label)
    return ", ".join(found) if found else None


def is_mac_like_name(name: Optional[str]) -> bool:
    if not name:
        return True
    cleaned = name.strip()
    if not cleaned:
        return True
    return bool(MAC_LIKE_NAME_RE.match(cleaned))


def parse_bthome_v2(data: bytes) -> Dict[str, Any]:
    """
    Parses unencrypted BTHome v2 service data (UUID 0xFCD2).
    """
    out: Dict[str, Any] = {}
    if len(data) < 2:
        return out

    header = data[0]
    encrypted = bool(header & 0x01)
    version = (header >> 5) & 0x07
    if encrypted or version not in (1, 2):
        return out

    idx = 1
    n = len(data)
    while idx < n:
        obj_id = data[idx]
        idx += 1
        if obj_id == 0x00:  # packet id (uint8)
            if idx + 1 > n:
                break
            out["sequence"] = data[idx]
            idx += 1
        elif obj_id == 0x01:  # battery % (uint8)
            if idx + 1 > n:
                break
            bat = data[idx]
            out["battery_pct"] = bat
            out["battery_ok"] = 1 if bat > 15 else 0
            idx += 1
        elif obj_id == 0x02:  # temperature (sint16, 0.01 °C)
            if idx + 2 > n:
                break
            val = struct.unpack_from("<h", data, idx)[0]
            out["temperature_C"] = round(val * 0.01, 2)
            idx += 2
        elif obj_id == 0x03:  # humidity (uint16, 0.01 %)
            if idx + 2 > n:
                break
            val = struct.unpack_from("<H", data, idx)[0]
            out["humidity"] = round(val * 0.01, 1)
            idx += 2
        elif obj_id == 0x04:  # pressure (uint24, 0.01 hPa)
            if idx + 3 > n:
                break
            val = int.from_bytes(data[idx : idx + 3], "little", signed=False)
            out["pressure_hPa"] = round(val * 0.01, 1)
            idx += 3
        elif obj_id == 0x05:  # illuminance (uint24, 0.01 lux)
            if idx + 3 > n:
                break
            val = int.from_bytes(data[idx : idx + 3], "little", signed=False)
            out["lux"] = round(val * 0.01, 1)
            idx += 3
        elif obj_id == 0x0C:  # voltage (uint16, 0.001 V)
            if idx + 2 > n:
                break
            val = struct.unpack_from("<H", data, idx)[0]
            out["voltage_V"] = round(val * 0.001, 3)
            out["battery_mV"] = val
            idx += 2
        elif obj_id in (0x10, 0x11, 0x15, 0x2D):  # power/opening/battery_low/window-door (uint8)
            if idx + 1 > n:
                break
            bval = data[idx]
            if obj_id == 0x15:
                out["battery_ok"] = 0 if bval else 1
            elif obj_id == 0x2D:
                out["contact_open"] = 1 if bval else 0
            else:
                out["state"] = "ON" if bval else "OFF"
            idx += 1
        elif obj_id == 0x14:  # moisture (uint16, 0.01 %)
            if idx + 2 > n:
                break
            val = struct.unpack_from("<H", data, idx)[0]
            out["moisture"] = round(val * 0.01, 1)
            idx += 2
        elif obj_id == 0x21:  # motion (uint8)
            if idx + 1 > n:
                break
            out["motion"] = int(data[idx])
            idx += 1
        elif obj_id == 0x2E:  # humidity (uint8, 1 %)
            if idx + 1 > n:
                break
            out["humidity"] = int(data[idx])
            idx += 1
        elif obj_id == 0x2F:  # moisture (uint8, 1 %)
            if idx + 1 > n:
                break
            out["moisture"] = int(data[idx])
            idx += 1
        elif obj_id == 0x3A:  # button (uint8)
            if idx + 1 > n:
                break
            out["button"] = int(data[idx])
            idx += 1
        elif obj_id == 0x45:  # temperature (sint16, 0.1 °C)
            if idx + 2 > n:
                break
            val = struct.unpack_from("<h", data, idx)[0]
            out["temperature_C"] = round(val * 0.1, 1)
            idx += 2
        else:
            break
    return out


def parse_atc_pvvx_181a(data: bytes) -> Dict[str, Any]:
    """
    Parses ATC1441 (13 bytes, big-endian) and PVVX custom firmware (15+ bytes, little-endian)
    frames on Service UUID 0x181A (0000181a-0000-1000-8000-00805f9b34fb), as well as
    headerless 7-byte (ATC1441) and 9-byte (PVVX) variants.
    """
    out: Dict[str, Any] = {}
    if len(data) == 13:
        # Format 2: ATC1441 Original (13 bytes in 0x181a)
        # Bytes 0..5: MAC (big-endian), Bytes 6..7: int16 BE (0.1 C), Byte 8: uint8 (%),
        # Byte 9: uint8 (%), Bytes 10..11: uint16 BE (mV), Byte 12: uint8 counter
        temp_raw = struct.unpack_from(">h", data, 6)[0]
        hum = data[8]
        bat_pct = data[9]
        bat_mv = struct.unpack_from(">H", data, 10)[0]
        seq = data[12]
        out["temperature_C"] = round(temp_raw / 10.0, 1)
        out["humidity"] = int(hum)
        out["battery_pct"] = int(bat_pct)
        out["battery_ok"] = 1 if bat_pct > 15 else 0
        out["battery_mV"] = int(bat_mv)
        out["voltage_V"] = round(bat_mv / 1000.0, 3)
        out["sequence"] = int(seq)
    elif len(data) >= 15:
        # Format 1: Custom PVVX (15..19 bytes in 0x181a)
        # Bytes 0..5: MAC (little-endian), Bytes 6..7: int16 LE (0.01 C), Bytes 8..9: uint16 LE (0.01 %),
        # Bytes 10..11: uint16 LE (mV), Byte 12: uint8 (%), Byte 13: uint8 counter, Byte 14: uint8 flags
        temp_raw = struct.unpack_from("<h", data, 6)[0]
        hum_raw = struct.unpack_from("<H", data, 8)[0]
        bat_mv = struct.unpack_from("<H", data, 10)[0]
        bat_pct = data[12]
        seq = data[13]
        flags = data[14]
        out["temperature_C"] = round(temp_raw / 100.0, 2)
        out["humidity"] = round(hum_raw / 100.0, 1)
        out["battery_pct"] = int(bat_pct)
        out["battery_ok"] = 1 if bat_pct > 15 else 0
        out["battery_mV"] = int(bat_mv)
        out["voltage_V"] = round(bat_mv / 1000.0, 3)
        out["sequence"] = int(seq)
        out["flags"] = int(flags)
    elif len(data) == 7:
        temp_raw = struct.unpack_from(">h", data, 0)[0]
        hum = data[2]
        bat_pct = data[3]
        bat_mv = struct.unpack_from(">H", data, 4)[0]
        seq = data[6]
        if -450 <= temp_raw <= 850 and 0 <= hum <= 100 and 0 <= bat_pct <= 100:
            out["temperature_C"] = round(temp_raw / 10.0, 1)
            out["humidity"] = int(hum)
            out["battery_pct"] = int(bat_pct)
            out["battery_ok"] = 1 if bat_pct > 15 else 0
            out["battery_mV"] = int(bat_mv)
            out["voltage_V"] = round(bat_mv / 1000.0, 3)
            out["sequence"] = int(seq)
    elif len(data) in (9, 10):
        temp_raw = struct.unpack_from("<h", data, 0)[0]
        hum_raw = struct.unpack_from("<H", data, 2)[0]
        bat_mv = struct.unpack_from("<H", data, 4)[0]
        bat_pct = data[6]
        seq = data[7]
        if -4500 <= temp_raw <= 8500 and 0 <= hum_raw <= 10000 and 0 <= bat_pct <= 100:
            out["temperature_C"] = round(temp_raw / 100.0, 2)
            out["humidity"] = round(hum_raw / 100.0, 1)
            out["battery_pct"] = int(bat_pct)
            out["battery_ok"] = 1 if bat_pct > 15 else 0
            out["battery_mV"] = int(bat_mv)
            out["voltage_V"] = round(bat_mv / 1000.0, 3)
            out["sequence"] = int(seq)
    return out


def parse_bthome_v1_181c(data: bytes) -> Dict[str, Any]:
    """
    Parses unencrypted BTHome v1 / HA BLE service data (UUID 0x181C).
    """
    out: Dict[str, Any] = {}
    idx = 0
    n = len(data)
    while idx + 2 <= n:
        header = data[idx]
        val_len = header & 0x1F
        if idx + 1 + val_len > n or val_len == 0:
            break
        meas_type = data[idx + 1]
        val_bytes = data[idx + 2 : idx + 1 + val_len]
        idx += 1 + val_len
        if meas_type == 0x00 and len(val_bytes) == 1:
            out["sequence"] = val_bytes[0]
        elif meas_type == 0x01 and len(val_bytes) == 1:
            bat = val_bytes[0]
            out["battery_pct"] = int(bat)
            out["battery_ok"] = 1 if bat > 15 else 0
        elif meas_type == 0x02 and len(val_bytes) == 2:
            val = struct.unpack_from("<h", val_bytes, 0)[0]
            out["temperature_C"] = round(val * 0.01, 2)
        elif meas_type == 0x03 and len(val_bytes) == 2:
            val = struct.unpack_from("<H", val_bytes, 0)[0]
            out["humidity"] = round(val * 0.01, 1)
        elif meas_type == 0x0C and len(val_bytes) == 2:
            val = struct.unpack_from("<H", val_bytes, 0)[0]
            out["battery_mV"] = int(val)
            out["voltage_V"] = round(val * 0.001, 3)
    return out


def parse_xiaomi_fe95(data: bytes) -> Dict[str, Any]:
    """
    Parses unencrypted Xiaomi MiBeacon service data (UUID 0xFE95).
    """
    out: Dict[str, Any] = {}
    if len(data) < 11:
        return out
    frame_ctrl = struct.unpack_from("<H", data, 0)[0]
    is_encrypted = bool(frame_ctrl & 0x0008)
    has_mac = bool(frame_ctrl & 0x0010)
    has_cap = bool(frame_ctrl & 0x0020)
    has_obj = bool(frame_ctrl & 0x0040)
    if is_encrypted or not has_obj:
        return out

    out["sequence"] = data[4]
    offset = 5
    if has_mac:
        offset += 6
    if has_cap:
        offset += 1

    while offset + 3 <= len(data):
        obj_type = struct.unpack_from("<H", data, offset)[0]
        obj_len = data[offset + 2]
        obj_start = offset + 3
        if obj_start + obj_len > len(data):
            break
        obj_bytes = data[obj_start : obj_start + obj_len]
        offset = obj_start + obj_len

        if obj_type == 0x1004 and len(obj_bytes) >= 2:
            t = struct.unpack_from("<h", obj_bytes, 0)[0] / 10.0
            out["temperature_C"] = round(t, 1)
        elif obj_type == 0x1006 and len(obj_bytes) >= 2:
            h = struct.unpack_from("<H", obj_bytes, 0)[0] / 10.0
            out["humidity"] = round(h, 1)
        elif obj_type == 0x100A and len(obj_bytes) >= 1:
            bat = obj_bytes[0]
            out["battery_pct"] = int(bat)
            out["battery_ok"] = 1 if bat > 15 else 0
            if len(obj_bytes) >= 3:
                mv = struct.unpack_from("<H", obj_bytes, 1)[0]
                if 1800 <= mv <= 3600:
                    out["battery_mV"] = int(mv)
                    out["voltage_V"] = round(mv / 1000.0, 3)
        elif obj_type == 0x100D and len(obj_bytes) >= 4:
            t = struct.unpack_from("<h", obj_bytes, 0)[0] / 10.0
            h = struct.unpack_from("<H", obj_bytes, 2)[0] / 10.0
            out["temperature_C"] = round(t, 1)
            out["humidity"] = round(h, 1)
        elif obj_type == 0x1007 and len(obj_bytes) >= 3:
            lux = int.from_bytes(obj_bytes[:3], "little")
            out["lux"] = lux
        elif obj_type == 0x1008 and len(obj_bytes) >= 1:
            out["moisture"] = int(obj_bytes[0])
    return out


def parse_ruuvi_0499(data: bytes) -> Dict[str, Any]:
    """
    Parses RuuviTag Manufacturer Data (Company ID 0x0499, Data Format 5 / RAWv2).
    """
    out: Dict[str, Any] = {}
    if len(data) >= 24 and data[0] == 0x05:
        temp_raw = struct.unpack_from(">h", data, 1)[0]
        hum_raw = struct.unpack_from(">H", data, 3)[0]
        pres_raw = struct.unpack_from(">H", data, 5)[0]
        power_info = struct.unpack_from(">H", data, 13)[0]
        seq = struct.unpack_from(">H", data, 16)[0]

        if temp_raw != -32768:
            out["temperature_C"] = round(temp_raw * 0.005, 2)
        if hum_raw != 65535:
            out["humidity"] = round(hum_raw * 0.0025, 1)
        if pres_raw != 65535:
            out["pressure_hPa"] = round((pres_raw + 50000) / 100.0, 1)

        bat_mv = (power_info >> 5) + 1600
        if 1600 <= bat_mv <= 3646:
            out["battery_mV"] = int(bat_mv)
            out["voltage_V"] = round(bat_mv / 1000.0, 3)
            out["battery_ok"] = 1 if bat_mv >= 2400 else 0
        if seq != 65535:
            out["sequence"] = int(seq)
    return out


def parse_govee_mfg(data: bytes) -> Dict[str, Any]:
    """
    Parses Govee thermo-hygrometer manufacturer data (0xEC88).
    """
    out: Dict[str, Any] = {}
    if len(data) == 6 and data[0] == 0x00:
        raw = int.from_bytes(data[1:4], "big")
        is_neg = bool(raw & 0x800000)
        raw = raw & 0x7FFFFF
        temp_c = (raw / 10000.0) * (-1.0 if is_neg else 1.0)
        hum = (raw % 1000) / 10.0
        bat = data[4]
        if -40.0 <= temp_c <= 85.0 and 0.0 <= hum <= 100.0:
            out["temperature_C"] = round(temp_c, 1)
            out["humidity"] = round(hum, 1)
            if 0 <= bat <= 100:
                out["battery_pct"] = int(bat)
                out["battery_ok"] = 1 if bat > 15 else 0
    elif len(data) >= 7 and data[0] == 0x00:
        temp_raw = struct.unpack_from("<h", data, 1)[0]
        hum_raw = struct.unpack_from("<H", data, 3)[0]
        bat = data[5]
        temp_c = temp_raw / 100.0
        hum = hum_raw / 100.0
        if -40.0 <= temp_c <= 85.0 and 0.0 <= hum <= 100.0:
            out["temperature_C"] = round(temp_c, 1)
            out["humidity"] = round(hum, 1)
            if 0 <= bat <= 100:
                out["battery_pct"] = int(bat)
                out["battery_ok"] = 1 if bat > 15 else 0
    return out


def parse_ibeacon_004c(data: bytes) -> Dict[str, Any]:
    """
    Parses Apple iBeacon frame (Company ID 0x004C, Type 0x02, Length 0x15 = 21 bytes).
    """
    out: Dict[str, Any] = {}
    if len(data) >= 23 and data[0] == 0x02 and data[1] == 0x15:
        uuid_hex = data[2:18].hex().upper()
        beacon_uuid = f"{uuid_hex[0:8]}-{uuid_hex[8:12]}-{uuid_hex[12:16]}-{uuid_hex[16:20]}-{uuid_hex[20:32]}"
        major = struct.unpack_from(">H", data, 18)[0]
        minor = struct.unpack_from(">H", data, 20)[0]
        tx_cal = struct.unpack_from("b", data, 22)[0]
        out["ibeacon_uuid"] = beacon_uuid
        out["major"] = int(major)
        out["minor"] = int(minor)
        out["tx_power"] = int(tx_cal)
        if beacon_uuid in KNOWN_IBEACON_UUIDS:
            out["ibeacon_profile"] = KNOWN_IBEACON_UUIDS[beacon_uuid]
    return out


def _fetch_mac_vendor_sync(mac_or_oui: str) -> Optional[str]:
    """
    Queries api.macvendors.com (with fallback to api.maclookup.app) for the IEEE OUI vendor name.
    """
    clean_oui = str(mac_or_oui or "").strip().upper()[:8]
    if len(clean_oui) < 8:
        return None

    headers = {
        "User-Agent": "SensorScanner/1.0 (BLE IEEE OUI Resolver)",
        "Accept": "text/plain, application/json",
    }
    try:
        req = urllib.request.Request(f"https://api.macvendors.com/{clean_oui}", headers=headers)
        with urllib.request.urlopen(req, timeout=4.0) as resp:
            if resp.status == 200:
                txt = resp.read().decode("utf-8", errors="ignore").strip()
                if txt and "errors" not in txt.lower() and "not found" not in txt.lower() and len(txt) < 120:
                    return txt
    except Exception:
        pass

    try:
        req2 = urllib.request.Request(f"https://api.maclookup.app/v2/macs/{clean_oui}", headers=headers)
        with urllib.request.urlopen(req2, timeout=4.0) as resp2:
            if resp2.status == 200:
                data = json.loads(resp2.read().decode("utf-8", errors="ignore"))
                if isinstance(data, dict) and data.get("found") and data.get("company"):
                    comp = str(data["company"]).strip()
                    if comp:
                        return comp
    except Exception:
        pass

    return BUILTIN_OUI_VENDORS.get(clean_oui)


class BLEManager:
    def __init__(
        self,
        get_settings_fn: Callable[[], Dict[str, str]],
        is_known_aliased_fn: Callable[[str], bool],
        on_signal_fn: Callable[[Dict[str, Any]], Awaitable[None]],
        on_status_change_fn: Callable[[Dict[str, Any]], Awaitable[None]],
        on_log_line_fn: Callable[[str], Awaitable[None]],
        on_beacon_seen_fn: Optional[Callable[[Dict[str, Any]], bool]] = None,
        get_oui_cache_fn: Optional[Callable[[], Dict[str, str]]] = None,
        on_oui_resolved_fn: Optional[Callable[[str, str], Awaitable[None]]] = None,
    ):
        self._get_settings = get_settings_fn
        self._is_known_aliased = is_known_aliased_fn
        self._on_signal = on_signal_fn
        self._on_status_change = on_status_change_fn
        self._on_log_line = on_log_line_fn
        self._on_beacon_seen = on_beacon_seen_fn
        self._get_oui_cache = get_oui_cache_fn
        self._on_oui_resolved = on_oui_resolved_fn

        self._task: Optional[asyncio.Task] = None
        self._stop_event = asyncio.Event()

        self._ble_status: str = "stopped"
        self._last_error: str = ""
        self._received_count: int = 0
        self._debounced_count: int = 0
        self._discovered_devices: Set[str] = set()
        self._debounce_cache: Dict[str, Tuple[float, str]] = {}
        self._beacon_touch_cache: Dict[str, float] = {}
        self._device_state_cache: Dict[str, Dict[str, Any]] = {}
        self._rssi_ema_cache: Dict[str, float] = {}
        self._ble_device_objects: Dict[str, Any] = {}
        self._oui_cache: Dict[str, str] = {}
        self._oui_queried: Set[str] = set()
        self._oui_lock = asyncio.Lock()
        if self._get_oui_cache is not None:
            try:
                loaded = self._get_oui_cache()
                if loaded:
                    self._oui_cache.update({k.upper(): v for k, v in loaded.items() if v})
                    self._oui_queried.update(self._oui_cache.keys())
            except Exception:
                pass
        self._log_tail: Deque[str] = deque(maxlen=100)

    def get_cached_oui_vendor(self, mac: str) -> Optional[str]:
        oui = str(mac or "").strip().upper()[:8]
        if len(oui) < 8:
            return None
        if oui in self._oui_cache:
            return self._oui_cache[oui]
        return BUILTIN_OUI_VENDORS.get(oui)

    async def resolve_oui_vendor(self, mac: str, force_retry: bool = False) -> Optional[str]:
        oui = str(mac or "").strip().upper()[:8]
        if len(oui) < 8 or oui.count(":") != 2:
            return None
        if not force_retry and oui in self._oui_cache:
            return self._oui_cache[oui]
        if not force_retry and oui in self._oui_queried:
            return self._oui_cache.get(oui) or BUILTIN_OUI_VENDORS.get(oui)

        self._oui_queried.add(oui)
        async with self._oui_lock:
            if not force_retry and oui in self._oui_cache:
                return self._oui_cache[oui]
            vendor = await asyncio.to_thread(_fetch_mac_vendor_sync, oui)
            if vendor:
                self._oui_cache[oui] = vendor
                for m_key, st in self._device_state_cache.items():
                    if m_key.startswith(oui):
                        st["mac_vendor"] = vendor
                if self._on_oui_resolved is not None:
                    try:
                        await self._on_oui_resolved(oui, vendor)
                    except Exception as exc:
                        logger.debug("OUI callback error for %s: %s", oui, exc)
            return vendor

    async def inspect_gatt_device(self, mac: str) -> Dict[str, Any]:
        """
        Actively connects to a BLE device over GATT (timeout=8.0s), enumerates all GATT services,
        and reads standard Device Information / Generic Access / Battery characteristics.
        """
        raw_target = str(mac or "").strip()
        if "_" in raw_target and ":" not in raw_target:
            raw_target = raw_target.split("_")[-1]
        clean_hex = re.sub(r"[^0-9A-Fa-f]", "", raw_target).upper()
        if len(clean_hex) == 12:
            mac_norm = ":".join(clean_hex[i : i + 2] for i in range(0, 12, 2))
        else:
            mac_norm = raw_target.upper()

        now_iso = datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
        mac_type = analyze_mac_type(mac_norm)
        mac_vendor: Optional[str] = None
        if mac_type == "IEEE Public (Fast)":
            mac_vendor = await self.resolve_oui_vendor(mac_norm, force_retry=True)

        if not BLEAK_AVAILABLE or BleakClient is None:
            return {
                "ok": False,
                "connectable": False,
                "gatt_connectable": False,
                "mac": mac_norm,
                "mac_vendor": mac_vendor,
                "gatt_services": [],
                "gatt_inspected_at": now_iso,
                "message": "Python-biblioteket 'bleak' är inte tillgängligt i miljön.",
            }

        await self._emit_log(f"GATT Djupinspektion startad mot {mac_norm} (timeout 8.0s)...")
        target_device = self._ble_device_objects.get(mac_norm, mac_norm)

        result: Dict[str, Any] = {
            "ok": True,
            "connectable": False,
            "gatt_connectable": False,
            "mac": mac_norm,
            "gatt_services": [],
            "gatt_inspected_at": now_iso,
        }
        if mac_vendor:
            result["mac_vendor"] = mac_vendor

        try:
            async with BleakClient(target_device, timeout=8.0) as client:
                result["connectable"] = True
                result["gatt_connectable"] = True

                # 1. Force-read standard identity characteristics directly (even if 0x1800/0x180A is hidden by BlueZ)
                forced_char_reads: Dict[str, bytes] = {}
                for char_uuid, field_name in GATT_IDENTITY_CHARS.items():
                    try:
                        raw_val = await client.read_gatt_char(char_uuid)
                        if raw_val is not None and len(raw_val) > 0:
                            raw_b = bytes(raw_val)
                            forced_char_reads[char_uuid.lower()] = raw_b
                            if field_name == "battery_pct":
                                bat_int = int(raw_b[0])
                                if 0 <= bat_int <= 100:
                                    result["battery_pct"] = bat_int
                                    result["battery_ok"] = 1 if bat_int > 15 else 0
                            elif field_name == "gatt_appearance":
                                app_u16 = (
                                    int.from_bytes(raw_b[:2], byteorder="little", signed=False)
                                    if len(raw_b) >= 2
                                    else int(raw_b[0])
                                )
                                result["gatt_appearance"] = app_u16
                            else:
                                txt = _decode_printable_ascii(raw_b)
                                if txt:
                                    result[field_name] = txt
                    except Exception:
                        pass

                # 2. Enumerate all Services and their Characteristics + read all readable values
                gatt_services: List[Dict[str, Any]] = []
                total_chars_count = 0
                seen_char_uuids: Set[str] = set()

                for srv in client.services:
                    s_uuid = str(srv.uuid)
                    s_uuid_lower = s_uuid.lower()
                    s_desc = str(getattr(srv, "description", "") or "").strip()
                    short_u = s_uuid.split("-")[0][-4:].upper() if "-" in s_uuid else s_uuid.upper()
                    if s_uuid_lower in KNOWN_FULL_GATT_SERVICE_UUIDS:
                        s_desc = KNOWN_FULL_GATT_SERVICE_UUIDS[s_uuid_lower]
                    elif s_uuid.upper() in BLE_SERVICE_UUIDS:
                        s_desc = BLE_SERVICE_UUIDS[s_uuid.upper()]
                    elif (not s_desc or s_desc.lower() in ("unknown", "vendor specific")) and short_u in BLE_SERVICE_UUIDS:
                        s_desc = BLE_SERVICE_UUIDS[short_u]

                    chars_list: List[Dict[str, Any]] = []
                    for ch in getattr(srv, "characteristics", []) or []:
                        c_uuid = str(ch.uuid)
                        c_uuid_lower = c_uuid.lower()
                        seen_char_uuids.add(c_uuid_lower)
                        c_short = c_uuid.split("-")[0][-4:].upper() if "-" in c_uuid else c_uuid.upper()
                        c_desc = str(getattr(ch, "description", "") or "").strip()
                        if (not c_desc or c_desc.lower() in ("unknown", "vendor specific")) and c_short in GATT_CHAR_DESCRIPTIONS:
                            c_desc = GATT_CHAR_DESCRIPTIONS[c_short]
                        c_handle = getattr(ch, "handle", None)
                        c_props = [str(p) for p in (getattr(ch, "properties", []) or [])]

                        val_hex: Optional[str] = None
                        val_ascii: Optional[str] = None

                        raw_char_bytes: Optional[bytes] = forced_char_reads.get(c_uuid_lower)
                        if raw_char_bytes is None and any(p.lower() == "read" for p in c_props):
                            try:
                                read_res = await client.read_gatt_char(ch)
                                if read_res is not None:
                                    raw_char_bytes = bytes(read_res)
                            except Exception:
                                try:
                                    read_res = await client.read_gatt_char(c_uuid)
                                    if read_res is not None:
                                        raw_char_bytes = bytes(read_res)
                                except Exception:
                                    raw_char_bytes = None

                        if raw_char_bytes is not None:
                            val_hex = raw_char_bytes.hex()
                            val_ascii = _decode_printable_ascii(raw_char_bytes)
                            if c_uuid_lower in GATT_IDENTITY_CHARS:
                                f_name = GATT_IDENTITY_CHARS[c_uuid_lower]
                                if f_name == "battery_pct" and len(raw_char_bytes) > 0:
                                    b_val = int(raw_char_bytes[0])
                                    if 0 <= b_val <= 100:
                                        result["battery_pct"] = b_val
                                        result["battery_ok"] = 1 if b_val > 15 else 0
                                elif f_name == "gatt_appearance" and len(raw_char_bytes) > 0:
                                    app_u16 = (
                                        int.from_bytes(raw_char_bytes[:2], byteorder="little", signed=False)
                                        if len(raw_char_bytes) >= 2
                                        else int(raw_char_bytes[0])
                                    )
                                    result["gatt_appearance"] = app_u16
                                    if val_ascii is None:
                                        val_ascii = f"0x{app_u16:04X} ({app_u16})"
                                elif val_ascii and not result.get(f_name):
                                    result[f_name] = val_ascii

                        chars_list.append(
                            {
                                "uuid": c_uuid,
                                "description": c_desc or "Characteristic",
                                "handle": c_handle,
                                "properties": c_props,
                                "value_hex": val_hex,
                                "value_ascii": val_ascii,
                            }
                        )
                        total_chars_count += 1

                    gatt_services.append(
                        {
                            "uuid": s_uuid,
                            "description": s_desc or "GATT Service",
                            "characteristics": chars_list,
                        }
                    )

                # If BlueZ hid 0x1800 (Generic Access) from client.services but forced reads succeeded, append it
                hidden_ga_chars: List[Dict[str, Any]] = []
                for ga_uuid, ga_desc in (
                    ("00002a00-0000-1000-8000-00805f9b34fb", "Device Name"),
                    ("00002a01-0000-1000-8000-00805f9b34fb", "Appearance"),
                ):
                    if ga_uuid in forced_char_reads and ga_uuid not in seen_char_uuids:
                        rb = forced_char_reads[ga_uuid]
                        asc = _decode_printable_ascii(rb)
                        if ga_uuid.startswith("00002a01") and asc is None and len(rb) > 0:
                            u16_v = int.from_bytes(rb[:2], byteorder="little", signed=False) if len(rb) >= 2 else int(rb[0])
                            asc = f"0x{u16_v:04X} ({u16_v})"
                        hidden_ga_chars.append(
                            {
                                "uuid": ga_uuid,
                                "description": ga_desc,
                                "handle": None,
                                "properties": ["read"],
                                "value_hex": rb.hex(),
                                "value_ascii": asc,
                            }
                        )
                        total_chars_count += 1

                if hidden_ga_chars:
                    gatt_services.insert(
                        0,
                        {
                            "uuid": "00001800-0000-1000-8000-00805f9b34fb",
                            "description": "Generic Access",
                            "characteristics": hidden_ga_chars,
                        },
                    )

                result["gatt_services"] = gatt_services
                result["services_count"] = len(gatt_services)
                result["chars_count"] = total_chars_count

                cached = self._device_state_cache.setdefault(mac_norm, {})
                for k in (
                    "gatt_name",
                    "gatt_appearance",
                    "gatt_manufacturer",
                    "gatt_model",
                    "gatt_serial",
                    "gatt_firmware",
                    "gatt_hardware",
                    "gatt_software",
                    "battery_pct",
                    "battery_ok",
                    "gatt_services",
                    "services_count",
                    "chars_count",
                    "gatt_connectable",
                    "gatt_inspected_at",
                    "mac_vendor",
                ):
                    if k in result and result[k] is not None:
                        cached[k] = result[k]

                summary_parts = []
                if result.get("gatt_name"):
                    summary_parts.append(f"Namn='{result['gatt_name']}'")
                if result.get("gatt_manufacturer"):
                    summary_parts.append(f"Tillverkare='{result['gatt_manufacturer']}'")
                if result.get("gatt_model"):
                    summary_parts.append(f"Modell='{result['gatt_model']}'")
                if result.get("gatt_firmware"):
                    summary_parts.append(f"FW='{result['gatt_firmware']}'")
                summary_parts.append(f"{len(gatt_services)} tjänster / {total_chars_count} karakteristiker")
                msg = f"GATT-anslutning lyckades ({', '.join(summary_parts)})"
                result["message"] = msg
                await self._emit_log(f"GATT {mac_norm}: {msg}")
                return result

        except Exception as exc:
            non_conn_msg = "Enheten är i passivt beacon-läge (Non-Connectable) och accepterar inte GATT-anslutning"
            result["connectable"] = False
            result["gatt_connectable"] = False
            result["message"] = non_conn_msg
            result["error_detail"] = str(exc)
            cached = self._device_state_cache.setdefault(mac_norm, {})
            cached["gatt_connectable"] = False
            cached["gatt_inspected_at"] = now_iso
            if mac_vendor:
                cached["mac_vendor"] = mac_vendor
            await self._emit_log(f"GATT {mac_norm}: {non_conn_msg} ({exc})")
            return result

    def reset_stats_and_cache(self) -> None:
        self._received_count = 0
        self._debounced_count = 0
        self._discovered_devices.clear()
        self._debounce_cache.clear()
        self._beacon_touch_cache.clear()
        self._device_state_cache.clear()
        self._rssi_ema_cache.clear()

    def evict_device(self, model: str, device_id: str) -> None:
        dev_cache_key = f"{model}:{device_id}"
        self._discovered_devices.discard(dev_cache_key)
        self._debounce_cache.pop(dev_cache_key, None)
        self._beacon_touch_cache.pop(dev_cache_key, None)
        self._rssi_ema_cache.pop(dev_cache_key, None)
        if len(device_id) == 12:
            mac_fmt = ":".join(device_id[i : i + 2] for i in range(0, 12, 2)).upper()
            self._device_state_cache.pop(mac_fmt, None)

    def get_status(self) -> Dict[str, Any]:
        settings = self._get_settings()
        enabled = str(settings.get("ble_enabled", "1")).strip().lower() in ("1", "true", "yes", "on")
        mode = str(settings.get("ble_mode", "smart")).strip().lower()
        if mode not in ("smart", "all"):
            mode = "smart"
        try:
            debounce_sec = float(settings.get("ble_debounce_seconds", "15") or 15.0)
        except (ValueError, TypeError):
            debounce_sec = 15.0

        tesla_vin = str(settings.get("tesla_vin", "") or "").strip().upper()
        tesla_prefix = compute_tesla_ble_prefix(tesla_vin)

        return {
            "enabled": enabled,
            "running": self._ble_status == "scanning",
            "state": self._ble_status if enabled else "disabled",
            "mode": mode,
            "debounce_seconds": debounce_sec,
            "received_count": self._received_count,
            "debounced_count": self._debounced_count,
            "discovered_count": len(self._discovered_devices),
            "last_error": self._last_error,
            "theengs_available": THEENGS_AVAILABLE,
            "tesla_expected_prefix": tesla_prefix,
            "log_tail": list(self._log_tail),
        }

    async def _emit_log(self, msg: str) -> None:
        ts = datetime.now(timezone.utc).astimezone().strftime("%H:%M:%S")
        line = f"[BLE {ts}] {msg}"
        self._log_tail.append(line)
        try:
            await self._on_log_line(line)
        except Exception:
            pass

    async def _set_status(self, status: str, error: str = "") -> None:
        changed = (self._ble_status != status) or (self._last_error != error)
        self._ble_status = status
        self._last_error = error
        if changed:
            try:
                await self._on_status_change(self.get_status())
            except Exception:
                pass

    async def start(self) -> None:
        if self._task and not self._task.done():
            return
        self._stop_event.clear()
        self._task = asyncio.create_task(self._supervisor_loop(), name="ble_supervisor")

    async def stop(self) -> None:
        self._stop_event.set()
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        await self._set_status("stopped", "")

    async def restart(self) -> None:
        logger.info("Restarting BLE scanner manager...")
        await self.stop()
        await self.start()

    async def _supervisor_loop(self) -> None:
        while not self._stop_event.is_set():
            settings = self._get_settings()
            enabled = str(settings.get("ble_enabled", "1")).strip().lower() in ("1", "true", "yes", "on")

            if not enabled:
                await self._set_status("disabled", "")
                try:
                    await asyncio.wait_for(self._stop_event.wait(), timeout=3.0)
                except asyncio.TimeoutError:
                    pass
                continue

            if not BLEAK_AVAILABLE:
                await self._set_status("unavailable", "Python-biblioteket 'bleak' är inte installerat.")
                await self._emit_log("ERROR: 'bleak' saknas i miljön. BLE-scanning kan inte startas.")
                try:
                    await asyncio.wait_for(self._stop_event.wait(), timeout=20.0)
                except asyncio.TimeoutError:
                    pass
                continue

            if os.name != "nt" and not os.path.exists("/run/dbus"):
                err_msg = "D-Bus socket (/run/dbus) saknas i containern. Montera - /run/dbus:/run/dbus:ro."
                await self._set_status("unavailable", err_msg)
                await self._emit_log(f"WARN: {err_msg}")
                try:
                    await asyncio.wait_for(self._stop_event.wait(), timeout=20.0)
                except asyncio.TimeoutError:
                    pass
                continue

            try:
                scanner = BleakScanner(detection_callback=self._on_advertisement)
                await scanner.start()
                await self._set_status("scanning", "")
                await self._emit_log(
                    f"Bluetooth Low Energy (2.4 GHz) aktiv (Läge: {settings.get('ble_mode', 'smart').upper()}, Debounce: {settings.get('ble_debounce_seconds', '15')}s)."
                )

                while not self._stop_event.is_set():
                    cur_settings = self._get_settings()
                    cur_enabled = str(cur_settings.get("ble_enabled", "1")).strip().lower() in (
                        "1",
                        "true",
                        "yes",
                        "on",
                    )
                    if not cur_enabled:
                        break
                    try:
                        await asyncio.wait_for(self._stop_event.wait(), timeout=2.0)
                    except asyncio.TimeoutError:
                        pass

                await scanner.stop()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                err_str = str(exc)
                await self._set_status("unavailable", f"BLE/BlueZ ej tillgänglig: {err_str}")
                await self._emit_log(f"ERROR: Kunde inte starta BLE-scanner via BlueZ/D-Bus: {err_str}")
                try:
                    await asyncio.wait_for(self._stop_event.wait(), timeout=15.0)
                except asyncio.TimeoutError:
                    pass

    def _on_advertisement(self, device: BLEDevice, adv: AdvertisementData) -> None:
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self._process_advertisement(device, adv))
        except Exception as exc:
            logger.debug("BLE callback scheduling error: %s", exc)

    async def _process_advertisement(self, device: BLEDevice, adv: AdvertisementData) -> None:
        settings = self._get_settings()
        ble_mode = str(settings.get("ble_mode", "smart")).strip().lower()
        if ble_mode not in ("smart", "all"):
            ble_mode = "smart"

        try:
            debounce_window = max(1.0, float(settings.get("ble_debounce_seconds", "15") or 15.0))
        except (ValueError, TypeError):
            debounce_window = 15.0

        mac = str(getattr(device, "address", "") or "").upper().strip()
        if not mac:
            return

        self._ble_device_objects[mac] = device
        mac_type = analyze_mac_type(mac)

        rssi = getattr(adv, "rssi", None)
        tx_power = getattr(adv, "tx_power", None)
        mfg_data: Dict[int, bytes] = getattr(adv, "manufacturer_data", {}) or {}
        srv_data: Dict[str, bytes] = getattr(adv, "service_data", {}) or {}
        srv_uuids = list(getattr(adv, "service_uuids", []) or [])

        apple_type: Optional[str] = None
        apple_model: Optional[str] = None
        if 0x004C in mfg_data:
            apple_type, apple_model = decode_apple_continuity(bytes(mfg_data[0x004C]))

        raw_name = getattr(adv, "local_name", None) or getattr(device, "name", None) or ""
        local_name = str(raw_name).strip() if raw_name else ""
        if is_mac_like_name(local_name):
            local_name = ""

        # Filter truncated/garbage 1-2 character names (e.g. "4") on rotating private MACs or Apple Overflow
        if len(local_name) <= 2 and (
            mac_type == "Random Private (Roterande)"
            or apple_type == "iOS Background App (Overflow)"
            or 0x004C in mfg_data
        ):
            local_name = ""

        cached_state = self._device_state_cache.setdefault(mac, {})
        if local_name:
            cached_state["local_name"] = local_name
        elif cached_state.get("local_name"):
            cached_ln = str(cached_state["local_name"])
            if len(cached_ln) <= 2 and (
                mac_type == "Random Private (Roterande)"
                or apple_type == "iOS Background App (Overflow)"
                or 0x004C in mfg_data
            ):
                cached_state.pop("local_name", None)
            else:
                local_name = cached_ln

        now_iso = datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
        payload: Dict[str, Any] = {
            "time": now_iso,
            "freq": 2402.0,
            "mod": "BLE",
            "mac": mac,
            "mac_type": mac_type,
            "rssi": rssi,
        }

        if local_name:
            payload["local_name"] = local_name
        if tx_power is not None:
            payload["tx_power"] = tx_power
        if apple_type:
            payload["apple_type"] = apple_type

        if srv_uuids:
            payload["service_uuids"] = srv_uuids

        ble_service_name = lookup_ble_service_names(srv_uuids, srv_data)
        if ble_service_name:
            payload["ble_service_name"] = ble_service_name

        mfg_hex_map: Dict[str, str] = {}
        primary_company_id: Optional[int] = None
        for comp_id, raw_bytes in mfg_data.items():
            if primary_company_id is None:
                primary_company_id = int(comp_id)
            mfg_hex_map[f"0x{int(comp_id):04X}"] = bytes(raw_bytes).hex().upper()

        if mfg_hex_map:
            payload["manufacturer_data"] = mfg_hex_map
        if primary_company_id is not None:
            payload["manufacturer_id"] = f"0x{primary_company_id:04X}"
            if primary_company_id in BLE_COMPANY_IDS:
                payload["manufacturer_name"] = BLE_COMPANY_IDS[primary_company_id]

        srv_hex_map: Dict[str, str] = {}
        for suuid, sbytes in srv_data.items():
            srv_hex_map[str(suuid)] = bytes(sbytes).hex().upper()
        if srv_hex_map:
            payload["service_data"] = srv_hex_map

        # -------------------------------------------------------------------
        # 1. Decode Sensor Data via TheengsDecoder (if installed) + Built-in Parsers
        # -------------------------------------------------------------------
        has_decoded_sensor = False
        theengs_model: Optional[str] = None

        if THEENGS_AVAILABLE and theengs_decode_ble is not None and (mfg_data or srv_data):
            try:
                t_input: Dict[str, Any] = {"id": mac, "rssi": rssi or -70}
                if local_name:
                    t_input["name"] = local_name
                if primary_company_id is not None:
                    first_bytes = mfg_data[primary_company_id]
                    t_input["manufacturerdata"] = struct.pack("<H", primary_company_id).hex() + bytes(first_bytes).hex()
                if srv_data:
                    first_suuid, first_sbytes = next(iter(srv_data.items()))
                    clean_suuid = first_suuid.split("-")[0][-4:] if "-" in first_suuid else first_suuid
                    t_input["servicedatauuid"] = clean_suuid
                    t_input["servicedata"] = bytes(first_sbytes).hex()

                decoded_str = theengs_decode_ble(json.dumps(t_input))
                if decoded_str:
                    t_out = json.loads(decoded_str)
                    if isinstance(t_out, dict):
                        if "tempc" in t_out:
                            payload["temperature_C"] = round(float(t_out["tempc"]), 2)
                            has_decoded_sensor = True
                        if "hum" in t_out:
                            payload["humidity"] = round(float(t_out["hum"]), 1)
                            has_decoded_sensor = True
                        if "batt" in t_out:
                            bat_val = int(float(t_out["batt"]))
                            payload["battery_pct"] = bat_val
                            payload["battery_ok"] = 1 if bat_val > 15 else 0
                            has_decoded_sensor = True
                        if "volt" in t_out:
                            payload["voltage_V"] = round(float(t_out["volt"]), 3)
                            has_decoded_sensor = True
                        if "pres" in t_out:
                            payload["pressure_hPa"] = round(float(t_out["pres"]), 1)
                            has_decoded_sensor = True
                        if "lux" in t_out:
                            payload["lux"] = round(float(t_out["lux"]), 1)
                            has_decoded_sensor = True
                        if "moi" in t_out:
                            payload["moisture"] = round(float(t_out["moi"]), 1)
                            has_decoded_sensor = True
                        if "open" in t_out:
                            payload["contact_open"] = 1 if t_out["open"] else 0
                            has_decoded_sensor = True
                        if "motion" in t_out:
                            payload["motion"] = 1 if t_out["motion"] else 0
                            has_decoded_sensor = True
                        if t_out.get("model_id"):
                            theengs_model = str(t_out["model_id"]).strip()
            except Exception:
                pass

        # Built-in binary parsers for BTHome v2, BTHome v1, ATC/PVVX 0x181A, Xiaomi 0xFE95, Ruuvi 0x0499, Govee 0xEC88
        for suuid, sbytes in srv_data.items():
            u_low = suuid.lower()
            raw_b = bytes(sbytes)
            if "fcd2" in u_low:
                parsed = parse_bthome_v2(raw_b)
                if parsed:
                    payload.update({k: v for k, v in parsed.items() if k not in payload})
                    has_decoded_sensor = True
                    if not theengs_model:
                        theengs_model = "BTHome-BLE"
            elif "181c" in u_low:
                parsed = parse_bthome_v1_181c(raw_b)
                if parsed:
                    payload.update({k: v for k, v in parsed.items() if k not in payload})
                    has_decoded_sensor = True
                    if not theengs_model:
                        theengs_model = "BTHome-BLE"
            elif "181a" in u_low:
                parsed = parse_atc_pvvx_181a(raw_b)
                if parsed:
                    payload.update({k: v for k, v in parsed.items() if k not in payload})
                    has_decoded_sensor = True
                    if not theengs_model:
                        theengs_model = "ATC-Thermometer"
            elif "fe95" in u_low:
                parsed = parse_xiaomi_fe95(raw_b)
                if parsed:
                    payload.update({k: v for k, v in parsed.items() if k not in payload})
                    has_decoded_sensor = True
                    if not theengs_model:
                        theengs_model = "Xiaomi-MiBeacon"

        if 0x0499 in mfg_data:
            parsed = parse_ruuvi_0499(bytes(mfg_data[0x0499]))
            if parsed:
                payload.update({k: v for k, v in parsed.items() if k not in payload})
                has_decoded_sensor = True
                theengs_model = "RuuviTag-BLE"

        if 0xEC88 in mfg_data:
            parsed = parse_govee_mfg(bytes(mfg_data[0xEC88]))
            if parsed:
                payload.update({k: v for k, v in parsed.items() if k not in payload})
                has_decoded_sensor = True

        if 0x004C in mfg_data:
            parsed = parse_ibeacon_004c(bytes(mfg_data[0x004C]))
            if parsed:
                payload.update({k: v for k, v in parsed.items() if k not in payload})
                has_decoded_sensor = True
                if not theengs_model:
                    theengs_model = "iBeacon-BLE"

        # Merge cached sensor metrics and GATT/OUI identity for this MAC if a split advertisement arrived
        sensor_cache_keys = (
            "temperature_C",
            "humidity",
            "pressure_hPa",
            "battery_pct",
            "battery_ok",
            "battery_mV",
            "voltage_V",
            "lux",
            "moisture",
            "sequence",
            "manufacturer_name",
            "manufacturer_id",
            "mac_vendor",
            "ibeacon_profile",
            "gatt_name",
            "gatt_appearance",
            "gatt_manufacturer",
            "gatt_model",
            "gatt_serial",
            "gatt_firmware",
            "gatt_hardware",
            "gatt_software",
            "gatt_services",
            "services_count",
            "chars_count",
            "gatt_connectable",
            "gatt_inspected_at",
        )
        for sk in sensor_cache_keys:
            if sk in payload and payload[sk] is not None:
                cached_state[sk] = payload[sk]
            elif sk in cached_state and cached_state[sk] is not None:
                payload[sk] = cached_state[sk]
                if sk in ("temperature_C", "humidity", "pressure_hPa", "battery_pct", "lux", "moisture"):
                    has_decoded_sensor = True

        oui_vendor = self.get_cached_oui_vendor(mac)

        # -------------------------------------------------------------------
        # 2. Smart Identification of Specific BLE Device Types & Models
        # -------------------------------------------------------------------
        model = "BLE-Device"
        device_id = mac.replace(":", "")
        name_upper = local_name.upper()
        uuids_lower = [u.lower() for u in srv_uuids]
        srv_data_uuids_lower = [su.lower() for su in srv_data.keys()]

        # A. Tesla Vehicles (^S[0-9a-fA-F]{16}[CDPRFB]$ or Tesla BLE Service UUID 0x1122 / b2d1-43f0)
        is_tesla_name = bool(local_name and TESLA_BEACON_RE.match(local_name))
        is_tesla_uuid = any(
            "00000211-b2d1-43f0-9b88-960cebf8b91e" in u or "00001122-" in u or u in ("1122", "0211")
            for u in uuids_lower
        )
        if is_tesla_name or (is_tesla_uuid and local_name.startswith("S")):
            model = "Tesla-Vehicle-BLE"
            payload["category"] = "Vehicle"
            payload["beacon_hash"] = local_name or device_id
            node_char = ""
            # Use beacon_hash as stable device_id so rotating BLE MACs map to the same Tesla vehicle
            if local_name:
                device_id = local_name
                if len(local_name) >= 18:
                    node_char = local_name[-1].upper()
                    payload["tesla_node"] = TESLA_NODE_NAMES.get(node_char, f"Endpoint ({node_char})")

            expected_prefix = compute_tesla_ble_prefix(settings.get("tesla_vin", ""))
            if expected_prefix and device_id.lower().startswith(expected_prefix.lower()):
                payload["is_own_vehicle"] = True
                payload["vehicle_status"] = "VCSEC • Verifierat VIN"
            else:
                payload["is_own_vehicle"] = False
                payload["vehicle_status"] = f"VCSEC • Inom räckvidd ({node_char})" if node_char else "VCSEC • Inom räckvidd"

            has_decoded_sensor = True

        # B. Zeekr / Geely Vehicles (STRICT: local_name starts with ZeekrVehicle OR Manufacturer ID 0x06FE)
        elif name_upper.startswith("ZEEKRVEHICLE") or 0x06FE in mfg_data:
            model = "Zeekr-Vehicle-BLE"
            payload["category"] = "Vehicle"
            payload["vehicle_status"] = "Digital Key • Inom räckvidd"
            if local_name:
                device_id = local_name
            has_decoded_sensor = True

        # C. Polestar / Volvo / BMW Vehicles (including Volvo ES90, EX30, EX90, EX40, EC40, EX60)
        elif (
            any(name_upper.startswith(p) for p in ("POLESTAR", "VOLVO", "VCC", "BMW"))
            or name_upper in VOLVO_VEHICLE_MODELS
        ):
            if name_upper.startswith("POLESTAR"):
                brand = "Polestar"
            elif name_upper.startswith("BMW"):
                brand = "BMW"
            else:
                brand = "Volvo"
            model = f"{brand}-Vehicle-BLE"
            payload["category"] = "Vehicle"
            payload["vehicle_status"] = "Digital Key • Inom räckvidd"
            if local_name:
                device_id = local_name
            has_decoded_sensor = True

        # D. Enhauto S3XY Devices (S3XY_STRIP_*, ENH_KNOB_*, S3XY_BUTTON_*, COMMANDER_*)
        elif any(
            name_upper.startswith(p)
            for p in ("S3XY_STRIP", "ENH_KNOB", "S3XY_BUTTON", "S3XY_", "ENH_", "COMMANDER_")
        ):
            model = "Enhauto-S3XY"
            payload["category"] = "Vehicle"
            has_decoded_sensor = True

        # E. Xiaomi ATC / PVVX Thermometers (local_name starts with ATC_ or LYWSD, or MAC starts with A4:C1:38)
        elif (
            name_upper.startswith("ATC_")
            or name_upper.startswith("LYWSD")
            or mac.startswith("A4:C1:38")
            or theengs_model == "ATC-Thermometer"
        ):
            model = "ATC-Thermometer"
            payload["category"] = "Climate"

        # F. Govee Devices (ihoment_*, Govee_*, GVH*, B5178*, H5074*, H5075* or Manufacturer 0xEC88)
        elif (
            any(name_upper.startswith(p) for p in ("IHOMENT_", "GOVEE_", "GVH", "H507", "H510", "H517", "B517"))
            or 0xEC88 in mfg_data
        ):
            model = "Govee-BLE"
            if "temperature_C" in payload or "humidity" in payload or name_upper.startswith("GVH"):
                payload["category"] = "Climate"
            else:
                payload["category"] = "Switch"

        # G. Plejd / Bluetooth Mesh (local_name == "P mesh" or Company ID 0x09A3)
        elif local_name.lower() == "p mesh" or 0x09A3 in mfg_data:
            model = "Plejd-Mesh"
            payload["category"] = "Switch"

        # H. Xiaomi / Aqara / BTHome / Qingping / RuuviTag
        elif theengs_model:
            model = theengs_model
            if model in ("iBeacon-BLE", "Apple-AirTag"):
                payload["category"] = "Tracker"
        elif any(
            name_upper.startswith(p)
            for p in ("MIJIA", "QINGPING", "CGD1", "CGG1", "RUUVI", "BTHOME")
        ):
            clean_p = re.sub(r"[^A-Za-z0-9]+", "-", local_name).strip("-").split("-")[0]
            model = f"{clean_p}-BLE"
            payload["category"] = "Climate"

        # I. Apple Continuity Identified Devices (AirPods, AirPlay, AirTag, iBeacon)
        elif apple_model:
            model = apple_model
            if model in ("iBeacon-BLE", "Apple-AirTag"):
                payload["category"] = "Tracker"
            else:
                payload["category"] = "Generic"

        # J. Other Named BLE Devices (e.g. ZAG*, ZAP*, GPN*, zq*, Shelly*, Hue*, etc.)
        elif local_name:
            prefix_match = re.match(r"^([A-Za-z0-9]{2,14})", local_name)
            clean_prefix = prefix_match.group(1) if prefix_match else "Generic"
            model = f"BLE-{clean_prefix}"

        # Determine if this BLE packet carries real sensor telemetry or is a passive raw beacon
        telemetry_keys = (
            "temperature_C",
            "humidity",
            "pressure_hPa",
            "battery_pct",
            "voltage_V",
            "battery_mV",
            "power_W",
            "energy_kWh",
            "current_A",
            "lux",
            "illuminance",
            "moisture",
            "contact_open",
            "motion",
            "button",
            "state",
        )
        has_sensor_measurements = any(payload.get(k) is not None for k in telemetry_keys)
        has_real_telemetry = (
            has_sensor_measurements
            or model in ("Tesla-Vehicle-BLE", "Zeekr-Vehicle-BLE", "Polestar-Vehicle-BLE", "Volvo-Vehicle-BLE", "BMW-Vehicle-BLE")
            or bool(payload.get("vehicle_status"))
        )
        is_beacon_only = not has_real_telemetry
        payload["is_beacon_only"] = is_beacon_only

        # Refine mac_type and compute deterministic payload fingerprint ID for rotating BLE devices
        mac_type = analyze_mac_type(
            mac,
            mac_vendor=oui_vendor,
            is_sensor=has_sensor_measurements or (model in FIXED_MAC_SENSOR_MODELS),
            service_data=payload.get("service_data"),
        )
        payload["mac_type"] = mac_type

        if mac_type == "IEEE Public (Fast)":
            if oui_vendor:
                payload["mac_vendor"] = oui_vendor
                cached_state["mac_vendor"] = oui_vendor
            elif mac[:8] not in self._oui_queried and has_real_telemetry:
                asyncio.create_task(self.resolve_oui_vendor(mac))
        else:
            payload.pop("mac_vendor", None)

        computed_id, fp_source = compute_ble_device_id(
            mac=mac,
            mac_vendor=oui_vendor if mac_type == "IEEE Public (Fast)" else None,
            local_name=local_name,
            service_data=payload.get("service_data"),
            manufacturer_data=payload.get("manufacturer_data"),
            ibeacon_info=payload,
            is_sensor=has_sensor_measurements,
            model=model,
        )
        if computed_id:
            device_id = computed_id
        if fp_source:
            payload["fingerprint_source"] = fp_source
            payload["mac_type"] = "Random Private (Roterande)"
            fp_state = self._device_state_cache.setdefault(f"fp:{model}:{device_id}", {})
            prev_seen_mac = fp_state.get("last_mac")
            if prev_seen_mac and prev_seen_mac != mac:
                fp_state["previous_mac"] = prev_seen_mac
                fp_state["mac_rotations"] = int(fp_state.get("mac_rotations") or 0) + 1
            fp_state["last_mac"] = mac
            if fp_state.get("previous_mac"):
                payload["previous_mac"] = fp_state["previous_mac"]
            if fp_state.get("mac_rotations"):
                payload["mac_rotations"] = fp_state["mac_rotations"]
            # Map BLEDevice object under current MAC and fingerprint key for GATT inspection
            self._ble_device_objects[device_id] = device

        payload["model"] = model
        payload["id"] = device_id

        if model == "iBeacon-BLE" or apple_type == "iBeacon" or "ibeacon_uuid" in payload:
            if not payload.get("manufacturer_name") or payload.get("manufacturer_name") == "Apple":
                payload["manufacturer_name"] = "Apple iBeacon-spec (0x004C)"
            ib_uuid = str(payload.get("ibeacon_uuid") or "").strip().upper()
            if ib_uuid in KNOWN_IBEACON_UUIDS:
                payload["ibeacon_profile"] = KNOWN_IBEACON_UUIDS[ib_uuid]

        # Calculate estimated distance (distance_m) with EMA RSSI smoothing and Log-Distance Path Loss (n = 2.4)
        dev_cache_key = f"{model}:{device_id}"
        if rssi is not None:
            try:
                cur_rssi = float(rssi)
                prev_smoothed = self._rssi_ema_cache.get(dev_cache_key)
                if prev_smoothed is not None:
                    smoothed_rssi = 0.4 * cur_rssi + 0.6 * prev_smoothed
                else:
                    smoothed_rssi = cur_rssi
                self._rssi_ema_cache[dev_cache_key] = smoothed_rssi

                tx_p = payload.get("tx_power")
                if tx_p is not None:
                    tx_f = float(tx_p)
                    if -90.0 <= tx_f <= -30.0:
                        measured_power_1m = tx_f
                    elif tx_f > -30.0:
                        measured_power_1m = tx_f - 62.0
                    else:
                        measured_power_1m = -59.0
                else:
                    measured_power_1m = -59.0

                ratio = (measured_power_1m - smoothed_rssi) / (10.0 * 2.4)
                distance_m = round(10.0 ** ratio, 1)
                payload["distance_m"] = distance_m
                payload["measured_power_1m"] = int(round(measured_power_1m))
            except (ValueError, TypeError):
                pass

        # -------------------------------------------------------------------
        # 3. Smart Mode Filtering (Drop anonymous random MAC spam & passing iPhones in 'smart' mode)
        # -------------------------------------------------------------------
        if ble_mode == "smart":
            is_known = False
            try:
                is_known = self._is_known_aliased(device_id)
            except Exception:
                is_known = False

            if (
                apple_type in ("iOS Background App (Overflow)", "Apple Nearby (iPhone/iPad/Mac)", "Apple Handoff")
                and mac_type == "Random Private (Roterande)"
                and not has_decoded_sensor
                and not is_known
            ):
                return

            if not local_name and not has_decoded_sensor and not is_known:
                return

        # -------------------------------------------------------------------
        # 4. BLE Debounce Filter
        #    - Passive raw beacons (is_beacon_only=True): 5 minutes (300s) state-change
        #      debounce for full signals; silently updates last_seen & rssi in devices table.
        #    - Real telemetry sensors & Tesla-Vehicle-BLE (is_beacon_only=False):
        #      15-30s debounce or immediate update when a measurement value changes.
        # -------------------------------------------------------------------
        now_mono = time.monotonic()
        dev_cache_key = f"{model}:{device_id}"
        metric_sig_parts = [
            f"{k}={payload.get(k)}"
            for k in (
                "temperature_C",
                "humidity",
                "pressure_hPa",
                "battery_pct",
                "voltage_V",
                "lux",
                "moisture",
                "state",
                "contact_open",
                "motion",
                "button",
                "vehicle_status",
            )
            if k in payload
        ]
        metric_sig = "|".join(metric_sig_parts) if metric_sig_parts else (local_name or "beacon")

        prev_entry = self._debounce_cache.get(dev_cache_key)
        if prev_entry is not None:
            prev_ts, prev_sig = prev_entry
            elapsed = now_mono - prev_ts
            prev_was_name_only = "=" not in prev_sig
            cur_has_metrics = bool(metric_sig_parts)

            if is_beacon_only:
                beacon_debounce_window = max(300.0, debounce_window)
                if elapsed < beacon_debounce_window:
                    # Silently update last_seen and rssi in devices table without spamming signals/WebSocket
                    last_touch = self._beacon_touch_cache.get(dev_cache_key, 0.0)
                    if (now_mono - last_touch) >= debounce_window and self._on_beacon_seen is not None:
                        self._beacon_touch_cache[dev_cache_key] = now_mono
                        try:
                            exists_in_db = self._on_beacon_seen(payload)
                            if exists_in_db:
                                self._debounced_count += 1
                                return
                        except Exception:
                            self._debounced_count += 1
                            return
                    else:
                        self._debounced_count += 1
                        return
            else:
                if metric_sig == prev_sig and elapsed < debounce_window:
                    self._debounced_count += 1
                    return
                # Allow immediate update if previous packet had no metrics and current packet decoded sensor metrics
                if not (prev_was_name_only and cur_has_metrics) and metric_sig != prev_sig and elapsed < 1.5:
                    self._debounced_count += 1
                    return

        self._debounce_cache[dev_cache_key] = (now_mono, metric_sig)
        self._beacon_touch_cache[dev_cache_key] = now_mono
        if len(self._debounce_cache) > 4000:
            cutoff = now_mono - max(600.0, debounce_window * 2)
            stale = [k for k, (t, _) in self._debounce_cache.items() if t < cutoff]
            for k in stale:
                self._debounce_cache.pop(k, None)
                self._beacon_touch_cache.pop(k, None)

        self._received_count += 1
        self._discovered_devices.add(dev_cache_key)

        try:
            await self._on_signal(payload)
        except Exception as exc:
            logger.error("Error forwarding BLE signal to pipeline: %s", exc)

