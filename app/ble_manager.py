import asyncio
import json
import logging
import os
import re
import struct
import time
from collections import deque
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Deque, Dict, Optional, Set, Tuple

logger = logging.getLogger("sensor_scanner.ble_manager")

try:
    from bleak import BleakScanner
    from bleak.backends.device import BLEDevice
    from bleak.backends.scanner import AdvertisementData

    BLEAK_AVAILABLE = True
except Exception:
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
    0x0768: "Peloton",
    0x0822: "Shelly / Allterco",
    0x0953: "IKEA of Sweden",
    0x09A3: "Plejd",
    0xEC88: "Govee",
}

TESLA_BEACON_RE = re.compile(r"^S[0-9a-fA-F]{16}[A-Za-z]$")
MAC_LIKE_NAME_RE = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$")


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
    Parses ATC1441 (13 bytes, big-endian) and PVVX custom firmware (15 bytes, little-endian)
    frames on Service UUID 0x181A.
    """
    out: Dict[str, Any] = {}
    if len(data) == 13:
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
        temp_raw = struct.unpack_from("<h", data, 6)[0]
        hum_raw = struct.unpack_from("<H", data, 8)[0]
        bat_mv = struct.unpack_from("<H", data, 10)[0]
        bat_pct = data[12]
        seq = data[13]
        out["temperature_C"] = round(temp_raw / 100.0, 2)
        out["humidity"] = round(hum_raw / 100.0, 1)
        out["battery_pct"] = int(bat_pct)
        out["battery_ok"] = 1 if bat_pct > 15 else 0
        out["battery_mV"] = int(bat_mv)
        out["voltage_V"] = round(bat_mv / 1000.0, 3)
        out["sequence"] = int(seq)
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
    if offset + 3 > len(data):
        return out

    obj_type = struct.unpack_from("<H", data, offset)[0]
    obj_len = data[offset + 2]
    obj_start = offset + 3
    if obj_start + obj_len > len(data):
        return out
    obj_bytes = data[obj_start : obj_start + obj_len]

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
    return out


class BLEManager:
    def __init__(
        self,
        get_settings_fn: Callable[[], Dict[str, str]],
        is_known_aliased_fn: Callable[[str], bool],
        on_signal_fn: Callable[[Dict[str, Any]], Awaitable[None]],
        on_status_change_fn: Callable[[Dict[str, Any]], Awaitable[None]],
        on_log_line_fn: Callable[[str], Awaitable[None]],
    ):
        self._get_settings = get_settings_fn
        self._is_known_aliased = is_known_aliased_fn
        self._on_signal = on_signal_fn
        self._on_status_change = on_status_change_fn
        self._on_log_line = on_log_line_fn

        self._task: Optional[asyncio.Task] = None
        self._stop_event = asyncio.Event()

        self._ble_status: str = "stopped"
        self._last_error: str = ""
        self._received_count: int = 0
        self._debounced_count: int = 0
        self._discovered_devices: Set[str] = set()
        self._debounce_cache: Dict[str, Tuple[float, str]] = {}
        self._log_tail: Deque[str] = deque(maxlen=100)

    def reset_stats_and_cache(self) -> None:
        self._received_count = 0
        self._debounced_count = 0
        self._discovered_devices.clear()
        self._debounce_cache.clear()

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

        raw_name = getattr(adv, "local_name", None) or getattr(device, "name", None) or ""
        local_name = str(raw_name).strip() if raw_name else ""
        if is_mac_like_name(local_name):
            local_name = ""

        rssi = getattr(adv, "rssi", None)
        tx_power = getattr(adv, "tx_power", None)
        mfg_data: Dict[int, bytes] = getattr(adv, "manufacturer_data", {}) or {}
        srv_data: Dict[str, bytes] = getattr(adv, "service_data", {}) or {}
        srv_uuids = list(getattr(adv, "service_uuids", []) or [])

        now_iso = datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
        payload: Dict[str, Any] = {
            "time": now_iso,
            "freq": 2402.0,
            "mod": "BLE",
            "mac": mac,
            "rssi": rssi,
        }

        if local_name:
            payload["local_name"] = local_name
        if tx_power is not None:
            payload["tx_power"] = tx_power
            if rssi is not None:
                try:
                    dist_m = 10.0 ** ((float(tx_power) - float(rssi)) / 24.0)
                    payload["distance_m"] = round(max(0.1, min(dist_m, 99.9)), 1)
                except Exception:
                    pass

        if srv_uuids:
            payload["service_uuids"] = srv_uuids

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

        # Built-in binary parsers for BTHome v2, ATC/PVVX 0x181A, Xiaomi 0xFE95, Ruuvi 0x0499, Govee 0xEC88
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
            elif "181a" in u_low:
                parsed = parse_atc_pvvx_181a(raw_b)
                if parsed:
                    payload.update({k: v for k, v in parsed.items() if k not in payload})
                    has_decoded_sensor = True
                    if not theengs_model:
                        theengs_model = "ATC-Thermo-BLE"
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

        # -------------------------------------------------------------------
        # 2. Smart Identification of Specific BLE Device Types & Models
        # -------------------------------------------------------------------
        model = "BLE-Device"
        device_id = mac.replace(":", "")
        name_upper = local_name.upper()
        uuids_lower = [u.lower() for u in srv_uuids]

        # A. Tesla Vehicles (^S[0-9a-fA-F]{16}[A-Z]$ or Tesla BLE Service UUID 0x1122 / b2d1-43f0)
        is_tesla_name = bool(local_name and TESLA_BEACON_RE.match(local_name))
        is_tesla_uuid = any("00000211-b2d1-43f0-9b88-960cebf8b91e" in u or "00001122-" in u for u in uuids_lower)
        if is_tesla_name or (is_tesla_uuid and local_name.startswith("S")):
            model = "Tesla-Vehicle-BLE"
            payload["category"] = "Vehicle"
            payload["vehicle_status"] = "Närvarande (BLE Beacon)"
            payload["beacon_hash"] = local_name or device_id
            # Use beacon_hash as stable device_id so rotating BLE MACs map to the same Tesla vehicle
            if local_name:
                device_id = local_name
            has_decoded_sensor = True

        # B. Enhauto S3XY Devices (S3XY_STRIP_*, ENH_KNOB_*, S3XY_BUTTON_*, COMMANDER_*)
        elif any(
            name_upper.startswith(p)
            for p in ("S3XY_STRIP", "ENH_KNOB", "S3XY_BUTTON", "S3XY_", "ENH_", "COMMANDER_")
        ):
            model = "Enhauto-S3XY"
            payload["category"] = "Vehicle"
            has_decoded_sensor = True

        # C. Govee Devices (ihoment_*, Govee_*, GVH*, B5178*, H5074*, H5075* or Manufacturer 0xEC88)
        elif (
            any(name_upper.startswith(p) for p in ("IHOMENT_", "GOVEE_", "GVH", "H507", "H510", "H517", "B517"))
            or 0xEC88 in mfg_data
        ):
            model = "Govee-BLE"
            if "temperature_C" in payload or "humidity" in payload or name_upper.startswith("GVH"):
                payload["category"] = "Weather"
            else:
                payload["category"] = "Switch"

        # D. Plejd / Bluetooth Mesh (local_name == "P mesh" or Company ID 0x09A3)
        elif local_name.lower() == "p mesh" or 0x09A3 in mfg_data:
            model = "Plejd-Mesh"
            payload["category"] = "Switch"

        # E. Xiaomi / Aqara / BTHome / Qingping / RuuviTag
        elif theengs_model:
            model = theengs_model
        elif any(
            name_upper.startswith(p)
            for p in ("LYWSD", "ATC_", "MIJIA", "QINGPING", "CGD1", "CGG1", "RUUVI", "BTHOME")
        ):
            clean_p = re.sub(r"[^A-Za-z0-9]+", "-", local_name).strip("-").split("-")[0]
            model = f"{clean_p}-BLE"
            payload["category"] = "Weather"

        # F. Other Named BLE Devices (e.g. ZAG*, ZAP*, GPN*, zq*, Shelly*, Hue*, etc.)
        elif local_name:
            prefix_match = re.match(r"^([A-Za-z0-9]{2,14})", local_name)
            clean_prefix = prefix_match.group(1) if prefix_match else "Generic"
            model = f"BLE-{clean_prefix}"

        payload["model"] = model
        payload["id"] = device_id

        # -------------------------------------------------------------------
        # 3. Smart Mode Filtering (Drop anonymous random MAC spam in 'smart' mode)
        # -------------------------------------------------------------------
        if ble_mode == "smart":
            is_known = False
            try:
                is_known = self._is_known_aliased(device_id)
            except Exception:
                is_known = False

            if not local_name and not has_decoded_sensor and not is_known:
                return

        # -------------------------------------------------------------------
        # 4. BLE Debounce Filter (Default 15s unless sensor metrics changed)
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
            if metric_sig == prev_sig and elapsed < debounce_window:
                self._debounced_count += 1
                return
            if metric_sig != prev_sig and elapsed < 1.5:
                self._debounced_count += 1
                return

        self._debounce_cache[dev_cache_key] = (now_mono, metric_sig)
        if len(self._debounce_cache) > 4000:
            cutoff = now_mono - max(120.0, debounce_window * 2)
            stale = [k for k, (t, _) in self._debounce_cache.items() if t < cutoff]
            for k in stale:
                self._debounce_cache.pop(k, None)

        self._received_count += 1
        self._discovered_devices.add(dev_cache_key)

        try:
            await self._on_signal(payload)
        except Exception as exc:
            logger.error("Error forwarding BLE signal to pipeline: %s", exc)

