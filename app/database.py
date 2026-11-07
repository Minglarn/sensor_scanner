import hashlib
import json
import logging
import os
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("sensor_scanner.database")

DB_PATH = os.environ.get("DB_PATH", "/app/data/sensor_scanner.db")
TESLA_VERIFIED_ALIAS = "Min Tesla (VIN-verifierad)"


def compute_tesla_ble_prefix(tesla_vin: Optional[str]) -> str:
    vin_clean = (tesla_vin or "").strip().upper()
    if len(vin_clean) < 5:
        return ""
    vin_hash = hashlib.sha1(vin_clean.encode("utf-8")).hexdigest()[:16].lower()
    return f"S{vin_hash}"


def _parse_bool_env(val: str, default: str = "0") -> str:
    v = (val or "").strip().lower()
    if v in ("1", "true", "yes", "on"):
        return "1"
    if v in ("0", "false", "no", "off"):
        return "0"
    return default


def get_default_settings() -> Dict[str, str]:
    ble_mode_env = (os.environ.get("BLE_MODE", "smart") or "smart").strip().lower()
    if ble_mode_env not in ("smart", "all"):
        ble_mode_env = "smart"
    return {
        "device_index": os.environ.get("DEVICE_INDEX", "0"),
        "mode": os.environ.get("DEFAULT_MODE", "hop"),
        "custom_freqs": os.environ.get("CUSTOM_FREQS", "433.92M,868.3M"),
        "custom_sample_rate": os.environ.get("CUSTOM_SAMPLE_RATE", "1024k"),
        "hop_interval": os.environ.get("HOP_INTERVAL", "60"),
        "gain": os.environ.get("RTL_GAIN", "auto"),
        "ppm": os.environ.get("RTL_PPM", "0"),
        "debounce_seconds": os.environ.get("DEBOUNCE_SECONDS", "2.0"),
        "ble_enabled": _parse_bool_env(os.environ.get("BLE_ENABLED", "true"), "1"),
        "ble_mode": ble_mode_env,
        "ble_debounce_seconds": os.environ.get("BLE_DEBOUNCE_SECONDS", "15") or "15",
        "tesla_vin": (os.environ.get("TESLA_VIN", "") or "").strip().upper(),
        "retention_days": os.environ.get("RETENTION_DAYS", "30"),
        "mqtt_enabled": _parse_bool_env(os.environ.get("MQTT_ENABLED", "1"), "1"),
        "mqtt_host": os.environ.get("MQTT_HOST", "192.168.1.121"),
        "mqtt_port": os.environ.get("MQTT_PORT", "1883"),
        "mqtt_user": os.environ.get("MQTT_USER", ""),
        "mqtt_pass": os.environ.get("MQTT_PASS", ""),
        "mqtt_prefix": os.environ.get("MQTT_PREFIX", "sensor_scanner"),
        "ha_discovery_enabled": _parse_bool_env(os.environ.get("HA_DISCOVERY_ENABLED", "false"), "0"),
        "ha_discovery_prefix": os.environ.get("HA_DISCOVERY_PREFIX", "homeassistant") or "homeassistant",
    }


def enrich_sparsnas_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    If payload is from Ikea-Sparsnas (or contains 'effect' > 0 with pulses_per_kwh),
    computes 'calculated_power_W' and adds it to the payload.
    """
    model_lower = str(payload.get("model") or "").lower()
    effect = payload.get("effect")
    if effect is not None and ("sparsnas" in model_lower or "pulses_per_kwh" in payload or "cumulative_kwh" in payload):
        try:
            eff_num = float(effect)
            if eff_num > 0:
                ppk = float(payload.get("pulses_per_kwh") or 1000.0)
                if ppk <= 0:
                    ppk = 1000.0
                watts = round((3600000.0 / ppk) * 1024.0 / eff_num)
                payload["calculated_power_W"] = int(watts)
        except (ValueError, TypeError, ZeroDivisionError):
            pass
    return payload


def infer_category(model: str, payload: Dict[str, Any]) -> str:
    explicit_cat = str(payload.get("category") or "").strip()
    if explicit_cat and explicit_cat not in ("Sensor", "Unknown"):
        return explicit_cat

    model_lower = (model or "").lower()
    keys = {k.lower() for k in payload.keys()}
    ptype = str(payload.get("type") or "").strip().upper()

    if (
        "vehicle_status" in keys
        or "beacon_hash" in keys
        or any(w in model_lower for w in ("tesla", "zeekr", "polestar", "volvo", "bmw", "s3xy", "enhauto", "vehicle"))
    ):
        return "Vehicle"

    if (
        ptype == "TPMS"
        or "tpms" in model_lower
        or any(k in keys for k in ("pressure_psi", "pressure_kpa", "pressure_bar", "wheel"))
    ):
        return "TPMS"

    if any(
        k in keys
        for k in (
            "cumulative_kwh",
            "energy_kwh",
            "total_kwh",
            "energy_mwh",
            "power_w",
            "power_kw",
            "calculated_power_w",
            "effect",
            "pulses",
            "pulse_count",
            "volume_m3",
            "water",
            "consumption",
            "current_a",
            "voltage_v",
        )
    ) or any(w in model_lower for w in ("sparsnas", "efergy", "owl", "cm180", "wmbus", "meter", "energy", "water", "emon", "gas")):
        return "Meter"

    if (
        any(
            k in keys
            for k in (
                "temperature_c",
                "temperature_f",
                "temp_c",
                "temperature_1_c",
                "temperature_2_c",
                "temperature_1_f",
                "temperature_2_f",
                "humidity",
                "humidity_1",
                "humidity_2",
                "moisture",
                "wind_avg_km_h",
                "wind_max_km_h",
                "wind_avg_m_s",
                "wind_max_m_s",
                "wind_speed_m_s",
                "wind_speed_km_h",
                "wind_dir_deg",
                "rain_mm",
                "total_rain_mm",
                "rain_in",
                "rain_rate_mm_h",
                "rain_rate_in_h",
                "pressure_hpa",
            )
        )
        or any(k.startswith("temperature_") or k.startswith("humidity_") for k in keys)
        or any(w in model_lower for w in ("wgr800", "pcr800", "ft0385", "weather", "wind", "rain", "therm"))
    ):
        return "Weather"

    if any(k in keys for k in ("motion", "contact_open")) or any(
        w in model_lower for w in ("smoke", "pir", "motion", "alarm", "security", "door", "contact", "dsc", "honeywell")
    ):
        return "Security"

    if any(k in keys for k in ("state", "cmd", "button", "switch", "unit", "group")) or any(
        w in model_lower for w in ("switch", "remote", "nexa", "proove", "intertechno", "kaku", "chuango", "kerui")
    ):
        return "Switch"

    return "Sensor"


def extract_device_id(payload: Dict[str, Any]) -> str:
    for key in ("id", "device", "sensor_id", "node_id", "address", "house_code", "code"):
        val = payload.get(key)
        if val is not None and str(val).strip() != "":
            return str(val).strip()
    channel = payload.get("channel")
    if channel is not None:
        return f"ch{channel}"
    return "unknown"


def extract_temperature_c(payload: Dict[str, Any]) -> Optional[float]:
    for c_key in ("temperature_C", "temp_C", "temperature_1_C", "temperature_2_C"):
        if c_key in payload and payload[c_key] is not None:
            try:
                return round(float(payload[c_key]), 2)
            except (ValueError, TypeError):
                pass
    for f_key in ("temperature_F", "temp_F", "temperature_1_F", "temperature_2_F"):
        if f_key in payload and payload[f_key] is not None:
            try:
                f_val = float(payload[f_key])
                return round((f_val - 32.0) * 5.0 / 9.0, 2)
            except (ValueError, TypeError):
                pass
    for k, val in payload.items():
        if val is None:
            continue
        kl = str(k).lower()
        if "temp" in kl and kl.endswith("_c"):
            try:
                return round(float(val), 2)
            except (ValueError, TypeError):
                pass
        if "temp" in kl and kl.endswith("_f"):
            try:
                f_val = float(val)
                return round((f_val - 32.0) * 5.0 / 9.0, 2)
            except (ValueError, TypeError):
                pass
    return None


def extract_freq_mhz(payload: Dict[str, Any]) -> Optional[float]:
    for key in ("freq", "freq1", "freq2"):
        val = payload.get(key)
        if val is not None:
            try:
                num = float(val)
                if num > 1_000_000:
                    return round(num / 1_000_000.0, 3)
                return round(num, 3)
            except (ValueError, TypeError):
                pass
    return None


def sanitize_key(text: str) -> str:
    cleaned = []
    for ch in str(text):
        if ch.isalnum() or ch in ("-", "_"):
            cleaned.append(ch)
        else:
            cleaned.append("_")
    res = "".join(cleaned).strip("_")
    return res or "unknown"


def _is_older_than_15_min(ts_str: Any) -> bool:
    if not ts_str:
        return False
    try:
        clean = str(ts_str).strip()
        dt = datetime.fromisoformat(clean.replace("Z", "+00:00"))
        now = datetime.now(timezone.utc).astimezone()
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=now.tzinfo)
        return (now - dt).total_seconds() > 900.0
    except Exception:
        return False


class Database:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        db_dir = os.path.dirname(os.path.abspath(self.db_path))
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)
        self._lock = threading.RLock()
        self._init_db()
        self.expire_new_devices()

    def expire_new_devices(self) -> int:
        """
        Clears is_new = 0 for any device that has hit_count > 5, has an alias/group,
        or whose first_seen is older than 15 minutes.
        """
        with self._lock:
            conn = self._get_conn()
            try:
                with conn:
                    cur = conn.execute(
                        """
                        UPDATE devices
                        SET is_new = 0
                        WHERE is_new = 1
                          AND (
                              hit_count > 5
                              OR (alias IS NOT NULL AND alias != '')
                              OR (group_name IS NOT NULL AND group_name != '')
                              OR ignored = 1
                              OR first_seen < datetime('now', '-15 minutes')
                              OR datetime(first_seen) < datetime('now', '-15 minutes')
                          );
                        """
                    )
                    changed = cur.rowcount if cur.rowcount and cur.rowcount > 0 else 0
                    rows = conn.execute(
                        "SELECT device_key, first_seen FROM devices WHERE is_new = 1;"
                    ).fetchall()
                    expired_keys = [
                        r["device_key"] for r in rows if _is_older_than_15_min(r["first_seen"])
                    ]
                    if expired_keys:
                        placeholders = ",".join("?" for _ in expired_keys)
                        cur2 = conn.execute(
                            f"UPDATE devices SET is_new = 0 WHERE device_key IN ({placeholders});",
                            expired_keys,
                        )
                        if cur2.rowcount and cur2.rowcount > 0:
                            changed += cur2.rowcount
                    return changed
            finally:
                conn.close()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=30.0, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        return conn

    def _init_db(self) -> None:
        with self._lock:
            conn = self._get_conn()
            try:
                with conn:
                    conn.execute(
                        """
                        CREATE TABLE IF NOT EXISTS signals (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            timestamp TEXT NOT NULL,
                            model TEXT NOT NULL,
                            device_id TEXT NOT NULL,
                            channel TEXT,
                            freq REAL,
                            rssi REAL,
                            snr REAL,
                            noise REAL,
                            battery_ok INTEGER,
                            temperature_c REAL,
                            humidity REAL,
                            payload TEXT NOT NULL
                        );
                        """
                    )
                    conn.execute("CREATE INDEX IF NOT EXISTS idx_signals_timestamp ON signals(timestamp DESC);")
                    conn.execute("CREATE INDEX IF NOT EXISTS idx_signals_model ON signals(model);")
                    conn.execute("CREATE INDEX IF NOT EXISTS idx_signals_device_id ON signals(device_id);")

                    conn.execute(
                        """
                        CREATE TABLE IF NOT EXISTS devices (
                            device_key TEXT PRIMARY KEY,
                            model TEXT NOT NULL,
                            device_id TEXT NOT NULL,
                            alias TEXT DEFAULT '',
                            group_name TEXT DEFAULT '',
                            category TEXT DEFAULT 'Sensor',
                            mqtt_enabled INTEGER DEFAULT 1,
                            ha_discovery INTEGER DEFAULT 0,
                            ignored INTEGER DEFAULT 0,
                            is_new INTEGER DEFAULT 1,
                            first_seen TEXT NOT NULL,
                            last_seen TEXT NOT NULL,
                            hit_count INTEGER DEFAULT 1,
                            last_payload TEXT NOT NULL
                        );
                        """
                    )
                    conn.execute("CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen DESC);")
                    conn.execute("CREATE INDEX IF NOT EXISTS idx_devices_model_id ON devices(model, device_id);")

                    # Schema migrations for existing SQLite databases
                    try:
                        conn.execute("ALTER TABLE devices ADD COLUMN ha_discovery INTEGER DEFAULT 0;")
                    except Exception:
                        pass
                    try:
                        conn.execute("ALTER TABLE devices ADD COLUMN group_name TEXT DEFAULT '';")
                    except Exception:
                        pass
                    try:
                        conn.execute("ALTER TABLE devices ADD COLUMN is_new INTEGER DEFAULT 1;")
                    except Exception:
                        pass

                    # Always run NY-badge cleanup at startup so old/established devices never stay marked as NY
                    conn.execute(
                        """
                        UPDATE devices
                        SET is_new = 0
                        WHERE hit_count > 5
                           OR (alias IS NOT NULL AND alias != '')
                           OR (group_name IS NOT NULL AND group_name != '')
                           OR ignored = 1
                           OR first_seen < datetime('now', '-15 minutes')
                           OR datetime(first_seen) < datetime('now', '-15 minutes');
                        """
                    )

                    conn.execute(
                        """
                        CREATE TABLE IF NOT EXISTS settings (
                            key TEXT PRIMARY KEY,
                            value TEXT NOT NULL
                        );
                        """
                    )

                    defaults = get_default_settings()
                    for k, v in defaults.items():
                        conn.execute(
                            "INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?);",
                            (k, str(v)),
                        )

                    # Explicit category upgrades for IKEA Sparsnäs and Oregon rain/weather sensors
                    conn.execute(
                        "UPDATE devices SET category = 'Meter' WHERE model LIKE '%Sparsnas%' OR last_payload LIKE '%cumulative_kwh%';"
                    )
                    conn.execute(
                        "UPDATE devices SET category = 'Weather' WHERE model LIKE '%Oregon-PCR%' OR last_payload LIKE '%rain%';"
                    )

                    # Migrate any legacy ATC-BLE / ATC-Thermo-BLE devices to ATC-Thermometer (Weather)
                    atc_rows = conn.execute(
                        "SELECT device_key, device_id FROM devices WHERE model IN ('ATC-BLE', 'ATC-Thermo-BLE');"
                    ).fetchall()
                    for ar in atc_rows:
                        old_key = ar["device_key"]
                        dev_id = ar["device_id"]
                        new_key = f"ATC-Thermometer_{dev_id}"
                        exists_new = conn.execute(
                            "SELECT 1 FROM devices WHERE device_key = ?;", (new_key,)
                        ).fetchone()
                        if exists_new:
                            conn.execute("DELETE FROM devices WHERE device_key = ?;", (old_key,))
                        else:
                            conn.execute(
                                "UPDATE devices SET device_key = ?, model = 'ATC-Thermometer', category = 'Weather' WHERE device_key = ?;",
                                (new_key, old_key),
                            )
                    conn.execute(
                        "UPDATE signals SET model = 'ATC-Thermometer' WHERE model IN ('ATC-BLE', 'ATC-Thermo-BLE');"
                    )

                    # Remove any noise/truncated BLE devices named "4" (or 1-char local_name) without user alias
                    conn.execute(
                        "DELETE FROM devices WHERE model = 'BLE-4' AND (alias IS NULL OR alias = '');"
                    )
                    conn.execute(
                        "DELETE FROM signals WHERE model = 'BLE-4';"
                    )

                    # Remove false-positive Zeekr-Vehicle-BLE entries (e.g. CCC3) where device_id does not start with ZeekrVehicle and manufacturer_id is not 0x06FE
                    conn.execute(
                        """
                        DELETE FROM devices
                        WHERE model = 'Zeekr-Vehicle-BLE'
                          AND UPPER(device_id) NOT LIKE 'ZEEKRVEHICLE%'
                          AND last_payload NOT LIKE '%0x06FE%';
                        """
                    )
                    conn.execute(
                        """
                        DELETE FROM signals
                        WHERE model = 'Zeekr-Vehicle-BLE'
                          AND UPPER(device_id) NOT LIKE 'ZEEKRVEHICLE%'
                          AND payload NOT LIKE '%0x06FE%';
                        """
                    )

                    # Auto-categorize existing devices that still have generic 'Sensor' or 'Unknown' category
                    existing_Rows = conn.execute(
                        "SELECT device_key, model, category, last_payload FROM devices;"
                    ).fetchall()
                    for r in existing_Rows:
                        try:
                            pl = json.loads(r["last_payload"] or "{}")
                        except Exception:
                            pl = {}
                        enriched_pl = enrich_sparsnas_payload(dict(pl))
                        if r["model"] in ("Zeekr-Vehicle-BLE", "Polestar-Vehicle-BLE", "Volvo-Vehicle-BLE", "BMW-Vehicle-BLE"):
                            enriched_pl["vehicle_status"] = "Digital Key • Inom räckvidd"
                        new_cat = infer_category(r["model"], enriched_pl)
                        cur_cat = r["category"] or "Sensor"
                        new_pl_json = json.dumps(enriched_pl, ensure_ascii=False)
                        if (cur_cat in ("Sensor", "Unknown", "") and new_cat != "Sensor") or new_pl_json != r["last_payload"]:
                            conn.execute(
                                "UPDATE devices SET category = ?, last_payload = ? WHERE device_key = ?;",
                                (new_cat if cur_cat in ("Sensor", "Unknown", "") else cur_cat, new_pl_json, r["device_key"]),
                            )
            finally:
                conn.close()
        self.apply_tesla_vin_matching()

    def apply_tesla_vin_matching(self, tesla_vin: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Matches existing Tesla-Vehicle-BLE devices in SQLite against the configured Tesla VIN
        (SHA-1 prefix 'S' + 16 hex chars). Automatically sets alias = 'Min Tesla (VIN-verifierad)'
        if the device has no custom alias, and updates 'is_own_vehicle' in last_payload.
        """
        with self._lock:
            if tesla_vin is None:
                settings = self.get_settings()
                tesla_vin = settings.get("tesla_vin", "")
            expected_prefix = compute_tesla_ble_prefix(tesla_vin)
            updated_list: List[Dict[str, Any]] = []

            conn = self._get_conn()
            try:
                with conn:
                    rows = conn.execute(
                        "SELECT * FROM devices WHERE model = 'Tesla-Vehicle-BLE';"
                    ).fetchall()
                    for row in rows:
                        dev_key = row["device_key"]
                        dev_id = str(row["device_id"] or "")
                        cur_alias = str(row["alias"] or "").strip()
                        try:
                            pl = json.loads(row["last_payload"] or "{}")
                        except Exception:
                            pl = {}

                        b_hash = str(pl.get("beacon_hash") or pl.get("local_name") or dev_id)
                        node_char = b_hash[-1].upper() if len(b_hash) >= 18 else ""
                        is_match = bool(
                            expected_prefix
                            and (
                                dev_id.lower().startswith(expected_prefix.lower())
                                or b_hash.lower().startswith(expected_prefix.lower())
                            )
                        )
                        pl["is_own_vehicle"] = is_match
                        pl["vehicle_status"] = (
                            "VCSEC • Verifierat VIN"
                            if is_match
                            else (f"VCSEC • Inom räckvidd ({node_char})" if node_char else "VCSEC • Inom räckvidd")
                        )

                        new_alias = cur_alias
                        new_is_new = int(row["is_new"] or 0)
                        if is_match:
                            if not cur_alias:
                                new_alias = TESLA_VERIFIED_ALIAS
                            new_is_new = 0
                        else:
                            if cur_alias == TESLA_VERIFIED_ALIAS:
                                new_alias = ""

                        new_pl_str = json.dumps(pl, ensure_ascii=False)
                        if new_alias != cur_alias or new_pl_str != row["last_payload"] or new_is_new != int(row["is_new"] or 0):
                            conn.execute(
                                """
                                UPDATE devices
                                SET alias = ?, is_new = ?, category = 'Vehicle', last_payload = ?
                                WHERE device_key = ?;
                                """,
                                (new_alias, new_is_new, new_pl_str, dev_key),
                            )
                            conn.execute(
                                "UPDATE signals SET payload = ? WHERE model = 'Tesla-Vehicle-BLE' AND device_id = ?;",
                                (new_pl_str, dev_id),
                            )
                            u_row = conn.execute(
                                "SELECT * FROM devices WHERE device_key = ?;", (dev_key,)
                            ).fetchone()
                            if u_row:
                                d_dict = dict(u_row)
                                d_dict["last_payload"] = pl
                                updated_list.append(d_dict)
                return updated_list
            finally:
                conn.close()

    def get_settings(self) -> Dict[str, str]:
        with self._lock:
            conn = self._get_conn()
            try:
                rows = conn.execute("SELECT key, value FROM settings;").fetchall()
                result = get_default_settings()
                for row in rows:
                    result[row["key"]] = row["value"]
                return result
            finally:
                conn.close()

    def update_settings(self, updates: Dict[str, Any]) -> Dict[str, str]:
        with self._lock:
            conn = self._get_conn()
            try:
                with conn:
                    for k, v in updates.items():
                        if v is None:
                            continue
                        conn.execute(
                            """
                            INSERT INTO settings (key, value) VALUES (?, ?)
                            ON CONFLICT(key) DO UPDATE SET value = excluded.value;
                            """,
                            (str(k), str(v)),
                        )
            finally:
                conn.close()
        return self.get_settings()

    def record_signal(self, payload: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], Dict[str, Any]]:
        """
        Records a signal and updates the device registry.
        Returns (signal_record_or_None_if_ignored, device_record).
        """
        enrich_sparsnas_payload(payload)

        now_iso = datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
        timestamp = str(payload.get("time") or now_iso)
        model = str(payload.get("model") or "Unknown").strip()
        device_id = extract_device_id(payload)
        device_key = f"{sanitize_key(model)}_{sanitize_key(device_id)}"

        channel = str(payload.get("channel")) if payload.get("channel") is not None else None
        freq = extract_freq_mhz(payload)

        def _to_float(val: Any) -> Optional[float]:
            if val is None:
                return None
            try:
                return round(float(val), 2)
            except (ValueError, TypeError):
                return None

        def _to_int(val: Any) -> Optional[int]:
            if val is None:
                return None
            try:
                return int(val)
            except (ValueError, TypeError):
                return None

        rssi = _to_float(payload.get("rssi"))
        snr = _to_float(payload.get("snr"))
        noise = _to_float(payload.get("noise"))
        battery_ok = _to_int(payload.get("battery_ok"))
        temperature_c = extract_temperature_c(payload)
        humidity = _to_float(payload.get("humidity"))
        raw_json = json.dumps(payload, ensure_ascii=False)
        inferred_cat = infer_category(model, payload)

        with self._lock:
            conn = self._get_conn()
            try:
                with conn:
                    existing_dev = conn.execute(
                        "SELECT * FROM devices WHERE device_key = ?;", (device_key,)
                    ).fetchone()

                    auto_alias = ""
                    if model == "Tesla-Vehicle-BLE" and payload.get("is_own_vehicle") is True:
                        auto_alias = TESLA_VERIFIED_ALIAS

                    is_brand_new = existing_dev is None
                    if is_brand_new:
                        init_is_new = 0 if auto_alias else 1
                        conn.execute(
                            """
                            INSERT INTO devices (
                                device_key, model, device_id, alias, group_name, category,
                                mqtt_enabled, ha_discovery, ignored, is_new, first_seen, last_seen, hit_count, last_payload
                            ) VALUES (?, ?, ?, ?, '', ?, 1, 0, 0, ?, ?, ?, 1, ?);
                            """,
                            (device_key, model, device_id, auto_alias, inferred_cat, init_is_new, timestamp, timestamp, raw_json),
                        )
                    else:
                        cur_cat = existing_dev["category"] or "Sensor"
                        updated_cat = inferred_cat if cur_cat in ("Sensor", "Unknown", "") and inferred_cat != "Sensor" else cur_cat
                        next_hits = int(existing_dev["hit_count"] or 0) + 1
                        cur_is_new = int(existing_dev["is_new"] or 0)
                        cur_alias = str(existing_dev["alias"] or "").strip()
                        updated_alias = cur_alias or auto_alias
                        has_alias = bool(updated_alias)
                        has_group = bool(existing_dev["group_name"] and str(existing_dev["group_name"]).strip())
                        if (
                            cur_is_new == 0
                            or next_hits > 5
                            or has_alias
                            or has_group
                            or int(existing_dev["ignored"] or 0) == 1
                            or _is_older_than_15_min(existing_dev["first_seen"])
                        ):
                            next_is_new = 0
                        else:
                            next_is_new = 1

                        conn.execute(
                            """
                            UPDATE devices
                            SET alias = ?,
                                category = ?,
                                last_seen = ?,
                                hit_count = hit_count + 1,
                                is_new = CASE
                                    WHEN ? = 0 THEN 0
                                    WHEN (hit_count + 1) > 5 THEN 0
                                    WHEN alias IS NOT NULL AND alias != '' THEN 0
                                    WHEN first_seen < datetime('now', '-15 minutes') THEN 0
                                    ELSE is_new
                                END,
                                last_payload = ?
                            WHERE device_key = ?;
                            """,
                            (updated_alias, updated_cat, timestamp, next_is_new, raw_json, device_key),
                        )

                    dev_row = conn.execute(
                        "SELECT * FROM devices WHERE device_key = ?;", (device_key,)
                    ).fetchone()
                    device_dict = dict(dev_row)
                    device_dict["group_name"] = device_dict.get("group_name") or ""
                    device_dict["last_payload"] = payload
                    device_dict["is_brand_new"] = is_brand_new

                    if int(device_dict.get("ignored", 0)) == 1:
                        return None, device_dict

                    cursor = conn.execute(
                        """
                        INSERT INTO signals (
                            timestamp, model, device_id, channel, freq,
                            rssi, snr, noise, battery_ok, temperature_c, humidity, payload
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                        """,
                        (
                            timestamp,
                            model,
                            device_id,
                            channel,
                            freq,
                            rssi,
                            snr,
                            noise,
                            battery_ok,
                            temperature_c,
                            humidity,
                            raw_json,
                        ),
                    )
                    signal_id = cursor.lastrowid

                    signal_dict = {
                        "id": signal_id,
                        "timestamp": timestamp,
                        "model": model,
                        "device_id": device_id,
                        "device_key": device_key,
                        "alias": device_dict.get("alias", ""),
                        "group_name": device_dict.get("group_name", ""),
                        "category": device_dict.get("category", inferred_cat),
                        "mqtt_enabled": device_dict.get("mqtt_enabled", 1),
                        "ha_discovery": device_dict.get("ha_discovery", 0),
                        "ignored": device_dict.get("ignored", 0),
                        "is_new": int(device_dict.get("is_new", 1)),
                        "hit_count": int(device_dict.get("hit_count", 1)),
                        "channel": channel,
                        "freq": freq,
                        "rssi": rssi,
                        "snr": snr,
                        "noise": noise,
                        "battery_ok": battery_ok,
                        "temperature_c": temperature_c,
                        "humidity": humidity,
                        "payload": payload,
                    }
                    return signal_dict, device_dict
            finally:
                conn.close()

    def touch_beacon_device(self, payload: Dict[str, Any]) -> bool:
        """
        Silently updates last_seen, hit_count, and last_payload (including rssi) in the
        devices table for a known passive BLE beacon (is_beacon_only=True) without inserting
        a new row into the signals table or broadcasting a WebSocket signal event.
        Returns True if the device already exists in devices, or False if it is brand new.
        """
        now_iso = datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
        timestamp = str(payload.get("time") or now_iso)
        model = str(payload.get("model") or "Unknown").strip()
        device_id = extract_device_id(payload)
        device_key = f"{sanitize_key(model)}_{sanitize_key(device_id)}"
        raw_json = json.dumps(payload, ensure_ascii=False)

        with self._lock:
            conn = self._get_conn()
            try:
                with conn:
                    existing_dev = conn.execute(
                        "SELECT device_key, first_seen, hit_count, is_new, alias, group_name FROM devices WHERE device_key = ?;", (device_key,)
                    ).fetchone()
                    if existing_dev is None:
                        return False
                    next_hits = int(existing_dev["hit_count"] or 0) + 1
                    cur_is_new = int(existing_dev["is_new"] or 0)
                    has_alias = bool(existing_dev["alias"] and str(existing_dev["alias"]).strip())
                    has_group = bool(existing_dev["group_name"] and str(existing_dev["group_name"]).strip())
                    next_is_new = 0 if (cur_is_new == 0 or next_hits > 5 or has_alias or has_group or _is_older_than_15_min(existing_dev["first_seen"])) else 1
                    conn.execute(
                        """
                        UPDATE devices
                        SET last_seen = ?,
                            hit_count = hit_count + 1,
                            is_new = CASE
                                WHEN ? = 0 THEN 0
                                WHEN (hit_count + 1) > 5 THEN 0
                                WHEN alias IS NOT NULL AND alias != '' THEN 0
                                WHEN first_seen < datetime('now', '-15 minutes') THEN 0
                                ELSE is_new
                            END,
                            last_payload = ?
                        WHERE device_key = ?;
                        """,
                        (timestamp, next_is_new, raw_json, device_key),
                    )
                    return True
            finally:
                conn.close()

    def get_signals(
        self,
        search: Optional[str] = None,
        model: Optional[str] = None,
        device_id: Optional[str] = None,
        freq_band: Optional[str] = None,
        only_aliased: bool = False,
        unique_devices: bool = False,
        limit: int = 100,
        offset: int = 0,
    ) -> Dict[str, Any]:
        limit = max(1, min(int(limit), 500))
        offset = max(0, int(offset))

        where_clauses = [" COALESCE(d.ignored, 0) = 0 "]
        params: List[Any] = []

        if model and model.strip() and model.strip().lower() != "all":
            where_clauses.append("s.model = ?")
            params.append(model.strip())

        if device_id and device_id.strip():
            where_clauses.append("s.device_id = ?")
            params.append(device_id.strip())

        if freq_band:
            fb = freq_band.strip().lower()
            if fb == "433":
                where_clauses.append("(s.freq >= 430.0 AND s.freq <= 440.0)")
            elif fb == "868":
                where_clauses.append("(s.freq >= 860.0 AND s.freq <= 875.0)")
            elif fb in ("2400", "2.4", "ble"):
                where_clauses.append("(s.freq >= 2400.0 AND s.freq <= 2500.0)")

        if only_aliased:
            where_clauses.append("(d.alias IS NOT NULL AND TRIM(d.alias) != '')")

        if search and search.strip():
            q = f"%{search.strip()}%"
            where_clauses.append(
                "(s.model LIKE ? OR s.device_id LIKE ? OR COALESCE(d.alias, '') LIKE ? OR COALESCE(d.group_name, '') LIKE ? OR COALESCE(d.category, '') LIKE ? OR s.payload LIKE ?)"
            )
            params.extend([q, q, q, q, q, q])

        where_sql = " AND ".join(where_clauses)

        if unique_devices:
            query = f"""
                SELECT
                    s.id, s.timestamp, s.model, s.device_id, s.channel, s.freq,
                    s.rssi, s.snr, s.noise, s.battery_ok, s.temperature_c, s.humidity, s.payload,
                    d.device_key, COALESCE(d.alias, '') AS alias, COALESCE(d.group_name, '') AS group_name,
                    COALESCE(d.category, 'Sensor') AS category,
                    COALESCE(d.mqtt_enabled, 1) AS mqtt_enabled, COALESCE(d.ha_discovery, 0) AS ha_discovery,
                    COALESCE(d.ignored, 0) AS ignored,
                    CASE WHEN COALESCE(d.is_new, 0) = 1 AND COALESCE(d.hit_count, 1) <= 5 AND COALESCE(TRIM(d.alias), '') = '' THEN 1 ELSE 0 END AS is_new,
                    COALESCE(d.hit_count, 1) AS hit_count,
                    d.first_seen AS first_seen
                FROM signals s
                INNER JOIN (
                    SELECT MAX(s2.id) AS max_id
                    FROM signals s2
                    LEFT JOIN devices d2 ON d2.model = s2.model AND d2.device_id = s2.device_id
                    WHERE {where_sql.replace('s.', 's2.').replace('d.', 'd2.')}
                    GROUP BY s2.model, s2.device_id
                ) latest ON s.id = latest.max_id
                LEFT JOIN devices d ON d.model = s.model AND d.device_id = s.device_id
                ORDER BY s.timestamp DESC, s.id DESC
                LIMIT ? OFFSET ?;
            """
            count_query = f"""
                SELECT COUNT(DISTINCT s.model || ':' || s.device_id) AS total
                FROM signals s
                LEFT JOIN devices d ON d.model = s.model AND d.device_id = s.device_id
                WHERE {where_sql};
            """
        else:
            query = f"""
                SELECT
                    s.id, s.timestamp, s.model, s.device_id, s.channel, s.freq,
                    s.rssi, s.snr, s.noise, s.battery_ok, s.temperature_c, s.humidity, s.payload,
                    d.device_key, COALESCE(d.alias, '') AS alias, COALESCE(d.group_name, '') AS group_name,
                    COALESCE(d.category, 'Sensor') AS category,
                    COALESCE(d.mqtt_enabled, 1) AS mqtt_enabled, COALESCE(d.ha_discovery, 0) AS ha_discovery,
                    COALESCE(d.ignored, 0) AS ignored,
                    CASE WHEN COALESCE(d.is_new, 0) = 1 AND COALESCE(d.hit_count, 1) <= 5 AND COALESCE(TRIM(d.alias), '') = '' THEN 1 ELSE 0 END AS is_new,
                    COALESCE(d.hit_count, 1) AS hit_count,
                    d.first_seen AS first_seen
                FROM signals s
                LEFT JOIN devices d ON d.model = s.model AND d.device_id = s.device_id
                WHERE {where_sql}
                ORDER BY s.timestamp DESC, s.id DESC
                LIMIT ? OFFSET ?;
            """
            count_query = f"""
                SELECT COUNT(*) AS total
                FROM signals s
                LEFT JOIN devices d ON d.model = s.model AND d.device_id = s.device_id
                WHERE {where_sql};
            """

        with self._lock:
            conn = self._get_conn()
            try:
                total_row = conn.execute(count_query, params).fetchone()
                total = int(total_row["total"]) if total_row else 0

                rows = conn.execute(query, params + [limit, offset]).fetchall()
                items = []
                for row in rows:
                    item = dict(row)
                    if not item.get("device_key"):
                        item["device_key"] = f"{sanitize_key(item['model'])}_{sanitize_key(item['device_id'])}"
                    item["group_name"] = item.get("group_name") or ""
                    try:
                        pl = json.loads(item["payload"])
                        item["payload"] = enrich_sparsnas_payload(pl) if isinstance(pl, dict) else {"raw": item["payload"]}
                    except Exception:
                        item["payload"] = {"raw": item["payload"]}
                    items.append(item)

                return {
                    "items": items,
                    "total": total,
                    "limit": limit,
                    "offset": offset,
                }
            finally:
                conn.close()

    def get_models(self) -> List[str]:
        with self._lock:
            conn = self._get_conn()
            try:
                rows = conn.execute(
                    """
                    SELECT DISTINCT model FROM (
                        SELECT model FROM devices
                        UNION
                        SELECT model FROM signals
                    )
                    WHERE model IS NOT NULL AND TRIM(model) != ''
                    ORDER BY model COLLATE NOCASE ASC;
                    """
                ).fetchall()
                return [r["model"] for r in rows]
            finally:
                conn.close()

    def get_devices(
        self,
        search: Optional[str] = None,
        include_ignored: bool = True,
    ) -> List[Dict[str, Any]]:
        where_clauses = ["1=1"]
        params: List[Any] = []

        if not include_ignored:
            where_clauses.append("ignored = 0")

        if search and search.strip():
            q = f"%{search.strip()}%"
            where_clauses.append(
                "(model LIKE ? OR device_id LIKE ? OR alias LIKE ? OR COALESCE(group_name, '') LIKE ? OR category LIKE ? OR last_payload LIKE ?)"
            )
            params.extend([q, q, q, q, q, q])

        where_sql = " AND ".join(where_clauses)
        with self._lock:
            conn = self._get_conn()
            try:
                rows = conn.execute(
                    f"""
                    SELECT * FROM devices
                    WHERE {where_sql}
                    ORDER BY last_seen DESC;
                    """,
                    params,
                ).fetchall()
                result = []
                for r in rows:
                    d = dict(r)
                    d["group_name"] = d.get("group_name") or ""
                    d["is_new"] = (
                        1
                        if (
                            int(d.get("is_new") or 0) == 1
                            and int(d.get("hit_count") or 1) <= 5
                            and not (d.get("alias") or "").strip()
                            and not (d.get("group_name") or "").strip()
                            and int(d.get("ignored") or 0) == 0
                            and not _is_older_than_15_min(d.get("first_seen"))
                        )
                        else 0
                    )
                    try:
                        pl = json.loads(d["last_payload"])
                        d["last_payload"] = enrich_sparsnas_payload(pl) if isinstance(pl, dict) else {}
                    except Exception:
                        d["last_payload"] = {}
                    result.append(d)
                return result
            finally:
                conn.close()

    def get_device(self, device_key: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            conn = self._get_conn()
            try:
                row = conn.execute(
                    "SELECT * FROM devices WHERE device_key = ?;", (device_key,)
                ).fetchone()
                if not row:
                    return None
                d = dict(row)
                d["group_name"] = d.get("group_name") or ""
                try:
                    pl = json.loads(d["last_payload"])
                    d["last_payload"] = enrich_sparsnas_payload(pl) if isinstance(pl, dict) else {}
                except Exception:
                    d["last_payload"] = {}
                return d
            finally:
                conn.close()

    def update_device(
        self,
        device_key: str,
        alias: Optional[str] = None,
        group_name: Optional[str] = None,
        category: Optional[str] = None,
        mqtt_enabled: Optional[int] = None,
        ha_discovery: Optional[int] = None,
        ignored: Optional[int] = None,
    ) -> Optional[Dict[str, Any]]:
        with self._lock:
            conn = self._get_conn()
            try:
                row = conn.execute(
                    "SELECT * FROM devices WHERE device_key = ?;", (device_key,)
                ).fetchone()
                if not row:
                    return None

                new_alias = alias.strip() if alias is not None else (row["alias"] or "")
                new_group = group_name.strip() if group_name is not None else (row["group_name"] or "")
                new_cat = category.strip() if category is not None else (row["category"] or "Sensor")
                new_mqtt = int(bool(mqtt_enabled)) if mqtt_enabled is not None else row["mqtt_enabled"]
                new_ha = int(bool(ha_discovery)) if ha_discovery is not None else row["ha_discovery"]
                new_ignored = int(bool(ignored)) if ignored is not None else row["ignored"]

                with conn:
                    conn.execute(
                        """
                        UPDATE devices
                        SET alias = ?, group_name = ?, category = ?, mqtt_enabled = ?, ha_discovery = ?, ignored = ?, is_new = 0
                        WHERE device_key = ?;
                        """,
                        (new_alias, new_group, new_cat, new_mqtt, new_ha, new_ignored, device_key),
                    )
            finally:
                conn.close()
        return self.get_device(device_key)

    def bulk_update_devices(
        self,
        device_keys: List[str],
        group_name: Optional[str] = None,
        category: Optional[str] = None,
        ignored: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        if not device_keys:
            return []
        updated_keys: List[str] = []
        with self._lock:
            conn = self._get_conn()
            try:
                with conn:
                    for dk in device_keys:
                        row = conn.execute(
                            "SELECT * FROM devices WHERE device_key = ?;", (dk,)
                        ).fetchone()
                        if not row:
                            continue
                        new_group = group_name.strip() if group_name is not None else (row["group_name"] or "")
                        new_cat = category.strip() if (category is not None and category.strip() != "") else (row["category"] or "Sensor")
                        new_ignored = int(bool(ignored)) if ignored is not None else row["ignored"]
                        conn.execute(
                            """
                            UPDATE devices
                            SET group_name = ?, category = ?, ignored = ?, is_new = 0
                            WHERE device_key = ?;
                            """,
                            (new_group, new_cat, new_ignored, dk),
                        )
                        updated_keys.append(dk)
            finally:
                conn.close()

        return [d for d in (self.get_device(k) for k in updated_keys) if d is not None]

    def delete_device(self, device_key: str) -> bool:
        with self._lock:
            conn = self._get_conn()
            try:
                row = conn.execute(
                    "SELECT model, device_id FROM devices WHERE device_key = ?;",
                    (device_key,),
                ).fetchone()
                if not row:
                    return False
                with conn:
                    conn.execute(
                        "DELETE FROM signals WHERE model = ? AND device_id = ?;",
                        (row["model"], row["device_id"]),
                    )
                    conn.execute("DELETE FROM devices WHERE device_key = ?;", (device_key,))
                return True
            finally:
                conn.close()

    def is_device_known_and_named(self, device_id: str) -> bool:
        with self._lock:
            conn = self._get_conn()
            try:
                row = conn.execute(
                    """
                    SELECT 1 FROM devices
                    WHERE device_id = ?
                      AND (COALESCE(TRIM(alias), '') != '' OR COALESCE(TRIM(group_name), '') != '')
                    LIMIT 1;
                    """,
                    (str(device_id).strip(),),
                ).fetchone()
                return row is not None
            finally:
                conn.close()

    def get_summary_counts(self) -> Dict[str, int]:
        today_prefix = datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d")
        with self._lock:
            conn = self._get_conn()
            try:
                total_signals = conn.execute("SELECT COUNT(*) AS c FROM signals;").fetchone()["c"]
                signals_today = conn.execute(
                    "SELECT COUNT(*) AS c FROM signals WHERE timestamp LIKE ?;",
                    (f"{today_prefix}%",),
                ).fetchone()["c"]
                total_devices = conn.execute("SELECT COUNT(*) AS c FROM devices;").fetchone()["c"]
                active_devices = conn.execute(
                    "SELECT COUNT(*) AS c FROM devices WHERE ignored = 0;"
                ).fetchone()["c"]
                ignored_devices = conn.execute(
                    "SELECT COUNT(*) AS c FROM devices WHERE ignored = 1;"
                ).fetchone()["c"]
                new_devices = conn.execute(
                    "SELECT COUNT(*) AS c FROM devices WHERE COALESCE(is_new, 0) = 1 AND COALESCE(hit_count, 1) <= 5 AND ignored = 0 AND COALESCE(TRIM(alias), '') = '' AND COALESCE(TRIM(group_name), '') = '';"
                ).fetchone()["c"]
                ble_devices = conn.execute(
                    "SELECT COUNT(*) AS c FROM devices WHERE ignored = 0 AND (model LIKE '%BLE%' OR model IN ('Enhauto-S3XY', 'Plejd-Mesh', 'Xiaomi-MiBeacon') OR last_payload LIKE '%\"mod\": \"BLE\"%' OR last_payload LIKE '%\"mod\":\"BLE\"%');"
                ).fetchone()["c"]
                return {
                    "total_signals": int(total_signals),
                    "signals_today": int(signals_today),
                    "total_devices": int(total_devices),
                    "active_devices": int(active_devices),
                    "ignored_devices": int(ignored_devices),
                    "new_devices": int(new_devices),
                    "ble_devices": int(ble_devices),
                }
            finally:
                conn.close()

    def get_stats(self) -> Dict[str, Any]:
        now = datetime.now(timezone.utc).astimezone()
        since_24h = (now - timedelta(hours=23)).replace(minute=0, second=0, microsecond=0)
        since_iso = since_24h.isoformat(timespec="seconds")

        hours_map: Dict[str, int] = {}
        for i in range(24):
            h_dt = since_24h + timedelta(hours=i)
            h_key = h_dt.strftime("%Y-%m-%d %H:00")
            hours_map[h_key] = 0

        with self._lock:
            conn = self._get_conn()
            try:
                rows_24h = conn.execute(
                    """
                    SELECT SUBSTR(REPLACE(timestamp, 'T', ' '), 1, 13) || ':00' AS hour_bucket,
                           COUNT(*) AS cnt
                    FROM signals
                    WHERE timestamp >= ?
                    GROUP BY hour_bucket
                    ORDER BY hour_bucket ASC;
                    """,
                    (since_iso[:13],),
                ).fetchall()

                for r in rows_24h:
                    hb = r["hour_bucket"]
                    if hb in hours_map:
                        hours_map[hb] = int(r["cnt"])

                hourly_series = [
                    {"hour": k[-5:], "full_hour": k, "count": v}
                    for k, v in hours_map.items()
                ]

                freq_rows = conn.execute(
                    """
                    SELECT
                        SUM(CASE WHEN freq >= 430.0 AND freq <= 440.0 THEN 1 ELSE 0 END) AS band_433,
                        SUM(CASE WHEN freq >= 860.0 AND freq <= 875.0 THEN 1 ELSE 0 END) AS band_868,
                        SUM(CASE WHEN freq >= 2400.0 AND freq <= 2500.0 THEN 1 ELSE 0 END) AS band_2400,
                        SUM(CASE WHEN freq IS NULL OR NOT ((freq >= 430.0 AND freq <= 440.0) OR (freq >= 860.0 AND freq <= 875.0) OR (freq >= 2400.0 AND freq <= 2500.0)) THEN 1 ELSE 0 END) AS band_other
                    FROM signals;
                    """
                ).fetchone()

                band_433 = int(freq_rows["band_433"] or 0)
                band_868 = int(freq_rows["band_868"] or 0)
                band_2400 = int(freq_rows["band_2400"] or 0)
                band_other = int(freq_rows["band_other"] or 0)

                top_devices_rows = conn.execute(
                    """
                    SELECT device_key, model, device_id, alias, category, hit_count, last_seen, ignored
                    FROM devices
                    WHERE ignored = 0
                    ORDER BY hit_count DESC, last_seen DESC
                    LIMIT 10;
                    """
                ).fetchall()
                top_devices = [dict(r) for r in top_devices_rows]

                counts = self.get_summary_counts()
                return {
                    **counts,
                    "hourly_24h": hourly_series,
                    "frequency_distribution": {
                        "433_mhz": band_433,
                        "868_mhz": band_868,
                        "2400_mhz": band_2400,
                        "other": band_other,
                    },
                    "top_devices": top_devices,
                }
            finally:
                conn.close()

    def run_retention_cleanup(self, retention_days: Optional[int] = None) -> int:
        if retention_days is None:
            settings = self.get_settings()
            try:
                retention_days = int(settings.get("retention_days", 30))
            except (ValueError, TypeError):
                retention_days = 30

        retention_days = max(1, int(retention_days))
        cutoff = (datetime.now(timezone.utc).astimezone() - timedelta(days=retention_days)).isoformat(
            timespec="seconds"
        )

        with self._lock:
            conn = self._get_conn()
            try:
                with conn:
                    cur = conn.execute("DELETE FROM signals WHERE timestamp < ?;", (cutoff,))
                    deleted = cur.rowcount
                    conn.execute("PRAGMA optimize;")
                logger.info("Retention cleanup completed: removed %d signals older than %d days.", deleted, retention_days)
                return deleted
            finally:
                conn.close()

    def optimize_database(self) -> Dict[str, Any]:
        deleted = self.run_retention_cleanup()
        with self._lock:
            conn = self._get_conn()
            try:
                with conn:
                    conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
                    conn.execute("PRAGMA optimize;")
            finally:
                conn.close()
        size_bytes = os.path.getsize(self.db_path) if os.path.exists(self.db_path) else 0
        return {"ok": True, "deleted_signals": deleted, "size_bytes": size_bytes}

    def export_backup(self) -> Dict[str, Any]:
        devices = self.get_devices(include_ignored=True)
        settings = self.get_settings()
        return {
            "exported_at": now_iso(),
            "devices": devices,
            "settings": settings,
        }

    def import_backup(self, data: Dict[str, Any]) -> Dict[str, int]:
        devices_in = data.get("devices") if isinstance(data.get("devices"), list) else []
        imported_count = 0
        now_ts = now_iso()
        with self._lock:
            conn = self._get_conn()
            try:
                with conn:
                    for dev in devices_in:
                        if not isinstance(dev, dict):
                            continue
                        dk = str(dev.get("device_key") or "").strip()
                        model = str(dev.get("model") or "").strip()
                        dev_id = str(dev.get("device_id") or "").strip()
                        if not dk or not model:
                            continue
                        alias = str(dev.get("alias") or "").strip()
                        group_name = str(dev.get("group_name") or "").strip()
                        category = str(dev.get("category") or "Sensor").strip()
                        mqtt_en = int(bool(dev.get("mqtt_enabled", 1)))
                        ha_disc = int(bool(dev.get("ha_discovery", 0)))
                        ignored = int(bool(dev.get("ignored", 0)))
                        first_seen = str(dev.get("first_seen") or now_ts)
                        last_seen = str(dev.get("last_seen") or now_ts)
                        hit_count = int(dev.get("hit_count") or 1)
                        lp = dev.get("last_payload")
                        lp_json = json.dumps(lp, ensure_ascii=False) if isinstance(lp, dict) else "{}"

                        existing = conn.execute(
                            "SELECT device_key FROM devices WHERE device_key = ?;", (dk,)
                        ).fetchone()
                        if existing:
                            conn.execute(
                                """
                                UPDATE devices
                                SET alias = ?, group_name = ?, category = ?, mqtt_enabled = ?, ha_discovery = ?, ignored = ?, is_new = 0
                                WHERE device_key = ?;
                                """,
                                (alias, group_name, category, mqtt_en, ha_disc, ignored, dk),
                            )
                        else:
                            conn.execute(
                                """
                                INSERT INTO devices (
                                    device_key, model, device_id, alias, group_name, category,
                                    mqtt_enabled, ha_discovery, ignored, is_new, first_seen, last_seen, hit_count, last_payload
                                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?);
                                """,
                                (dk, model, dev_id, alias, group_name, category, mqtt_en, ha_disc, ignored, first_seen, last_seen, hit_count, lp_json),
                            )
                        imported_count += 1
            finally:
                conn.close()
        return {"imported_devices": imported_count}

    def reset_database(self, keep_aliases: bool = False) -> Dict[str, Any]:
        with self._lock:
            conn = self._get_conn()
            try:
                with conn:
                    deleted_signals = conn.execute("DELETE FROM signals;").rowcount
                    try:
                        conn.execute("DELETE FROM sqlite_sequence WHERE name = 'signals';")
                    except Exception:
                        pass

                    if keep_aliases:
                        deleted_devices = conn.execute(
                            "DELETE FROM devices WHERE COALESCE(TRIM(alias), '') = '' AND COALESCE(TRIM(group_name), '') = '';"
                        ).rowcount
                        conn.execute("UPDATE devices SET hit_count = 0;")
                    else:
                        deleted_devices = conn.execute("DELETE FROM devices;").rowcount
                        try:
                            conn.execute("DELETE FROM sqlite_sequence WHERE name IN ('signals', 'devices');")
                        except Exception:
                            pass

                try:
                    conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
                    conn.execute("VACUUM;")
                except Exception as exc:
                    logger.warning("VACUUM after reset warning: %s", exc)
            finally:
                conn.close()

        size_bytes = os.path.getsize(self.db_path) if os.path.exists(self.db_path) else 0
        return {
            "ok": True,
            "keep_aliases": bool(keep_aliases),
            "deleted_signals": int(deleted_signals or 0),
            "deleted_devices": int(deleted_devices or 0),
            "size_bytes": size_bytes,
        }
