import json
import logging
import re
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

import paho.mqtt.client as mqtt

from app import __version__
from app.database import enrich_sparsnas_payload

logger = logging.getLogger("sensor_scanner.mqtt")


def sanitize_topic_segment(value: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9_\-]", "_", str(value or "").strip())
    cleaned = re.sub(r"_+", "_", cleaned).strip("_")
    return cleaned or "unknown"


# Metric definitions: (json_key, metric_slug, friendly_suffix, unit, device_class, state_class, value_template)
HA_METRIC_SPECS: List[Tuple[str, str, str, str, Optional[str], str, str]] = [
    (
        "temperature_C",
        "temperature",
        "Temperatur",
        "°C",
        "temperature",
        "measurement",
        "{{ value_json.temperature_C | float | round(1) }}",
    ),
    (
        "temperature_F",
        "temperature_f",
        "Temperatur",
        "°C",
        "temperature",
        "measurement",
        "{{ ((value_json.temperature_F | float - 32) * 5 / 9) | round(1) }}",
    ),
    (
        "temperature_1_C",
        "temperature_1",
        "Temperatur (Kanal 1)",
        "°C",
        "temperature",
        "measurement",
        "{{ value_json.temperature_1_C | float | round(1) }}",
    ),
    (
        "temperature_1_F",
        "temperature_1_f",
        "Temperatur (Kanal 1)",
        "°C",
        "temperature",
        "measurement",
        "{{ ((value_json.temperature_1_F | float - 32) * 5 / 9) | round(1) }}",
    ),
    (
        "temperature_2_C",
        "temperature_2",
        "Temperatur (Kanal 2)",
        "°C",
        "temperature",
        "measurement",
        "{{ value_json.temperature_2_C | float | round(1) }}",
    ),
    (
        "temperature_2_F",
        "temperature_2_f",
        "Temperatur (Kanal 2)",
        "°C",
        "temperature",
        "measurement",
        "{{ ((value_json.temperature_2_F | float - 32) * 5 / 9) | round(1) }}",
    ),
    (
        "humidity",
        "humidity",
        "Luftfuktighet",
        "%",
        "humidity",
        "measurement",
        "{{ value_json.humidity | float | round(1) }}",
    ),
    (
        "humidity_1",
        "humidity_1",
        "Luftfuktighet (Kanal 1)",
        "%",
        "humidity",
        "measurement",
        "{{ value_json.humidity_1 | float | round(1) }}",
    ),
    (
        "humidity_2",
        "humidity_2",
        "Luftfuktighet (Kanal 2)",
        "%",
        "humidity",
        "measurement",
        "{{ value_json.humidity_2 | float | round(1) }}",
    ),
    (
        "lux",
        "illuminance",
        "Ljusstyrka",
        "lx",
        "illuminance",
        "measurement",
        "{{ value_json.lux | int }}",
    ),
    (
        "moisture",
        "moisture",
        "Markfuktighet",
        "%",
        "moisture",
        "measurement",
        "{{ value_json.moisture | float | round(1) }}",
    ),
    (
        "distance_m",
        "distance_m",
        "BLE Avstånd",
        "m",
        "distance",
        "measurement",
        "{{ value_json.distance_m | float | round(1) }}",
    ),
    (
        "pressure_kPa",
        "pressure_kpa",
        "Däcktryck",
        "bar",
        "pressure",
        "measurement",
        "{{ (value_json.pressure_kPa | float / 100.0) | round(2) }}",
    ),
    (
        "pressure_bar",
        "pressure_bar",
        "Däcktryck",
        "bar",
        "pressure",
        "measurement",
        "{{ value_json.pressure_bar | float | round(2) }}",
    ),
    (
        "pressure_PSI",
        "pressure_psi_bar",
        "Däcktryck",
        "bar",
        "pressure",
        "measurement",
        "{{ (value_json.pressure_PSI | float * 0.0689476) | round(2) }}",
    ),
    (
        "pressure_hPa",
        "pressure_hpa",
        "Lufttryck",
        "hPa",
        "atmospheric_pressure",
        "measurement",
        "{{ value_json.pressure_hPa | float | round(1) }}",
    ),
    (
        "power_W",
        "power",
        "Effekt",
        "W",
        "power",
        "measurement",
        "{{ value_json.power_W | float | round(1) }}",
    ),
    (
        "calculated_power_W",
        "calculated_power",
        "Aktuell Effekt",
        "W",
        "power",
        "measurement",
        "{{ value_json.calculated_power_W | int }}",
    ),
    (
        "energy_kWh",
        "energy",
        "Energi",
        "kWh",
        "energy",
        "total_increasing",
        "{{ value_json.energy_kWh | float | round(3) }}",
    ),
    (
        "cumulative_kwh",
        "cumulative_energy",
        "Total Energi",
        "kWh",
        "energy",
        "total_increasing",
        "{{ value_json.cumulative_kwh | float | round(3) }}",
    ),
    (
        "pulses",
        "pulses",
        "Pulser",
        "pulser",
        None,
        "total_increasing",
        "{{ value_json.pulses | int }}",
    ),
    (
        "wind_avg_km_h",
        "wind_speed",
        "Vindhastighet",
        "m/s",
        "wind_speed",
        "measurement",
        "{{ (value_json.wind_avg_km_h | float / 3.6) | round(1) }}",
    ),
    (
        "wind_avg_m_s",
        "wind_speed_ms",
        "Vindhastighet",
        "m/s",
        "wind_speed",
        "measurement",
        "{{ value_json.wind_avg_m_s | float | round(1) }}",
    ),
    (
        "rain_mm",
        "rain",
        "Nederbörd",
        "mm",
        "precipitation",
        "total_increasing",
        "{{ value_json.rain_mm | float | round(1) }}",
    ),
    (
        "rssi",
        "rssi",
        "RSSI",
        "dB",
        "signal_strength",
        "measurement",
        "{{ value_json.rssi | float | round(1) }}",
    ),
    (
        "snr",
        "snr",
        "SNR",
        "dB",
        "signal_strength",
        "measurement",
        "{{ value_json.snr | float | round(1) }}",
    ),
]


class MQTTManager:
    def __init__(self, status_callback: Optional[Callable[[Dict[str, Any]], None]] = None):
        self._client: Optional[mqtt.Client] = None
        self._lock = threading.RLock()
        self._connected: bool = False
        self._enabled: bool = True
        self._host: str = "192.168.1.121"
        self._port: int = 1883
        self._user: str = ""
        self._password: str = ""
        self._prefix: str = "sensor_scanner"
        self._ha_discovery_enabled: bool = False
        self._ha_discovery_prefix: str = "homeassistant"
        self._last_error: str = ""
        self._published_count: int = 0
        self._status_callback = status_callback
        self._ble_presence_state: Dict[str, Dict[str, Any]] = {}

    def configure_and_connect(self, settings: Dict[str, Any], reconnect_broker: bool = True) -> None:
        with self._lock:
            self._enabled = str(settings.get("mqtt_enabled", "1")).strip() not in ("0", "false", "False", "")
            self._host = str(settings.get("mqtt_host", "192.168.1.121")).strip()
            try:
                self._port = int(settings.get("mqtt_port", 1883))
            except (ValueError, TypeError):
                self._port = 1883
            self._user = str(settings.get("mqtt_user", "")).strip()
            self._password = str(settings.get("mqtt_pass", ""))
            self._prefix = str(settings.get("mqtt_prefix", "sensor_scanner")).strip().strip("/") or "sensor_scanner"
            self._ha_discovery_enabled = str(settings.get("ha_discovery_enabled", "0")).strip() in ("1", "true", "True")
            self._ha_discovery_prefix = (
                str(settings.get("ha_discovery_prefix", "homeassistant")).strip().strip("/") or "homeassistant"
            )

            if not reconnect_broker and self._client is not None:
                self._notify_status()
                return

            self.disconnect()

            if not self._enabled or not self._host:
                self._connected = False
                self._last_error = "" if not self._enabled else "MQTT host saknas"
                self._notify_status()
                return

            try:
                client = mqtt.Client(
                    callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
                    client_id=f"sensor_scanner_{sanitize_topic_segment(self._prefix)}",
                )
                if self._user:
                    client.username_pw_set(self._user, self._password)

                client.on_connect = self._on_connect
                client.on_disconnect = self._on_disconnect

                availability_topic = f"{self._prefix}/status"
                client.will_set(availability_topic, payload="offline", qos=1, retain=True)

                client.reconnect_delay_set(min_delay=2, max_delay=30)
                client.connect_async(self._host, self._port, keepalive=60)
                client.loop_start()
                self._client = client
                self._last_error = ""
            except Exception as exc:
                self._connected = False
                self._last_error = str(exc)
                logger.error("Failed to initialize MQTT client: %s", exc)
                self._notify_status()

    def disconnect(self) -> None:
        with self._lock:
            if self._client is not None:
                try:
                    if self._connected:
                        self._client.publish(f"{self._prefix}/status", payload="offline", qos=1, retain=True)
                    self._client.loop_stop()
                    self._client.disconnect()
                except Exception as exc:
                    logger.debug("Error while disconnecting MQTT: %s", exc)
                finally:
                    self._client = None
                    self._connected = False

    def _on_connect(self, client: mqtt.Client, userdata: Any, flags: Any, reason_code: Any, properties: Any = None) -> None:
        if reason_code == 0 or str(reason_code).lower() == "success":
            self._connected = True
            self._last_error = ""
            logger.info("Connected to MQTT broker at %s:%d", self._host, self._port)
            try:
                client.publish(f"{self._prefix}/status", payload="online", qos=1, retain=True)
            except Exception:
                pass
        else:
            self._connected = False
            self._last_error = f"MQTT anslutningsfel: {reason_code}"
            logger.warning("MQTT connection failed with reason: %s", reason_code)
        self._notify_status()

    def _on_disconnect(
        self, client: mqtt.Client, userdata: Any, flags: Any, reason_code: Any, properties: Any = None
    ) -> None:
        self._connected = False
        if reason_code != 0 and str(reason_code).lower() != "normal disconnection":
            self._last_error = f"Frånkopplad ({reason_code})"
        logger.info("Disconnected from MQTT broker (reason=%s)", reason_code)
        self._notify_status()

    def _notify_status(self) -> None:
        if self._status_callback:
            try:
                self._status_callback(self.get_status())
            except Exception:
                pass

    def get_status(self) -> Dict[str, Any]:
        return {
            "enabled": self._enabled,
            "connected": self._connected,
            "host": self._host,
            "port": self._port,
            "prefix": self._prefix,
            "user": self._user,
            "ha_discovery_enabled": self._ha_discovery_enabled,
            "ha_discovery_prefix": self._ha_discovery_prefix,
            "last_error": self._last_error,
            "published_count": self._published_count,
        }

    def publish_signal(self, device: Dict[str, Any], payload: Dict[str, Any]) -> bool:
        if not self._enabled or not self._connected or self._client is None:
            return False

        if int(device.get("ignored", 0)) == 1 or int(device.get("mqtt_enabled", 1)) == 0:
            return False

        model_seg = sanitize_topic_segment(device.get("model", "Unknown"))
        id_seg = sanitize_topic_segment(device.get("device_id", "unknown"))
        safe_device_key = sanitize_topic_segment(device.get("device_key") or f"{model_seg}_{id_seg}")
        alias_raw = str(device.get("alias", "") or "").strip()

        enriched_payload = enrich_sparsnas_payload(dict(payload))
        if enriched_payload.get("battery_mV") is not None and "battery_mv" not in enriched_payload:
            enriched_payload["battery_mv"] = enriched_payload["battery_mV"]
        elif enriched_payload.get("battery_mv") is not None and "battery_mV" not in enriched_payload:
            enriched_payload["battery_mV"] = enriched_payload["battery_mv"]
        if alias_raw:
            enriched_payload["alias"] = alias_raw
        enriched_payload["device_key"] = device.get("device_key") or safe_device_key

        json_str = json.dumps(enriched_payload, ensure_ascii=False)
        base_topic = f"{self._prefix}/{model_seg}/{id_seg}"
        state_topic = f"{self._prefix}/{safe_device_key}/state"

        try:
            self._client.publish(state_topic, payload=json_str, qos=0, retain=False)
            self._client.publish(base_topic, payload=json_str, qos=0, retain=False)
            is_ble = (
                str(enriched_payload.get("mod") or "").upper() == "BLE"
                or float(enriched_payload.get("freq") or 0) >= 2400.0
                or "BLE" in str(device.get("model", ""))
            )
            if is_ble:
                ble_topic = f"{self._prefix}/BLE/{model_seg}/{id_seg}"
                self._client.publish(ble_topic, payload=json_str, qos=0, retain=False)
                if enriched_payload.get("rssi") is not None and (
                    int(device.get("ha_discovery", 0)) == 1 or safe_device_key in self._ble_presence_state
                ):
                    with self._lock:
                        self._ble_presence_state[safe_device_key] = {
                            "last_seen_mono": time.monotonic(),
                            "is_home": True,
                            "state_topic": state_topic,
                            "base_topic": base_topic,
                            "device_key": device.get("device_key") or safe_device_key,
                        }
            if alias_raw:
                alias_seg = sanitize_topic_segment(alias_raw)
                alias_topic = f"{self._prefix}/alias/{alias_seg}"
                self._client.publish(alias_topic, payload=json_str, qos=0, retain=False)
            self._published_count += 1
            return True
        except Exception as exc:
            logger.warning("Failed to publish MQTT message: %s", exc)
            self._last_error = str(exc)
            return False

    def check_ble_presence_timeouts(self, timeout_seconds: float = 120.0) -> int:
        if not self._enabled or not self._connected or self._client is None:
            return 0

        now_mono = time.monotonic()
        expired_entries: List[Dict[str, Any]] = []
        with self._lock:
            for safe_key, info in self._ble_presence_state.items():
                if info.get("is_home") and (now_mono - float(info.get("last_seen_mono", 0.0))) > timeout_seconds:
                    info["is_home"] = False
                    expired_entries.append(dict(info))

        count = 0
        for entry in expired_entries:
            away_payload = json.dumps(
                {
                    "status": "not_home",
                    "presence": "OFF",
                    "device_key": entry.get("device_key"),
                },
                ensure_ascii=False,
            )
            try:
                if entry.get("state_topic"):
                    self._client.publish(entry["state_topic"], payload=away_payload, qos=0, retain=False)
                if entry.get("base_topic"):
                    self._client.publish(entry["base_topic"], payload=away_payload, qos=0, retain=False)
                count += 1
            except Exception as exc:
                logger.debug("Failed to publish BLE presence away payload: %s", exc)
        return count

    def publish_ha_discovery(self, device: Dict[str, Any]) -> Dict[str, Any]:
        """
        Publishes Home Assistant MQTT Auto-Discovery configurations for a device:
        - binary_sensor (device_class: presence, off_delay: 120) for Vehicle / iBeacon / BLE Beacon
        - device_tracker (source_type: bluetooth_le) for Vehicle
        - sensor entities for telemetry metrics (with expire_after: 120 on BLE distance_m and rssi)
        """
        if not self._ha_discovery_enabled:
            return {
                "ok": False,
                "error": "Home Assistant Auto-Discovery är avstängt under Inställningar.",
                "published_topics": [],
            }

        if not self._enabled or not self._connected or self._client is None:
            return {
                "ok": False,
                "error": "MQTT är inte ansluten. Kontrollera MQTT-inställningarna.",
                "published_topics": [],
            }

        safe_device_key = sanitize_topic_segment(device.get("device_key", "unknown"))
        model = str(device.get("model", "Unknown"))
        device_id = str(device.get("device_id", "unknown"))
        alias = str(device.get("alias", "") or "").strip()
        display_name = alias if alias else f"{model} {device_id}"

        model_seg = sanitize_topic_segment(model)
        id_seg = sanitize_topic_segment(device_id)
        base_topic = f"{self._prefix}/{model_seg}/{id_seg}"
        state_topic = f"{self._prefix}/{safe_device_key}/state"

        payload = device.get("last_payload") or {}
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except Exception:
                payload = {}
        payload = enrich_sparsnas_payload(dict(payload))

        category = str(device.get("category") or payload.get("category") or "Generic").strip()
        is_vehicle = category == "Vehicle" or model.endswith("-Vehicle-BLE")
        is_tracker = category == "Tracker"
        is_ibeacon = (
            str(payload.get("apple_type") or "") == "iBeacon"
            or model == "iBeacon-BLE"
            or bool(payload.get("ibeacon_uuid"))
        )
        is_beacon_only = bool(payload.get("is_beacon_only"))
        is_ble = (
            str(payload.get("mod") or "").upper() == "BLE"
            or float(payload.get("freq") or 0) >= 2400.0
            or "BLE" in model
            or is_vehicle
            or is_tracker
            or is_ibeacon
        )
        needs_presence = is_vehicle or is_tracker or is_ibeacon or is_beacon_only

        manufacturer = str(
            payload.get("manufacturer_name")
            or ("Tesla" if model == "Tesla-Vehicle-BLE" else ("BLE / SensorScanner" if is_ble else "rtl_433 / SensorScanner"))
        )
        ha_device_block = {
            "identifiers": [f"sensor_scanner_{safe_device_key}"],
            "name": display_name,
            "model": model,
            "manufacturer": manufacturer,
            "sw_version": __version__,
        }

        published_topics: List[str] = []

        # Remove any legacy vehicle_status text sensor topic
        for legacy_vs_topic in (
            f"{self._ha_discovery_prefix}/sensor/sensor_scanner_{safe_device_key}_vehicle_status/config",
            f"{self._ha_discovery_prefix}/sensor/{safe_device_key}/vehicle_status/config",
        ):
            try:
                self._client.publish(legacy_vs_topic, payload="", qos=1, retain=True)
            except Exception:
                pass

        attr_template = (
            "{{ {"
            "'beacon_hash': value_json.beacon_hash | default(''), "
            "'tesla_node': value_json.tesla_node | default(''), "
            "'mac': value_json.mac | default(''), "
            "'mac_type': value_json.mac_type | default(''), "
            "'ibeacon_uuid': value_json.ibeacon_uuid | default(''), "
            "'major': value_json.major | default(''), "
            "'minor': value_json.minor | default(''), "
            "'distance_m': value_json.distance_m | default('')"
            "} | tojson }}"
        )

        # 1. binary_sensor for Presence (device_class: "presence", off_delay: 120)
        if needs_presence:
            presence_topic = f"{self._ha_discovery_prefix}/binary_sensor/{safe_device_key}/presence/config"
            presence_config: Dict[str, Any] = {
                "name": "Närvaro",
                "unique_id": f"{safe_device_key}_presence",
                "state_topic": state_topic,
                "value_template": "{{ 'ON' if value_json.rssi is defined else 'OFF' }}",
                "payload_on": "ON",
                "payload_off": "OFF",
                "device_class": "presence",
                "off_delay": 120,
                "icon": "mdi:car-connected" if is_vehicle else "mdi:bluetooth-connect",
                "json_attributes_topic": state_topic,
                "json_attributes_template": attr_template,
                "device": ha_device_block,
            }
            self._client.publish(
                presence_topic,
                payload=json.dumps(presence_config, ensure_ascii=False),
                qos=1,
                retain=True,
            )
            published_topics.append(presence_topic)

        # 2. device_tracker for Vehicles (source_type: "bluetooth_le")
        if is_vehicle:
            tracker_topic = f"{self._ha_discovery_prefix}/device_tracker/{safe_device_key}/config"
            tracker_config: Dict[str, Any] = {
                "name": "Tracker",
                "unique_id": f"{safe_device_key}_tracker",
                "state_topic": state_topic,
                "value_template": "{{ 'home' if value_json.rssi is defined else 'not_home' }}",
                "payload_home": "home",
                "payload_not_home": "not_home",
                "source_type": "bluetooth_le",
                "icon": "mdi:car-estate",
                "json_attributes_topic": state_topic,
                "json_attributes_template": attr_template,
                "device": ha_device_block,
            }
            self._client.publish(
                tracker_topic,
                payload=json.dumps(tracker_config, ensure_ascii=False),
                qos=1,
                retain=True,
            )
            published_topics.append(tracker_topic)

        # 3. Battery entities (strictly deduplicated: battery_pct vs binary_sensor battery_low + diagnostic battery_mv)
        has_battery_pct = payload.get("battery_pct") is not None
        has_battery_mv = payload.get("battery_mV") is not None or payload.get("battery_mv") is not None
        has_battery_ok = payload.get("battery_ok") is not None or device.get("battery_ok") is not None

        if has_battery_pct:
            # Clear any legacy/duplicate battery_ok or duplicate battery topics so ONLY ONE "Batteri" (%) sensor exists
            for dup_bat_topic in (
                f"{self._ha_discovery_prefix}/sensor/sensor_scanner_{safe_device_key}_battery/config",
                f"{self._ha_discovery_prefix}/sensor/sensor_scanner_{safe_device_key}_battery_ok/config",
                f"{self._ha_discovery_prefix}/sensor/{safe_device_key}/battery_ok/config",
                f"{self._ha_discovery_prefix}/sensor/{safe_device_key}/battery/config",
                f"{self._ha_discovery_prefix}/sensor/{safe_device_key}/battery_pct/config",
                f"{self._ha_discovery_prefix}/binary_sensor/{safe_device_key}/battery_low/config",
                f"{self._ha_discovery_prefix}/binary_sensor/sensor_scanner_{safe_device_key}_battery_low/config",
            ):
                try:
                    self._client.publish(dup_bat_topic, payload="", qos=1, retain=True)
                except Exception:
                    pass

            bat_pct_uid = f"sensor_scanner_{safe_device_key}_battery_pct"
            bat_pct_topic = f"{self._ha_discovery_prefix}/sensor/{bat_pct_uid}/config"
            bat_pct_config: Dict[str, Any] = {
                "name": "Batteri",
                "unique_id": bat_pct_uid,
                "state_topic": state_topic,
                "device_class": "battery",
                "unit_of_measurement": "%",
                "state_class": "measurement",
                "value_template": "{{ value_json.battery_pct }}",
                "device": ha_device_block,
            }
            self._client.publish(
                bat_pct_topic,
                payload=json.dumps(bat_pct_config, ensure_ascii=False),
                qos=1,
                retain=True,
            )
            published_topics.append(bat_pct_topic)
        elif has_battery_ok:
            # Only battery_ok (0 or 1) exists (e.g., 433 MHz sensors): clear fake 100% percentage sensors
            for legacy_bat_topic in (
                f"{self._ha_discovery_prefix}/sensor/sensor_scanner_{safe_device_key}_battery/config",
                f"{self._ha_discovery_prefix}/sensor/sensor_scanner_{safe_device_key}_battery_ok/config",
                f"{self._ha_discovery_prefix}/sensor/sensor_scanner_{safe_device_key}_battery_pct/config",
                f"{self._ha_discovery_prefix}/sensor/{safe_device_key}/battery_ok/config",
                f"{self._ha_discovery_prefix}/sensor/{safe_device_key}/battery/config",
                f"{self._ha_discovery_prefix}/sensor/{safe_device_key}/battery_pct/config",
            ):
                try:
                    self._client.publish(legacy_bat_topic, payload="", qos=1, retain=True)
                except Exception:
                    pass

            bat_low_topic = f"{self._ha_discovery_prefix}/binary_sensor/{safe_device_key}/battery_low/config"
            bat_low_config: Dict[str, Any] = {
                "name": "Batteristatus",
                "unique_id": f"{safe_device_key}_battery_low",
                "state_topic": state_topic,
                "device_class": "battery",
                "value_template": "{{ 'ON' if value_json.battery_ok == 0 else 'OFF' }}",
                "payload_on": "ON",
                "payload_off": "OFF",
                "device": ha_device_block,
            }
            self._client.publish(
                bat_low_topic,
                payload=json.dumps(bat_low_config, ensure_ascii=False),
                qos=1,
                retain=True,
            )
            published_topics.append(bat_low_topic)

        if has_battery_mv:
            for dup_mv_topic in (
                f"{self._ha_discovery_prefix}/sensor/{safe_device_key}/battery_mv/config",
                f"{self._ha_discovery_prefix}/sensor/{safe_device_key}/battery_mV/config",
            ):
                try:
                    self._client.publish(dup_mv_topic, payload="", qos=1, retain=True)
                except Exception:
                    pass

            bat_mv_uid = f"sensor_scanner_{safe_device_key}_battery_mv"
            bat_mv_topic = f"{self._ha_discovery_prefix}/sensor/{bat_mv_uid}/config"
            bat_mv_config: Dict[str, Any] = {
                "name": "Batterispänning",
                "unique_id": bat_mv_uid,
                "state_topic": state_topic,
                "device_class": "voltage",
                "unit_of_measurement": "mV",
                "state_class": "measurement",
                "entity_category": "diagnostic",
                "value_template": "{{ (value_json.battery_mV if value_json.battery_mV is defined else value_json.battery_mv) | int }}",
                "device": ha_device_block,
            }
            self._client.publish(
                bat_mv_topic,
                payload=json.dumps(bat_mv_config, ensure_ascii=False),
                qos=1,
                retain=True,
            )
            published_topics.append(bat_mv_topic)

        # 4. Telemetry sensor entities (with expire_after: 120 on BLE distance_m and rssi)
        for json_key, metric_slug, suffix, unit, dev_class, state_class, val_tpl in HA_METRIC_SPECS:
            if json_key not in payload or payload[json_key] is None:
                continue

            unique_id = f"sensor_scanner_{safe_device_key}_{metric_slug}"
            config_topic = f"{self._ha_discovery_prefix}/sensor/{unique_id}/config"

            eff_unit = "dBm" if (is_ble and json_key == "rssi") else unit
            eff_tpl = val_tpl
            if is_ble and json_key == "rssi":
                eff_tpl = "{{ value_json.rssi | int if value_json.rssi is defined else None }}"
            elif is_ble and json_key == "distance_m":
                eff_tpl = "{{ value_json.distance_m | float | round(1) if value_json.distance_m is defined else None }}"

            config_payload: Dict[str, Any] = {
                "name": f"{display_name} {suffix}",
                "unique_id": unique_id,
                "state_topic": state_topic,
                "value_template": eff_tpl,
                "unit_of_measurement": eff_unit,
                "state_class": state_class,
                "device": ha_device_block,
            }
            if dev_class:
                config_payload["device_class"] = dev_class
            if is_ble and json_key in ("distance_m", "rssi"):
                config_payload["expire_after"] = 120

            self._client.publish(
                config_topic,
                payload=json.dumps(config_payload, ensure_ascii=False),
                qos=1,
                retain=True,
            )
            published_topics.append(config_topic)

        if is_ble:
            recently_seen = True
            last_seen_str = str(device.get("last_seen") or "").strip()
            if last_seen_str:
                try:
                    dt_seen = datetime.fromisoformat(last_seen_str.replace("Z", "+00:00"))
                    if dt_seen.tzinfo is None:
                        dt_seen = dt_seen.replace(tzinfo=timezone.utc)
                    age_sec = (datetime.now(timezone.utc) - dt_seen).total_seconds()
                    if age_sec > 120.0:
                        recently_seen = False
                except Exception:
                    recently_seen = True

            if recently_seen:
                with self._lock:
                    self._ble_presence_state[safe_device_key] = {
                        "last_seen_mono": time.monotonic(),
                        "is_home": True,
                        "state_topic": state_topic,
                        "base_topic": base_topic,
                        "device_key": device.get("device_key") or safe_device_key,
                    }
                self.publish_signal(device, payload)
            else:
                with self._lock:
                    self._ble_presence_state[safe_device_key] = {
                        "last_seen_mono": 0.0,
                        "is_home": False,
                        "state_topic": state_topic,
                        "base_topic": base_topic,
                        "device_key": device.get("device_key") or safe_device_key,
                    }
                away_payload = json.dumps(
                    {
                        "status": "not_home",
                        "presence": "OFF",
                        "device_key": device.get("device_key") or safe_device_key,
                    },
                    ensure_ascii=False,
                )
                try:
                    self._client.publish(state_topic, payload=away_payload, qos=0, retain=False)
                    self._client.publish(base_topic, payload=away_payload, qos=0, retain=False)
                except Exception:
                    pass
        else:
            self.publish_signal(device, payload)

        return {
            "ok": True,
            "device_key": safe_device_key,
            "published_count": len(published_topics),
            "published_topics": published_topics,
        }

    def clear_ha_discovery(self, device: Dict[str, Any]) -> Dict[str, Any]:
        """
        Clears Home Assistant MQTT Auto-Discovery configurations for a device by publishing
        an empty payload ("") with retain=True to all discovery topics for that device.
        """
        if not self._enabled or not self._connected or self._client is None:
            return {"ok": False, "cleared_topics": []}

        safe_device_key = sanitize_topic_segment(device.get("device_key", "unknown"))
        with self._lock:
            self._ble_presence_state.pop(safe_device_key, None)

        cleared_topics: List[str] = []
        extra_topics = [
            f"{self._ha_discovery_prefix}/binary_sensor/{safe_device_key}/presence/config",
            f"{self._ha_discovery_prefix}/binary_sensor/{safe_device_key}/battery_low/config",
            f"{self._ha_discovery_prefix}/binary_sensor/sensor_scanner_{safe_device_key}_battery_low/config",
            f"{self._ha_discovery_prefix}/device_tracker/{safe_device_key}/config",
            f"{self._ha_discovery_prefix}/sensor/sensor_scanner_{safe_device_key}_vehicle_status/config",
            f"{self._ha_discovery_prefix}/sensor/{safe_device_key}/vehicle_status/config",
            f"{self._ha_discovery_prefix}/sensor/sensor_scanner_{safe_device_key}_battery/config",
            f"{self._ha_discovery_prefix}/sensor/sensor_scanner_{safe_device_key}_battery_ok/config",
            f"{self._ha_discovery_prefix}/sensor/sensor_scanner_{safe_device_key}_battery_pct/config",
            f"{self._ha_discovery_prefix}/sensor/sensor_scanner_{safe_device_key}_battery_mv/config",
            f"{self._ha_discovery_prefix}/sensor/{safe_device_key}/battery_ok/config",
            f"{self._ha_discovery_prefix}/sensor/{safe_device_key}/battery/config",
            f"{self._ha_discovery_prefix}/sensor/{safe_device_key}/battery_pct/config",
            f"{self._ha_discovery_prefix}/sensor/{safe_device_key}/battery_mv/config",
            f"{self._ha_discovery_prefix}/sensor/{safe_device_key}/battery_mV/config",
        ]
        for topic in extra_topics:
            try:
                self._client.publish(topic, payload="", qos=1, retain=True)
                cleared_topics.append(topic)
            except Exception as exc:
                logger.debug("Failed to clear discovery topic %s: %s", topic, exc)

        for _, metric_slug, _, _, _, _, _ in HA_METRIC_SPECS:
            unique_id = f"sensor_scanner_{safe_device_key}_{metric_slug}"
            config_topic = f"{self._ha_discovery_prefix}/sensor/{unique_id}/config"
            try:
                self._client.publish(config_topic, payload="", qos=1, retain=True)
                cleared_topics.append(config_topic)
            except Exception as exc:
                logger.debug("Failed to clear discovery topic %s: %s", config_topic, exc)

        return {
            "ok": True,
            "device_key": safe_device_key,
            "cleared_count": len(cleared_topics),
            "cleared_topics": cleared_topics,
        }
