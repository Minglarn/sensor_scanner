import json
import logging
import re
import threading
from typing import Any, Callable, Dict, List, Optional

import paho.mqtt.client as mqtt

from app import __version__

logger = logging.getLogger("sensor_scanner.mqtt")


def sanitize_topic_segment(value: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9_\-]", "_", str(value or "").strip())
    cleaned = re.sub(r"_+", "_", cleaned).strip("_")
    return cleaned or "unknown"


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
        self._last_error: str = ""
        self._published_count: int = 0
        self._status_callback = status_callback

    def configure_and_connect(self, settings: Dict[str, Any]) -> None:
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

            self.disconnect()

            if not self._enabled or not self._host:
                self._connected = False
                self._last_error = "" if not self._enabled else "MQTT host saknas"
                self._notify_status()
                return

            try:
                client = mqtt.Client(
                    callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
                    client_id=f"sensor_scanner_{ sanitize_topic_segment(self._prefix) }",
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
        alias_raw = str(device.get("alias", "") or "").strip()

        enriched_payload = dict(payload)
        if alias_raw:
            enriched_payload["alias"] = alias_raw
        enriched_payload["device_key"] = device.get("device_key")

        json_str = json.dumps(enriched_payload, ensure_ascii=False)
        base_topic = f"{self._prefix}/{model_seg}/{id_seg}"

        try:
            self._client.publish(base_topic, payload=json_str, qos=0, retain=False)
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

    def publish_ha_discovery(self, device: Dict[str, Any]) -> Dict[str, Any]:
        """
        Publishes Home Assistant MQTT Auto-Discovery configurations for all detected metrics
        in the device's last_payload.
        Topic format: homeassistant/sensor/sensor_scanner_<device_key>_<metric>/config
        """
        if not self._enabled or not self._connected or self._client is None:
            return {
                "ok": False,
                "error": "MQTT är inte ansluten. Kontrollera MQTT-inställningarna under System & Logg.",
                "published_topics": [],
            }

        device_key = sanitize_topic_segment(device.get("device_key", "unknown"))
        model = str(device.get("model", "Unknown"))
        device_id = str(device.get("device_id", "unknown"))
        alias = str(device.get("alias", "") or "").strip()
        display_name = alias if alias else f"{model} {device_id}"

        model_seg = sanitize_topic_segment(model)
        id_seg = sanitize_topic_segment(device_id)
        state_topic = f"{self._prefix}/{model_seg}/{id_seg}"

        payload = device.get("last_payload") or {}
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except Exception:
                payload = {}

        # Metric definitions: (json_key, metric_slug, friendly_suffix, unit, device_class, state_class, value_template)
        metric_specs = [
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
                "°F",
                "temperature",
                "measurement",
                "{{ value_json.temperature_F | float | round(1) }}",
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
                "battery_ok",
                "battery",
                "Batteri",
                "%",
                "battery",
                "measurement",
                "{{ 100 if value_json.battery_ok | int == 1 else 10 }}",
            ),
            (
                "pressure_kPa",
                "pressure_kpa",
                "Tryck",
                "kPa",
                "pressure",
                "measurement",
                "{{ value_json.pressure_kPa | float | round(1) }}",
            ),
            (
                "pressure_bar",
                "pressure_bar",
                "Tryck",
                "bar",
                "pressure",
                "measurement",
                "{{ value_json.pressure_bar | float | round(2) }}",
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
                "energy_kWh",
                "energy",
                "Energi",
                "kWh",
                "energy",
                "total_increasing",
                "{{ value_json.energy_kWh | float | round(3) }}",
            ),
            (
                "wind_avg_km_h",
                "wind_speed",
                "Vindhastighet",
                "km/h",
                "wind_speed",
                "measurement",
                "{{ value_json.wind_avg_km_h | float | round(1) }}",
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

        ha_device_block = {
            "identifiers": [f"sensor_scanner_{device_key}"],
            "name": display_name,
            "model": model,
            "manufacturer": "rtl_433 / SensorScanner",
            "sw_version": __version__,
        }

        published_topics: List[str] = []

        for json_key, metric_slug, suffix, unit, dev_class, state_class, val_tpl in metric_specs:
            if json_key not in payload or payload[json_key] is None:
                continue

            unique_id = f"sensor_scanner_{device_key}_{metric_slug}"
            config_topic = f"homeassistant/sensor/{unique_id}/config"

            config_payload: Dict[str, Any] = {
                "name": f"{display_name} {suffix}",
                "unique_id": unique_id,
                "state_topic": state_topic,
                "value_template": val_tpl,
                "unit_of_measurement": unit,
                "state_class": state_class,
                "device": ha_device_block,
            }
            if dev_class:
                config_payload["device_class"] = dev_class

            self._client.publish(
                config_topic,
                payload=json.dumps(config_payload, ensure_ascii=False),
                qos=1,
                retain=True,
            )
            published_topics.append(config_topic)

        # Also publish current payload once so HA immediately gets state values
        self.publish_signal(device, payload)

        return {
            "ok": True,
            "device_key": device_key,
            "published_count": len(published_topics),
            "published_topics": published_topics,
        }
