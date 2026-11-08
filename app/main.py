import asyncio
import json
import logging
import os
import subprocess
import time
import urllib.request
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
from zoneinfo import ZoneInfo

from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from app import __app_name__, __version__
from app.ble_manager import BLEManager
from app.database import Database, extract_device_id, sanitize_key
from app.mqtt_client import MQTTManager
from app.rtl_manager import RTLManager

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logging.getLogger("uvicorn.access").disabled = True
logging.getLogger("uvicorn.access").propagate = False
logger = logging.getLogger("sensor_scanner.main")


class ConnectionManager:
    def __init__(self) -> None:
        self.active_connections: Set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        async with self._lock:
            self.active_connections.add(websocket)

    async def disconnect(self, websocket: WebSocket) -> None:
        async with self._lock:
            self.active_connections.discard(websocket)

    async def broadcast(self, message: Dict[str, Any]) -> None:
        async with self._lock:
            targets = list(self.active_connections)
        if not targets:
            return
        dead: List[WebSocket] = []
        for ws in targets:
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(ws)
        if dead:
            async with self._lock:
                for ws in dead:
                    self.active_connections.discard(ws)


ws_manager = ConnectionManager()
db = Database()
main_loop: Optional[asyncio.AbstractEventLoop] = None
APP_STARTED_AT = time.time()


try:
    LOCAL_TZ = ZoneInfo("Europe/Stockholm")
except Exception:
    LOCAL_TZ = datetime.now(timezone.utc).astimezone().tzinfo  # type: ignore[assignment]


def parse_and_format_local(iso_str: str) -> Tuple[Optional[datetime], str]:
    if not iso_str or iso_str == "unknown":
        return None, "Okänt datum"
    try:
        dt = datetime.fromisoformat(str(iso_str).strip().replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        local_dt = dt.astimezone(LOCAL_TZ)
        return local_dt, local_dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return None, str(iso_str)[:19].replace("T", " ")


def _resolve_local_git_commit() -> str:
    env_sha = (os.getenv("GIT_COMMIT", "unknown") or "unknown").strip()
    if env_sha and env_sha.lower() != "unknown":
        return env_sha[:7]
    try:
        out = subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            stderr=subprocess.DEVNULL,
            timeout=3.0,
        )
        sha = out.decode("utf-8", errors="ignore").strip()
        if sha:
            return sha[:7]
    except Exception:
        pass
    return "unknown"


def _resolve_local_build_date_raw() -> str:
    env_date = (os.getenv("BUILD_DATE", "unknown") or "unknown").strip()
    if env_date and env_date.lower() != "unknown":
        return env_date
    try:
        out = subprocess.check_output(
            ["git", "log", "-1", "--format=%cI"],
            cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            stderr=subprocess.DEVNULL,
            timeout=3.0,
        )
        c_date = out.decode("utf-8", errors="ignore").strip()
        if c_date:
            return c_date
    except Exception:
        pass
    try:
        mtime = os.path.getmtime(os.path.abspath(__file__))
        return datetime.fromtimestamp(mtime, tz=timezone.utc).astimezone(LOCAL_TZ).isoformat()
    except Exception:
        return "unknown"


LOCAL_GIT_COMMIT = _resolve_local_git_commit()
LOCAL_BUILD_DT, LOCAL_BUILD_DATE = parse_and_format_local(_resolve_local_build_date_raw())
REMOTE_COMMIT_DT: Optional[datetime] = None
GITHUB_COMMITS_URL = "https://api.github.com/repos/Minglarn/sensor_scanner/commits/main"

_version_cache: Dict[str, Any] = {
    "local_sha": LOCAL_GIT_COMMIT,
    "build_date": LOCAL_BUILD_DATE,
    "remote_sha": LOCAL_GIT_COMMIT if LOCAL_GIT_COMMIT != "unknown" else "",
    "commit_message": "",
    "commit_date": "",
    "update_available": False,
    "recent_commit": False,
    "checked_at": 0.0,
    "error": "",
}


def _fetch_github_latest_sync() -> Dict[str, Any]:
    import ssl

    req = urllib.request.Request(
        GITHUB_COMMITS_URL,
        headers={
            "User-Agent": "SensorScanner-Updater",
            "Accept": "application/vnd.github.v3+json",
        },
    )
    try:
        resp_ctx = urllib.request.urlopen(req, timeout=8.0)
    except Exception:
        unverified = ssl._create_unverified_context()
        resp_ctx = urllib.request.urlopen(req, timeout=8.0, context=unverified)
    with resp_ctx as resp:
        raw = resp.read().decode("utf-8", errors="replace")
        data = json.loads(raw)
        remote_sha = str(data.get("sha") or "")[:7]
        commit_obj = data.get("commit") or {}
        raw_msg = str(commit_obj.get("message") or "")
        commit_message = raw_msg.split("\n")[0].strip()
        committer_obj = commit_obj.get("committer") or {}
        commit_date = str(committer_obj.get("date") or "")
        return {
            "remote_sha": remote_sha,
            "commit_message": commit_message,
            "commit_date": commit_date,
        }


async def check_github_updates(force: bool = False) -> Dict[str, Any]:
    global REMOTE_COMMIT_DT
    now = time.time()
    if not force and _version_cache["checked_at"] > 0 and (now - _version_cache["checked_at"]) < 600.0:
        if REMOTE_COMMIT_DT is not None:
            now_dt = datetime.now(LOCAL_TZ)
            _version_cache["recent_commit"] = bool(0 <= (now_dt - REMOTE_COMMIT_DT).total_seconds() < 120.0)
        return dict(_version_cache)

    try:
        latest = await asyncio.to_thread(_fetch_github_latest_sync)
        remote_sha = latest.get("remote_sha", "")
        local_sha = _version_cache["local_sha"]
        remote_dt, remote_date_str = parse_and_format_local(latest.get("commit_date", ""))
        REMOTE_COMMIT_DT = remote_dt

        if not local_sha or local_sha == "unknown" or not remote_sha or remote_sha == local_sha:
            update_available = False
        elif LOCAL_BUILD_DT is not None and remote_dt is not None:
            update_available = bool(remote_dt > LOCAL_BUILD_DT)
        else:
            update_available = True

        now_dt = datetime.now(LOCAL_TZ)
        recent_commit = bool(remote_dt is not None and 0 <= (now_dt - remote_dt).total_seconds() < 120.0)

        _version_cache.update(
            {
                "remote_sha": remote_sha,
                "commit_message": latest.get("commit_message", ""),
                "commit_date": remote_date_str,
                "update_available": update_available,
                "recent_commit": recent_commit,
                "checked_at": now,
                "error": "",
            }
        )
    except Exception as exc:
        logger.debug("GitHub version check failed: %s", exc)
        _version_cache["checked_at"] = now
        _version_cache["error"] = str(exc)

    return dict(_version_cache)


_last_logged_mqtt_state: Optional[bool] = None
_last_logged_rtl_state: Optional[str] = None
_last_logged_ble_state: Optional[str] = None


def _on_mqtt_status_threadsafe(mqtt_status: Dict[str, Any]) -> None:
    global _last_logged_mqtt_state
    conn_state = bool(mqtt_status.get("connected"))
    if _last_logged_mqtt_state != conn_state:
        _last_logged_mqtt_state = conn_state
        if conn_state:
            print(f"[SYSTEM] MQTT connected to {mqtt_status.get('host')}:{mqtt_status.get('port')}", flush=True)
        elif mqtt_status.get("enabled"):
            print(f"[SYSTEM] MQTT disconnected ({mqtt_status.get('last_error') or 'offline'})", flush=True)
    if main_loop and main_loop.is_running():
        asyncio.run_coroutine_threadsafe(broadcast_full_status(), main_loop)


mqtt_manager = MQTTManager(status_callback=_on_mqtt_status_threadsafe)


def _log_signal_stdout(signal_rec: Dict[str, Any], device_rec: Dict[str, Any]) -> None:
    payload = signal_rec.get("payload") or {}
    model = str(signal_rec.get("model") or "Unknown")
    device_id = str(signal_rec.get("device_id") or "")
    alias = str(device_rec.get("alias") or "").strip()
    local_name = str(payload.get("local_name") or "").strip()
    freq = signal_rec.get("freq")
    mod = str(payload.get("mod") or "").upper()
    rssi = signal_rec.get("rssi")

    is_ble = mod == "BLE" or (freq is not None and float(freq) >= 2400.0) or "BLE" in model
    band_str = "2.4 GHz BLE" if is_ble else (f"{float(freq):.2f} MHz" if freq is not None else "RF")
    rssi_str = (
        f"RSSI: {int(round(float(rssi)))} dBm"
        if (rssi is not None and is_ble)
        else (f"RSSI: {float(rssi):.1f} dB" if rssi is not None else "RSSI: -")
    )

    is_brand_new = bool(device_rec.get("is_brand_new"))
    if is_brand_new:
        label = f"{local_name} ({model}, ID: {device_id})" if (local_name and local_name != model) else f"{model} (ID: {device_id})"
        print(f"[NEW DEVICE] {band_str} | {label} | {rssi_str}", flush=True)
        return

    # Skip passive BLE beacons without telemetry
    if payload.get("is_beacon_only") is True:
        return

    metrics: List[str] = []
    temp_c = signal_rec.get("temperature_c")
    if temp_c is not None:
        metrics.append(f"{float(temp_c):.1f}°C")
    hum = signal_rec.get("humidity")
    if hum is not None:
        metrics.append(f"{int(round(float(hum)))}%")
    power_w = payload.get("power_W") or payload.get("calculated_power_W")
    if power_w is not None:
        metrics.append(f"{power_w} W")
    kwh = payload.get("cumulative_kwh") or payload.get("energy_kWh")
    if kwh is not None:
        metrics.append(f"{kwh} kWh")
    press = payload.get("pressure_hPa") or payload.get("pressure_kPa")
    if press is not None:
        unit = "hPa" if payload.get("pressure_hPa") is not None else "kPa"
        metrics.append(f"{press} {unit}")
    bat_pct = payload.get("battery_pct")
    if bat_pct is not None:
        metrics.append(f"Batt: {int(round(float(bat_pct)))}%")
    elif signal_rec.get("battery_ok") is not None:
        metrics.append(f"Batt: {'OK' if int(signal_rec['battery_ok']) == 1 else 'LOW'}")
    if model == "Tesla-Vehicle-BLE":
        metrics.append("VCSEC • Verifierat VIN" if payload.get("is_own_vehicle") is True else "VCSEC • Inom räckvidd")
    elif payload.get("vehicle_status"):
        metrics.append(str(payload.get("vehicle_status")))
    if not metrics and not is_ble:
        state_val = payload.get("state") or payload.get("cmd") or payload.get("button")
        if state_val is not None:
            metrics.append(f"State: {state_val}")

    if not metrics and is_ble:
        return

    if alias:
        name_part = f"{alias} ({model})"
    elif local_name and local_name != model:
        name_part = f"{local_name} ({model})"
    else:
        name_part = f"{model} (ID: {device_id})"

    metrics_str = ", ".join(metrics)
    if metrics_str:
        print(f"[UPDATE] {band_str} | {name_part} | {metrics_str} | {rssi_str}", flush=True)
    else:
        print(f"[UPDATE] {band_str} | {name_part} | {rssi_str}", flush=True)


async def on_rtl_signal(payload: Dict[str, Any]) -> None:
    signal_rec, device_rec = await asyncio.to_thread(db.record_signal, payload)

    if signal_rec is None:
        return

    _log_signal_stdout(signal_rec, device_rec)
    await asyncio.to_thread(mqtt_manager.publish_signal, device_rec, signal_rec["payload"])
    counts = await asyncio.to_thread(db.get_summary_counts)

    await ws_manager.broadcast(
        {
            "type": "signal",
            "data": signal_rec,
            "device": device_rec,
            "counts": counts,
            "total_signals_count": counts.get("signals_today", 0),
            "total_devices_count": counts.get("active_devices", 0),
        }
    )


async def on_rtl_status_change(rtl_status: Dict[str, Any]) -> None:
    global _last_logged_rtl_state
    st_key = f"{rtl_status.get('state')}:{rtl_status.get('mode')}:{rtl_status.get('current_tuned_freq')}"
    if _last_logged_rtl_state != st_key:
        _last_logged_rtl_state = st_key
        print(
            f"[SYSTEM] SDR state={rtl_status.get('state')} mode={rtl_status.get('mode')} freq={rtl_status.get('current_tuned_freq')}",
            flush=True,
        )
    await broadcast_full_status()


async def on_rtl_stderr_line(line: str) -> None:
    await ws_manager.broadcast(
        {
            "type": "stderr",
            "line": line,
            "last_error": rtl_manager.get_status().get("last_error", ""),
        }
    )


async def on_rtl_freq_change(freq_state: Dict[str, Any]) -> None:
    await ws_manager.broadcast(
        {
            "type": "sdr_hop",
            "freq": freq_state.get("current_tuned_freq", "433.92 MHz"),
            "remaining": freq_state.get("remaining", 60),
            **freq_state,
        }
    )


rtl_manager = RTLManager(
    get_settings_fn=db.get_settings,
    on_signal_fn=on_rtl_signal,
    on_status_change_fn=on_rtl_status_change,
    on_stderr_line_fn=on_rtl_stderr_line,
    on_freq_change_fn=on_rtl_freq_change,
)


async def on_ble_status_change(ble_status: Dict[str, Any]) -> None:
    global _last_logged_ble_state
    st_key = f"{ble_status.get('state')}:{ble_status.get('mode')}"
    if _last_logged_ble_state != st_key:
        _last_logged_ble_state = st_key
        print(
            f"[SYSTEM] BLE state={ble_status.get('state')} mode={ble_status.get('mode')}",
            flush=True,
        )
    await broadcast_full_status()


def on_ble_beacon_seen(payload: Dict[str, Any]) -> bool:
    exists = db.touch_beacon_device(payload)
    if exists:
        try:
            model = str(payload.get("model") or "Unknown").strip()
            device_id = extract_device_id(payload)
            dev_key = f"{sanitize_key(model)}_{sanitize_key(device_id)}"
            dev_rec = db.get_device(dev_key)
            if dev_rec and int(dev_rec.get("ignored") or 0) == 0:
                if (
                    int(dev_rec.get("ha_discovery") or 0) == 1
                    and int(dev_rec.get("mqtt_enabled", 1)) == 1
                ):
                    mqtt_manager.publish_signal(dev_rec, payload)
                has_name = bool((dev_rec.get("alias") or "").strip()) or bool((payload.get("local_name") or "").strip())
                if has_name and main_loop and main_loop.is_running():
                    asyncio.run_coroutine_threadsafe(
                        ws_manager.broadcast({"type": "device_updated", "device": dev_rec}),
                        main_loop,
                    )
        except Exception as exc:
            logger.debug("Error forwarding beacon MQTT heartbeat: %s", exc)
    return exists


async def on_ble_oui_resolved(oui: str, vendor: str) -> None:
    try:
        await asyncio.to_thread(db.set_oui_vendor, oui, vendor)
        updated_devs = await asyncio.to_thread(
            db.merge_device_payload_by_mac, oui, {"mac_vendor": vendor}
        )
        if updated_devs:
            await ws_manager.broadcast({"type": "devices_bulk_updated", "devices": updated_devs})
    except Exception as exc:
        logger.debug("Error persisting OUI vendor %s=%s: %s", oui, vendor, exc)


ble_manager = BLEManager(
    get_settings_fn=db.get_settings,
    is_known_aliased_fn=db.is_device_known_and_named,
    on_signal_fn=on_rtl_signal,
    on_status_change_fn=on_ble_status_change,
    on_log_line_fn=on_rtl_stderr_line,
    on_beacon_seen_fn=on_ble_beacon_seen,
    get_oui_cache_fn=db.get_oui_cache,
    on_oui_resolved_fn=on_ble_oui_resolved,
)


def build_status_payload() -> Dict[str, Any]:
    counts = db.get_summary_counts()
    rtl_st = rtl_manager.get_status()
    ble_st = ble_manager.get_status()
    mqtt_st = mqtt_manager.get_status()
    return {
        "app_name": __app_name__,
        "version": __version__,
        "git_version": dict(_version_cache),
        "app_uptime_seconds": int(max(0.0, time.time() - APP_STARTED_AT)),
        "rtl": rtl_st,
        "ble": ble_st,
        "mqtt": mqtt_st,
        "counts": counts,
    }


async def broadcast_full_status() -> None:
    status_data = await asyncio.to_thread(build_status_payload)
    await ws_manager.broadcast({"type": "status", "data": status_data})


async def retention_worker() -> None:
    while True:
        try:
            await asyncio.to_thread(db.run_retention_cleanup)
        except Exception as exc:
            logger.error("Error in retention cleanup task: %s", exc)
        await asyncio.sleep(86400)


async def auto_prune_worker() -> None:
    """
    Runs automatic database pruning on startup and every hour (3600s) for:
    - Passing/ephemeral unknown devices (hit_count <= 10, older than prune_ephemeral_hours)
    - Stale/inactive unknown devices (older than prune_stale_days)
    - Orphaned signal rows and excess history rows (> max_signals_per_device)
    Protected devices (with alias, group_name, ha_discovery=1, or ignored=1) are NEVER touched.
    """
    await asyncio.sleep(5)
    while True:
        try:
            res = await asyncio.to_thread(db.auto_prune_database)
            pruned_items = res.get("pruned_items") or []
            for _dk, mod, did in pruned_items:
                ble_manager.evict_device(str(mod), str(did))
                rtl_manager.evict_device(str(mod), str(did))
            pruned_keys = res.get("pruned_keys") or []
            if pruned_keys or int(res.get("signals_deleted") or 0) > 0:
                if pruned_keys:
                    print(
                        f"[AUTO-PRUNE] Rensade {len(pruned_keys)} tillfälliga/inaktiva enheter och {res.get('signals_deleted', 0)} historikrader",
                        flush=True,
                    )
                    await ws_manager.broadcast({"type": "devices_pruned", "device_keys": pruned_keys})
                await broadcast_full_status()
        except Exception as exc:
            logger.error("Error in auto_prune_worker: %s", exc)
        await asyncio.sleep(3600)


async def new_device_expiry_worker() -> None:
    while True:
        try:
            changed = await asyncio.to_thread(db.expire_new_devices)
            if changed > 0:
                await broadcast_full_status()
        except Exception as exc:
            logger.debug("Error in new_device_expiry_worker: %s", exc)
        await asyncio.sleep(60)


async def ble_presence_timeout_worker() -> None:
    ha_synced_on_connect = False
    while True:
        try:
            mqtt_st = mqtt_manager.get_status()
            if mqtt_st.get("connected"):
                if not ha_synced_on_connect:
                    devices = await asyncio.to_thread(db.get_devices, include_ignored=False)
                    synced_count = 0
                    for d in devices:
                        if int(d.get("ha_discovery") or 0) == 1:
                            await asyncio.to_thread(mqtt_manager.publish_ha_discovery, d)
                            synced_count += 1
                    if synced_count > 0:
                        print(f"[SYSTEM] Synced HA Auto-Discovery for {synced_count} devices", flush=True)
                    ha_synced_on_connect = True
                await asyncio.to_thread(mqtt_manager.check_ble_presence_timeouts, 120.0)
            else:
                ha_synced_on_connect = False
        except Exception as exc:
            logger.debug("Error in ble_presence_timeout_worker: %s", exc)
        await asyncio.sleep(2 if not ha_synced_on_connect else 30)


async def github_update_worker() -> None:
    await asyncio.sleep(3)
    while True:
        try:
            prev_avail = _version_cache.get("update_available")
            prev_remote = _version_cache.get("remote_sha")
            res = await check_github_updates(force=True)
            if res.get("update_available") and (not prev_avail or res.get("remote_sha") != prev_remote):
                print(
                    f"[SYSTEM] GitHub update available: {res.get('remote_sha')} - {res.get('commit_message')}",
                    flush=True,
                )
            if res.get("update_available") != prev_avail or res.get("remote_sha") != prev_remote:
                await broadcast_full_status()
        except Exception as exc:
            logger.debug("Error in github_update_worker: %s", exc)
        await asyncio.sleep(600)


async def oui_backfill_worker() -> None:
    """
    One-shot startup task that resolves IEEE OUI hardware vendors for any existing
    BLE devices in SQLite with 'IEEE Public (Fast)' MAC addresses that lack mac_vendor.
    """
    await asyncio.sleep(2)
    try:
        devices = await asyncio.to_thread(db.get_devices, include_ignored=True)
        unique_ouis: Set[str] = set()
        for d in devices:
            pl = d.get("last_payload") or {}
            mac = str(pl.get("mac") or "").strip().upper()
            if (
                len(mac) >= 8
                and pl.get("mac_type") == "IEEE Public (Fast)"
                and not pl.get("mac_vendor")
            ):
                unique_ouis.add(mac[:8])
        for oui in sorted(unique_ouis):
            await ble_manager.resolve_oui_vendor(oui)
            await asyncio.sleep(1.1)
    except Exception as exc:
        logger.debug("Error in oui_backfill_worker: %s", exc)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global main_loop
    main_loop = asyncio.get_running_loop()

    await asyncio.to_thread(db.expire_new_devices)
    settings = db.get_settings()
    mqtt_manager.configure_and_connect(settings)
    await rtl_manager.start()
    await ble_manager.start()
    retention_task = asyncio.create_task(retention_worker(), name="retention_worker")
    auto_prune_task = asyncio.create_task(auto_prune_worker(), name="auto_prune_worker")
    expiry_task = asyncio.create_task(new_device_expiry_worker(), name="new_device_expiry_worker")
    presence_task = asyncio.create_task(ble_presence_timeout_worker(), name="ble_presence_timeout_worker")
    update_task = asyncio.create_task(github_update_worker(), name="github_update_worker")
    oui_task = asyncio.create_task(oui_backfill_worker(), name="oui_backfill_worker")

    try:
        yield
    finally:
        oui_task.cancel()
        update_task.cancel()
        presence_task.cancel()
        expiry_task.cancel()
        auto_prune_task.cancel()
        retention_task.cancel()
        for t in (oui_task, update_task, presence_task, expiry_task, auto_prune_task, retention_task):
            try:
                await t
            except asyncio.CancelledError:
                pass
        await ble_manager.stop()
        await rtl_manager.stop()
        mqtt_manager.disconnect()


app = FastAPI(
    title=__app_name__,
    version=__version__,
    description="Dockeriserad RTL-SDR Blog V4 & rtl_433 RF-signalmottagare med FastAPI, SQLite och MQTT.",
    lifespan=lifespan,
)

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


# ==============================================================================
# Pydantic Schemas
# ==============================================================================
class ControlRequest(BaseModel):
    action: Optional[str] = None
    mode: Optional[str] = None
    device_index: Optional[str] = None
    gain: Optional[str] = None
    ppm: Optional[str] = None
    hop_interval: Optional[str] = None
    custom_freqs: Optional[str] = None
    custom_sample_rate: Optional[str] = None
    ble_enabled: Optional[str] = None
    ble_mode: Optional[str] = None
    ble_debounce_seconds: Optional[str] = None
    tesla_vin: Optional[str] = None


class DeviceUpdateRequest(BaseModel):
    alias: Optional[str] = None
    group_name: Optional[str] = None
    category: Optional[str] = None
    mqtt_enabled: Optional[int] = None
    ha_discovery: Optional[int] = None
    ignored: Optional[int] = None


class BulkGroupRequest(BaseModel):
    device_keys: List[str]
    group_name: Optional[str] = None
    category: Optional[str] = None
    ignored: Optional[int] = None


class DatabaseResetRequest(BaseModel):
    keep_aliases: bool = False


class DbMaintenanceRequest(BaseModel):
    action: str


class SettingsUpdateRequest(BaseModel):
    device_index: Optional[str] = None
    mode: Optional[str] = None
    custom_freqs: Optional[str] = None
    custom_sample_rate: Optional[str] = None
    hop_interval: Optional[str] = None
    gain: Optional[str] = None
    ppm: Optional[str] = None
    debounce_seconds: Optional[str] = None
    ble_enabled: Optional[str] = None
    ble_mode: Optional[str] = None
    ble_debounce_seconds: Optional[str] = None
    tesla_vin: Optional[str] = None
    retention_days: Optional[str] = None
    prune_ephemeral_hours: Optional[str] = None
    prune_stale_days: Optional[str] = None
    max_signals_per_device: Optional[str] = None
    mqtt_enabled: Optional[str] = None
    mqtt_host: Optional[str] = None
    mqtt_port: Optional[str] = None
    mqtt_user: Optional[str] = None
    mqtt_pass: Optional[str] = None
    mqtt_prefix: Optional[str] = None
    ha_discovery_enabled: Optional[str] = None
    ha_discovery_prefix: Optional[str] = None


# ==============================================================================
# Routes
# ==============================================================================
@app.get("/", include_in_schema=False)
async def serve_spa():
    return FileResponse(
        os.path.join(STATIC_DIR, "index.html"),
        headers={
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Pragma": "no-cache",
            "Expires": "0",
        },
    )


@app.get("/manifest.json", include_in_schema=False)
async def serve_manifest():
    return FileResponse(os.path.join(STATIC_DIR, "manifest.json"), media_type="application/manifest+json")


@app.get("/sw.js", include_in_schema=False)
async def serve_service_worker():
    return FileResponse(
        os.path.join(STATIC_DIR, "sw.js"),
        media_type="application/javascript",
        headers={"Service-Worker-Allowed": "/", "Cache-Control": "no-cache"},
    )


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        initial_status = await asyncio.to_thread(build_status_payload)
        await websocket.send_json({"type": "status", "data": initial_status})
        while True:
            msg = await websocket.receive_text()
            if msg == "ping":
                await websocket.send_json({"type": "pong"})
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        await ws_manager.disconnect(websocket)


@app.get("/api/status")
async def api_get_status():
    return await asyncio.to_thread(build_status_payload)


@app.get("/api/version")
async def api_get_version(force: bool = Query(False)):
    info = await check_github_updates(force=force)
    if force:
        await broadcast_full_status()
    return {
        "version": __version__,
        **info,
    }


@app.post("/api/control")
async def api_control(req: ControlRequest):
    updates: Dict[str, str] = {}
    sdr_touched = False
    ble_touched = False
    if req.mode is not None:
        if req.mode not in ("433", "868", "hop", "custom"):
            raise HTTPException(status_code=400, detail="Ogiltigt frekvensläge. Tillåtna: 433, 868, hop, custom.")
        updates["mode"] = req.mode
        sdr_touched = True
    if req.device_index is not None:
        updates["device_index"] = str(req.device_index).strip()
        sdr_touched = True
    if req.gain is not None:
        updates["gain"] = str(req.gain).strip() or "auto"
        sdr_touched = True
    if req.ppm is not None:
        updates["ppm"] = str(req.ppm).strip() or "0"
        sdr_touched = True
    if req.hop_interval is not None:
        updates["hop_interval"] = str(req.hop_interval).strip() or "60"
        sdr_touched = True
    if req.custom_freqs is not None:
        updates["custom_freqs"] = str(req.custom_freqs).strip()
        sdr_touched = True
    if req.custom_sample_rate is not None:
        updates["custom_sample_rate"] = str(req.custom_sample_rate).strip()
        sdr_touched = True
    if req.ble_enabled is not None:
        updates["ble_enabled"] = "1" if str(req.ble_enabled).strip().lower() in ("1", "true", "yes", "on") else "0"
        ble_touched = True
    if req.ble_mode is not None:
        if req.ble_mode not in ("smart", "all"):
            raise HTTPException(status_code=400, detail="Ogiltigt BLE-läge. Tillåtna: smart, all.")
        updates["ble_mode"] = req.ble_mode
        ble_touched = True
    if req.ble_debounce_seconds is not None:
        updates["ble_debounce_seconds"] = str(req.ble_debounce_seconds).strip() or "15"
        ble_touched = True

    if updates:
        await asyncio.to_thread(db.update_settings, updates)

    if req.action == "restart_ble" or (ble_touched and not sdr_touched):
        await ble_manager.restart()
    elif req.action == "restart_all":
        await rtl_manager.restart()
        await ble_manager.restart()
    else:
        await rtl_manager.restart()
        if ble_touched:
            await ble_manager.restart()

    status = await asyncio.to_thread(build_status_payload)
    await ws_manager.broadcast({"type": "status", "data": status})
    return {"ok": True, "status": status}


@app.get("/api/signals")
async def api_get_signals(
    search: Optional[str] = Query(default=None),
    model: Optional[str] = Query(default=None),
    device_id: Optional[str] = Query(default=None),
    freq_band: Optional[str] = Query(default=None),
    only_aliased: bool = Query(default=False),
    unique_devices: bool = Query(default=True),
    limit: int = Query(default=5000, ge=1, le=10000),
    offset: int = Query(default=0, ge=0),
):
    return await asyncio.to_thread(
        db.get_signals,
        search=search,
        model=model,
        device_id=device_id,
        freq_band=freq_band,
        only_aliased=only_aliased,
        unique_devices=unique_devices,
        limit=limit,
        offset=offset,
    )


@app.get("/api/models")
async def api_get_models():
    models = await asyncio.to_thread(db.get_models)
    return {"models": models}


@app.get("/api/devices")
async def api_get_devices(
    search: Optional[str] = Query(default=None),
    include_ignored: bool = Query(default=True),
):
    devices = await asyncio.to_thread(db.get_devices, search=search, include_ignored=include_ignored)
    return {"devices": devices, "total": len(devices)}


@app.get("/api/devices/{device_key}")
async def api_get_device_detail(device_key: str):
    device = await asyncio.to_thread(db.get_device, device_key)
    if not device:
        raise HTTPException(status_code=404, detail="Enheten hittades inte.")
    history = await asyncio.to_thread(
        db.get_signals,
        model=device["model"],
        device_id=device["device_id"],
        unique_devices=False,
        limit=20,
        offset=0,
    )
    return {"device": device, "history": history["items"]}


@app.get("/api/devices/{device_key}/history")
async def api_get_device_history(device_key: str, limit: int = Query(default=20, ge=1, le=100)):
    device = await asyncio.to_thread(db.get_device, device_key)
    if not device:
        raise HTTPException(status_code=404, detail="Enheten hittades inte.")
    history = await asyncio.to_thread(
        db.get_signals,
        model=device["model"],
        device_id=device["device_id"],
        unique_devices=False,
        limit=limit,
        offset=0,
    )
    return {"device_key": device_key, "history": history["items"]}


@app.post("/api/devices/bulk_group")
async def api_bulk_group_devices(req: BulkGroupRequest):
    if not req.device_keys:
        raise HTTPException(status_code=400, detail="Inga enheter valda.")

    updated_devices = await asyncio.to_thread(
        db.bulk_update_devices,
        device_keys=req.device_keys,
        group_name=req.group_name,
        category=req.category,
        ignored=req.ignored,
    )
    await ws_manager.broadcast({"type": "devices_bulk_updated", "devices": updated_devices})
    await broadcast_full_status()
    return {"ok": True, "devices": updated_devices, "count": len(updated_devices)}


@app.put("/api/devices/{device_key}")
async def api_update_device(device_key: str, req: DeviceUpdateRequest):
    prev_device = await asyncio.to_thread(db.get_device, device_key)
    if not prev_device:
        raise HTTPException(status_code=404, detail="Enheten hittades inte.")

    updated = await asyncio.to_thread(
        db.update_device,
        device_key=device_key,
        alias=req.alias,
        group_name=req.group_name,
        category=req.category,
        mqtt_enabled=req.mqtt_enabled,
        ha_discovery=req.ha_discovery,
        ignored=req.ignored,
    )
    if not updated:
        raise HTTPException(status_code=404, detail="Enheten hittades inte.")

    # Handle HA Auto-Discovery publish or removal when ha_discovery flag changes
    if req.ha_discovery is not None:
        if int(bool(req.ha_discovery)) == 1:
            await asyncio.to_thread(mqtt_manager.publish_ha_discovery, updated)
        elif int(prev_device.get("ha_discovery", 0)) == 1 and int(bool(req.ha_discovery)) == 0:
            await asyncio.to_thread(mqtt_manager.clear_ha_discovery, updated)

    await ws_manager.broadcast({"type": "device_updated", "device": updated})
    await broadcast_full_status()
    return {"ok": True, "device": updated}


@app.post("/api/devices/{device_key}/ha_discovery")
async def api_ha_discovery(device_key: str):
    device = await asyncio.to_thread(db.get_device, device_key)
    if not device:
        raise HTTPException(status_code=404, detail="Enheten hittades inte.")

    result = await asyncio.to_thread(mqtt_manager.publish_ha_discovery, device)
    if not result.get("ok"):
        raise HTTPException(status_code=400, detail=result.get("error", "Kunde inte skicka HA Discovery."))

    updated = await asyncio.to_thread(db.update_device, device_key=device_key, ha_discovery=1)
    if updated:
        await ws_manager.broadcast({"type": "device_updated", "device": updated})
    return result


@app.post("/api/ble/inspect/{mac:path}")
async def api_inspect_ble_device(mac: str):
    res = await ble_manager.inspect_gatt_device(mac)
    persist_fields: Dict[str, Any] = {
        "gatt_connectable": res.get("connectable", False),
        "gatt_inspected_at": res.get("gatt_inspected_at"),
    }
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
        "mac_vendor",
    ):
        if res.get(k) is not None:
            persist_fields[k] = res[k]

    updated_devs = await asyncio.to_thread(
        db.merge_device_payload_by_mac, res.get("mac") or mac, persist_fields
    )
    if not updated_devs and mac != res.get("mac"):
        updated_devs = await asyncio.to_thread(
            db.merge_device_payload_by_mac, mac, persist_fields
        )

    for d in updated_devs:
        await ws_manager.broadcast({"type": "device_updated", "device": d})

    return {
        **res,
        "device": updated_devs[0] if updated_devs else None,
    }


@app.delete("/api/devices/{device_key:path}")
async def api_delete_device(device_key: str):
    device = await asyncio.to_thread(db.get_device, device_key)
    if device and int(device.get("ha_discovery", 0)) == 1:
        await asyncio.to_thread(mqtt_manager.clear_ha_discovery, device)

    deleted = await asyncio.to_thread(db.delete_device, device_key)
    if not deleted:
        raise HTTPException(status_code=404, detail="Enheten hittades inte.")

    if device:
        ble_manager.evict_device(str(device.get("model", "")), str(device.get("device_id", "")))
        rtl_manager.evict_device(str(device.get("model", "")), str(device.get("device_id", "")))

    await ws_manager.broadcast({"type": "device_deleted", "device_key": device_key})
    await broadcast_full_status()
    return {"ok": True, "device_key": device_key}


@app.get("/api/settings")
async def api_get_settings():
    settings = await asyncio.to_thread(db.get_settings)
    return {"settings": settings}


@app.put("/api/settings")
async def api_update_settings(req: SettingsUpdateRequest):
    old_settings = await asyncio.to_thread(db.get_settings)
    payload = {k: v for k, v in req.model_dump().items() if v is not None}
    if "tesla_vin" in payload:
        payload["tesla_vin"] = str(payload["tesla_vin"] or "").strip().upper()
    new_settings = await asyncio.to_thread(db.update_settings, payload)

    if old_settings.get("tesla_vin") != new_settings.get("tesla_vin"):
        updated_teslas = await asyncio.to_thread(
            db.apply_tesla_vin_matching, new_settings.get("tesla_vin", "")
        )
        if updated_teslas:
            await ws_manager.broadcast({"type": "devices_bulk_updated", "devices": updated_teslas})

    sdr_keys = ("device_index", "mode", "custom_freqs", "custom_sample_rate", "hop_interval", "gain", "ppm")
    ble_keys = ("ble_enabled", "ble_mode", "ble_debounce_seconds")
    mqtt_broker_keys = ("mqtt_enabled", "mqtt_host", "mqtt_port", "mqtt_user", "mqtt_pass", "mqtt_prefix")
    ha_keys = ("ha_discovery_enabled", "ha_discovery_prefix")

    sdr_changed = any(old_settings.get(k) != new_settings.get(k) for k in sdr_keys)
    ble_changed = any(old_settings.get(k) != new_settings.get(k) for k in ble_keys)
    mqtt_broker_changed = any(old_settings.get(k) != new_settings.get(k) for k in mqtt_broker_keys)
    ha_changed = any(old_settings.get(k) != new_settings.get(k) for k in ha_keys)

    # If HA Discovery was turned OFF globally, clear retained discovery topics for all enabled devices
    old_ha_en = str(old_settings.get("ha_discovery_enabled", "0")) in ("1", "true", "True")
    new_ha_en = str(new_settings.get("ha_discovery_enabled", "0")) in ("1", "true", "True")
    if old_ha_en and not new_ha_en:
        all_devs = await asyncio.to_thread(db.get_devices, include_ignored=True)
        for d in all_devs:
            if int(d.get("ha_discovery", 0)) == 1:
                await asyncio.to_thread(mqtt_manager.clear_ha_discovery, d)

    if mqtt_broker_changed or ha_changed:
        await asyncio.to_thread(
            mqtt_manager.configure_and_connect,
            new_settings,
            reconnect_broker=mqtt_broker_changed,
        )
        if new_ha_en and mqtt_manager.get_status().get("connected"):
            active_devs = await asyncio.to_thread(db.get_devices, include_ignored=False)
            for d in active_devs:
                if int(d.get("ha_discovery", 0)) == 1:
                    await asyncio.to_thread(mqtt_manager.publish_ha_discovery, d)

    if sdr_changed:
        await rtl_manager.restart()

    if ble_changed:
        await ble_manager.restart()

    if old_settings.get("retention_days") != new_settings.get("retention_days"):
        try:
            ret_days = int(new_settings.get("retention_days", "30"))
            await asyncio.to_thread(db.run_retention_cleanup, ret_days)
        except (ValueError, TypeError):
            pass

    prune_keys = ("prune_ephemeral_hours", "prune_stale_days", "max_signals_per_device")
    if any(old_settings.get(k) != new_settings.get(k) for k in prune_keys):
        try:
            prune_res = await asyncio.to_thread(db.auto_prune_database)
            for _dk, mod, did in prune_res.get("pruned_items") or []:
                ble_manager.evict_device(str(mod), str(did))
                rtl_manager.evict_device(str(mod), str(did))
            pruned_keys = prune_res.get("pruned_keys") or []
            if pruned_keys:
                await ws_manager.broadcast({"type": "devices_pruned", "device_keys": pruned_keys})
        except Exception as exc:
            logger.debug("Error running immediate auto_prune_database on settings change: %s", exc)

    await broadcast_full_status()
    return {"ok": True, "settings": new_settings}


@app.get("/api/db/stats")
async def api_get_db_stats():
    return await asyncio.to_thread(db.get_db_stats)


@app.post("/api/db/maintenance")
async def api_db_maintenance(req: DbMaintenanceRequest):
    result = await asyncio.to_thread(db.run_db_maintenance, req.action)
    if not result.get("ok"):
        raise HTTPException(status_code=400, detail=result.get("error", "Ogiltigt underhållskommando."))

    pruned_items = result.pop("pruned_items", None) or []
    for _dk, mod, did in pruned_items:
        ble_manager.evict_device(str(mod), str(did))
        rtl_manager.evict_device(str(mod), str(did))

    pruned_keys = result.get("pruned_keys") or []
    if pruned_keys:
        await ws_manager.broadcast({"type": "devices_pruned", "device_keys": pruned_keys})

    await broadcast_full_status()
    return result


@app.get("/api/stats")
async def api_get_stats():
    return await asyncio.to_thread(db.get_stats)


@app.get("/api/backup/export")
async def api_export_backup():
    data = await asyncio.to_thread(db.export_backup)
    return {"version": __version__, **data}


@app.post("/api/backup/import")
async def api_import_backup(payload: Dict[str, Any]):
    result = await asyncio.to_thread(db.import_backup, payload)
    await broadcast_full_status()
    return {"ok": True, **result}


@app.post("/api/database/optimize")
async def api_optimize_database():
    result = await asyncio.to_thread(db.optimize_database)
    await broadcast_full_status()
    return result


@app.post("/api/database/reset")
async def api_reset_database(req: Optional[DatabaseResetRequest] = None, keep_aliases: bool = Query(default=False)):
    keep = req.keep_aliases if req is not None else bool(keep_aliases)
    result = await asyncio.to_thread(db.reset_database, keep)
    rtl_manager.reset_stats_and_cache()
    ble_manager.reset_stats_and_cache()
    status_data = await asyncio.to_thread(build_status_payload)
    await ws_manager.broadcast(
        {
            "type": "db_reset",
            "keep_aliases": keep,
            "status": status_data,
        }
    )
    return result
