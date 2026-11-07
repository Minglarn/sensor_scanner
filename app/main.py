import asyncio
import logging
import os
import time
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional, Set

from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from app import __app_name__, __version__
from app.database import Database
from app.mqtt_client import MQTTManager
from app.rtl_manager import RTLManager

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
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


def _on_mqtt_status_threadsafe(mqtt_status: Dict[str, Any]) -> None:
    if main_loop and main_loop.is_running():
        asyncio.run_coroutine_threadsafe(broadcast_full_status(), main_loop)


mqtt_manager = MQTTManager(status_callback=_on_mqtt_status_threadsafe)


async def on_rtl_signal(payload: Dict[str, Any]) -> None:
    signal_rec, device_rec = await asyncio.to_thread(db.record_signal, payload)

    if signal_rec is None:
        return

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
    await broadcast_full_status()


async def on_rtl_stderr_line(line: str) -> None:
    await ws_manager.broadcast(
        {
            "type": "stderr",
            "line": line,
            "last_error": rtl_manager.get_status().get("last_error", ""),
        }
    )


rtl_manager = RTLManager(
    get_settings_fn=db.get_settings,
    on_signal_fn=on_rtl_signal,
    on_status_change_fn=on_rtl_status_change,
    on_stderr_line_fn=on_rtl_stderr_line,
)


def build_status_payload() -> Dict[str, Any]:
    counts = db.get_summary_counts()
    rtl_st = rtl_manager.get_status()
    mqtt_st = mqtt_manager.get_status()
    return {
        "app_name": __app_name__,
        "version": __version__,
        "app_uptime_seconds": int(max(0.0, time.time() - APP_STARTED_AT)),
        "rtl": rtl_st,
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


@asynccontextmanager
async def lifespan(app: FastAPI):
    global main_loop
    main_loop = asyncio.get_running_loop()

    settings = db.get_settings()
    mqtt_manager.configure_and_connect(settings)
    await rtl_manager.start()
    retention_task = asyncio.create_task(retention_worker(), name="retention_worker")

    try:
        yield
    finally:
        retention_task.cancel()
        try:
            await retention_task
        except asyncio.CancelledError:
            pass
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


class SettingsUpdateRequest(BaseModel):
    device_index: Optional[str] = None
    mode: Optional[str] = None
    custom_freqs: Optional[str] = None
    custom_sample_rate: Optional[str] = None
    hop_interval: Optional[str] = None
    gain: Optional[str] = None
    ppm: Optional[str] = None
    debounce_seconds: Optional[str] = None
    retention_days: Optional[str] = None
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


@app.post("/api/control")
async def api_control(req: ControlRequest):
    updates: Dict[str, str] = {}
    if req.mode is not None:
        if req.mode not in ("433", "868", "hop", "custom"):
            raise HTTPException(status_code=400, detail="Ogiltigt frekvensläge. Tillåtna: 433, 868, hop, custom.")
        updates["mode"] = req.mode
    if req.device_index is not None:
        updates["device_index"] = str(req.device_index).strip()
    if req.gain is not None:
        updates["gain"] = str(req.gain).strip() or "auto"
    if req.ppm is not None:
        updates["ppm"] = str(req.ppm).strip() or "0"
    if req.hop_interval is not None:
        updates["hop_interval"] = str(req.hop_interval).strip() or "60"
    if req.custom_freqs is not None:
        updates["custom_freqs"] = str(req.custom_freqs).strip()
    if req.custom_sample_rate is not None:
        updates["custom_sample_rate"] = str(req.custom_sample_rate).strip()

    if updates:
        await asyncio.to_thread(db.update_settings, updates)

    await rtl_manager.restart()
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
    unique_devices: bool = Query(default=False),
    limit: int = Query(default=150, ge=1, le=500),
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
        limit=20,
        offset=0,
    )
    return {"device": device, "history": history["items"]}


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


@app.delete("/api/devices/{device_key}")
async def api_delete_device(device_key: str):
    device = await asyncio.to_thread(db.get_device, device_key)
    if device and int(device.get("ha_discovery", 0)) == 1:
        await asyncio.to_thread(mqtt_manager.clear_ha_discovery, device)

    deleted = await asyncio.to_thread(db.delete_device, device_key)
    if not deleted:
        raise HTTPException(status_code=404, detail="Enheten hittades inte.")

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
    new_settings = await asyncio.to_thread(db.update_settings, payload)

    sdr_keys = ("device_index", "mode", "custom_freqs", "custom_sample_rate", "hop_interval", "gain", "ppm")
    mqtt_broker_keys = ("mqtt_enabled", "mqtt_host", "mqtt_port", "mqtt_user", "mqtt_pass", "mqtt_prefix")
    ha_keys = ("ha_discovery_enabled", "ha_discovery_prefix")

    sdr_changed = any(old_settings.get(k) != new_settings.get(k) for k in sdr_keys)
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

    if sdr_changed:
        await rtl_manager.restart()

    if old_settings.get("retention_days") != new_settings.get("retention_days"):
        try:
            ret_days = int(new_settings.get("retention_days", "30"))
            await asyncio.to_thread(db.run_retention_cleanup, ret_days)
        except (ValueError, TypeError):
            pass

    await broadcast_full_status()
    return {"ok": True, "settings": new_settings}


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
