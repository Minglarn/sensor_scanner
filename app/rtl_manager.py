import asyncio
import collections
import hashlib
import json
import logging
import shutil
import time
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Deque, Dict, List, Optional, Tuple

from app.database import extract_device_id

logger = logging.getLogger("sensor_scanner.rtl")

VOLATILE_KEYS = {
    "time",
    "rssi",
    "snr",
    "noise",
    "freq",
    "freq1",
    "freq2",
    "mod",
    "mic",
}


def compute_payload_signature(payload: Dict[str, Any]) -> str:
    filtered = {k: v for k, v in payload.items() if k not in VOLATILE_KEYS}
    canonical = json.dumps(filtered, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha1(canonical.encode("utf-8")).hexdigest()


class RTLManager:
    def __init__(
        self,
        get_settings_fn: Callable[[], Dict[str, str]],
        on_signal_fn: Callable[[Dict[str, Any]], Awaitable[None]],
        on_status_change_fn: Callable[[Dict[str, Any]], Awaitable[None]],
        on_stderr_line_fn: Callable[[str], Awaitable[None]],
    ):
        self._get_settings = get_settings_fn
        self._on_signal = on_signal_fn
        self._on_status_change = on_status_change_fn
        self._on_stderr_line = on_stderr_line_fn

        self._process: Optional[asyncio.subprocess.Process] = None
        self._watchdog_task: Optional[asyncio.Task] = None
        self._running: bool = False
        self._restart_event = asyncio.Event()
        self._process_lock = asyncio.Lock()

        self._state: str = "stopped"
        self._current_cmd: List[str] = []
        self._started_at: Optional[float] = None
        self._last_error: str = ""
        self._stderr_buffer: Deque[str] = collections.deque(maxlen=200)
        self._debounce_cache: Dict[str, Tuple[str, float]] = {}
        self._debounced_count: int = 0
        self._received_count: int = 0
        self._restart_count: int = 0

    def build_command(self, settings: Dict[str, str]) -> List[str]:
        binary = shutil.which("rtl_433") or "/usr/local/bin/rtl_433"
        device_index = str(settings.get("device_index", "0")).strip() or "0"
        mode = str(settings.get("mode", "hop")).strip().lower()
        gain = str(settings.get("gain", "auto")).strip()
        ppm = str(settings.get("ppm", "0")).strip()
        hop_interval = str(settings.get("hop_interval", "60")).strip() or "60"

        cmd: List[str] = [
            binary,
            "-d",
            device_index,
            "-F",
            "json",
            "-M",
            "time:iso",
            "-M",
            "level",
            "-M",
            "protocol",
        ]

        if mode == "433":
            cmd.extend(["-f", "433.92M"])
        elif mode == "868":
            cmd.extend(["-f", "868.3M", "-s", "1024k"])
        elif mode == "hop":
            cmd.extend(["-f", "433.92M", "-f", "868.3M", "-H", hop_interval, "-s", "1024k"])
        elif mode == "custom":
            raw_freqs = str(settings.get("custom_freqs", "433.92M,868.3M"))
            freqs = [f.strip() for f in raw_freqs.replace(";", ",").split(",") if f.strip()]
            if not freqs:
                freqs = ["433.92M"]
            for f in freqs:
                cmd.extend(["-f", f])
            if len(freqs) > 1:
                cmd.extend(["-H", hop_interval])
            sample_rate = str(settings.get("custom_sample_rate", "1024k")).strip()
            if sample_rate:
                cmd.extend(["-s", sample_rate])
        else:
            cmd.extend(["-f", "433.92M", "-f", "868.3M", "-H", "60", "-s", "1024k"])

        if gain and gain.lower() != "auto":
            cmd.extend(["-g", gain])

        if ppm and ppm not in ("0", "0.0", ""):
            cmd.extend(["-p", ppm])

        return cmd

    def get_status(self) -> Dict[str, Any]:
        settings = self._get_settings()
        uptime_sec = 0
        if self._state == "running" and self._started_at is not None:
            uptime_sec = max(0, int(time.time() - self._started_at))

        return {
            "running": self._state == "running",
            "state": self._state,
            "pid": self._process.pid if self._process and self._process.returncode is None else None,
            "mode": settings.get("mode", "hop"),
            "device_index": settings.get("device_index", "0"),
            "gain": settings.get("gain", "auto"),
            "ppm": settings.get("ppm", "0"),
            "hop_interval": settings.get("hop_interval", "60"),
            "custom_freqs": settings.get("custom_freqs", "433.92M,868.3M"),
            "custom_sample_rate": settings.get("custom_sample_rate", "1024k"),
            "debounce_seconds": float(settings.get("debounce_seconds", "2.0") or 2.0),
            "command": " ".join(self._current_cmd) if self._current_cmd else " ".join(self.build_command(settings)),
            "uptime_seconds": uptime_sec,
            "last_error": self._last_error,
            "stderr_tail": list(self._stderr_buffer)[-40:],
            "received_count": self._received_count,
            "debounced_count": self._debounced_count,
            "restart_count": self._restart_count,
        }

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._watchdog_task = asyncio.create_task(self._watchdog_loop(), name="rtl_433_watchdog")

    async def stop(self) -> None:
        self._running = False
        self._restart_event.set()
        await self._terminate_process()
        if self._watchdog_task is not None:
            self._watchdog_task.cancel()
            try:
                await self._watchdog_task
            except asyncio.CancelledError:
                pass
            self._watchdog_task = None
        self._state = "stopped"
        await self._on_status_change(self.get_status())

    async def restart(self) -> None:
        logger.info("Restarting rtl_433 subprocess on user/config request...")
        self._restart_event.set()
        await self._terminate_process()

    async def _terminate_process(self) -> None:
        async with self._process_lock:
            proc = self._process
            if proc is not None and proc.returncode is None:
                try:
                    proc.terminate()
                    try:
                        await asyncio.wait_for(proc.wait(), timeout=3.0)
                    except asyncio.TimeoutError:
                        proc.kill()
                        await proc.wait()
                except ProcessLookupError:
                    pass
                except Exception as exc:
                    logger.debug("Error terminating rtl_433: %s", exc)
            self._process = None

    def _append_stderr(self, line: str) -> str:
        ts = datetime.now(timezone.utc).astimezone().strftime("%H:%M:%S")
        formatted = f"[{ts}] {line}"
        self._stderr_buffer.append(formatted)
        return formatted

    def _is_debounced(self, payload: Dict[str, Any], debounce_window: float) -> bool:
        if debounce_window <= 0:
            return False

        now = time.monotonic()
        if len(self._debounce_cache) > 1000:
            expired = [k for k, (_, ts) in self._debounce_cache.items() if now - ts > max(debounce_window * 2, 30.0)]
            for k in expired:
                self._debounce_cache.pop(k, None)

        model = str(payload.get("model") or "Unknown").strip()
        dev_id = extract_device_id(payload)
        dev_key = f"{model}:{dev_id}"
        sig = compute_payload_signature(payload)

        prev = self._debounce_cache.get(dev_key)
        if prev is not None:
            prev_sig, prev_ts = prev
            if prev_sig == sig and (now - prev_ts) < debounce_window:
                self._debounced_count += 1
                return True

        self._debounce_cache[dev_key] = (sig, now)
        return False

    async def _read_stdout(self, stream: asyncio.StreamReader) -> None:
        while True:
            line_bytes = await stream.readline()
            if not line_bytes:
                break
            line = line_bytes.decode("utf-8", errors="replace").strip()
            if not line or not line.startswith("{"):
                continue

            try:
                payload = json.loads(line)
                if not isinstance(payload, dict):
                    continue
            except json.JSONDecodeError:
                continue

            settings = self._get_settings()
            try:
                debounce_sec = float(settings.get("debounce_seconds", "2.0"))
            except (ValueError, TypeError):
                debounce_sec = 2.0

            if self._is_debounced(payload, debounce_sec):
                continue

            self._received_count += 1
            try:
                await self._on_signal(payload)
            except Exception as exc:
                logger.error("Error processing signal callback: %s", exc)

    async def _read_stderr(self, stream: asyncio.StreamReader) -> None:
        while True:
            line_bytes = await stream.readline()
            if not line_bytes:
                break
            line = line_bytes.decode("utf-8", errors="replace").strip()
            if not line:
                continue

            formatted = self._append_stderr(line)
            lower = line.lower()
            if any(
                err_tok in lower
                for err_tok in (
                    "usb_open error",
                    "no supported devices found",
                    "failed to open rtlsdr device",
                    "usb_claim_interface error",
                    "kernel driver is active",
                    "rtlsdr_read_async failed",
                    "LIBUSB_ERROR",
                    "libusb_error",
                    "no matching device",
                )
            ):
                self._last_error = line

            try:
                await self._on_stderr_line(formatted)
            except Exception:
                pass

    async def _watchdog_loop(self) -> None:
        while self._running:
            self._restart_event.clear()
            settings = self._get_settings()
            cmd = self.build_command(settings)
            self._current_cmd = cmd

            self._state = "starting"
            await self._on_status_change(self.get_status())

            try:
                logger.info("Starting rtl_433: %s", " ".join(cmd))
                self._append_stderr(f"Startar: {' '.join(cmd)}")

                async with self._process_lock:
                    self._process = await asyncio.create_subprocess_exec(
                        *cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )

                self._started_at = time.time()
                self._state = "running"
                self._last_error = ""
                await self._on_status_change(self.get_status())

                stdout_task = asyncio.create_task(self._read_stdout(self._process.stdout))
                stderr_task = asyncio.create_task(self._read_stderr(self._process.stderr))

                return_code = await self._process.wait()
                await asyncio.gather(stdout_task, stderr_task, return_exceptions=True)

                if not self._running:
                    break

                if self._restart_event.is_set():
                    self._restart_count += 1
                    self._append_stderr("Omstart begärd, laddar nya inställningar...")
                    continue

                self._state = "error"
                self._started_at = None
                self._restart_count += 1
                if not self._last_error:
                    self._last_error = f"rtl_433 avslutades oväntat (exit code {return_code})"
                self._append_stderr(f"Processen stoppade (kod {return_code}). Försöker igen om 5 sekunder...")
                await self._on_status_change(self.get_status())

            except FileNotFoundError:
                self._state = "error"
                self._started_at = None
                self._last_error = "Kunde inte hitta binären 'rtl_433'. Kontrollera att containern är korrekt byggd."
                formatted = self._append_stderr(self._last_error)
                await self._on_stderr_line(formatted)
                await self._on_status_change(self.get_status())
            except Exception as exc:
                self._state = "error"
                self._started_at = None
                self._last_error = f"Fel vid start av rtl_433: {exc}"
                formatted = self._append_stderr(self._last_error)
                await self._on_stderr_line(formatted)
                await self._on_status_change(self.get_status())

            if not self._running:
                break

            try:
                await asyncio.wait_for(self._restart_event.wait(), timeout=5.0)
            except asyncio.TimeoutError:
                pass

