import asyncio
import collections
import hashlib
import json
import logging
import re
import shutil
import time
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Deque, Dict, List, Optional, Tuple

from app.database import extract_device_id, extract_freq_mhz

logger = logging.getLogger("sensor_scanner.rtl")

TUNED_TO_RE = re.compile(r"Tuned to\s+([0-9.]+)\s*MHz", re.IGNORECASE)

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
        on_freq_change_fn: Optional[Callable[[Dict[str, Any]], Awaitable[None]]] = None,
    ):
        self._get_settings = get_settings_fn
        self._on_signal = on_signal_fn
        self._on_status_change = on_status_change_fn
        self._on_stderr_line = on_stderr_line_fn
        self._on_freq_change = on_freq_change_fn

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

        self._current_tuned_freq: str = "433.92 MHz"
        self._last_hop_timestamp: float = time.time()
        self.hop_start_monotonic: float = time.monotonic()
        self._hop_interval: int = 60
        self.hop_interval: int = 60
        self._active_freqs: List[str] = ["433.92 MHz", "868.30 MHz"]
        self.hop_freqs: List[str] = ["433.92 MHz", "868.30 MHz"]
        self._last_hop_index: int = 0

    def reset_stats_and_cache(self) -> None:
        self._debounce_cache.clear()
        self._debounced_count = 0
        self._received_count = 0

    def evict_device(self, model: str, device_id: str) -> None:
        self._debounce_cache.pop(f"{model}:{device_id}", None)

    def _resolve_active_freqs(self, settings: Dict[str, str]) -> List[str]:
        mode = str(settings.get("mode", "hop")).strip().lower()
        if mode == "433":
            return ["433.92 MHz"]
        if mode == "868":
            return ["868.30 MHz"]
        if mode == "custom":
            raw_freqs = str(settings.get("custom_freqs", "433.92M,868.3M"))
            items = [f.strip() for f in raw_freqs.replace(";", ",").split(",") if f.strip()]
            normalized: List[str] = []
            for f in items:
                m = re.match(r"^([0-9.]+)\s*[mM]?(?:[hH][zZ])?$", f)
                if m:
                    try:
                        val = float(m.group(1))
                        if val > 1_000_000:
                            val = val / 1_000_000.0
                        normalized.append(f"{val:.2f} MHz")
                        continue
                    except ValueError:
                        pass
                normalized.append(f)
            return normalized or ["433.92 MHz"]
        return ["433.92 MHz", "868.30 MHz"]

    def _compute_hop_state(self) -> Tuple[str, int, int]:
        freqs = self.hop_freqs or self._active_freqs or ["433.92 MHz"]
        interval = max(5, int(self._hop_interval or 60))
        if len(freqs) <= 1 or self._state != "running":
            return freqs[0], interval, 0
        elapsed = max(0.0, time.monotonic() - self.hop_start_monotonic)
        hop_index = int(elapsed // interval) % len(freqs)
        current_freq = freqs[hop_index]
        remaining_sec = max(1, int(interval - (elapsed % interval)))
        return current_freq, remaining_sec, hop_index

    def get_freq_state(self) -> Dict[str, Any]:
        settings = self._get_settings()
        current_freq, remaining_sec, _ = self._compute_hop_state()
        self._current_tuned_freq = current_freq
        return {
            "mode": settings.get("mode", "hop"),
            "freq": current_freq,
            "current_tuned_freq": current_freq,
            "remaining": remaining_sec,
            "last_hop_timestamp": time.time() - (self._hop_interval - remaining_sec),
            "hop_interval": self._hop_interval,
            "active_freqs": self._active_freqs,
        }

    async def _emit_freq_change(self) -> None:
        if self._on_freq_change is not None:
            try:
                await self._on_freq_change(self.get_freq_state())
            except Exception as exc:
                logger.debug("Error in on_freq_change callback: %s", exc)

    async def _check_and_handle_tuned_line(self, line: str) -> bool:
        m = TUNED_TO_RE.search(line)
        if not m:
            return False
        try:
            freq_val = float(m.group(1))
            if freq_val > 1_000_000:
                freq_val = freq_val / 1_000_000.0
            new_freq = f"{freq_val:.2f} MHz"
            if len(self.hop_freqs) > 1:
                try:
                    idx = self.hop_freqs.index(new_freq)
                    self.hop_start_monotonic = time.monotonic() - (idx * self._hop_interval)
                    self._last_hop_index = idx
                except ValueError:
                    pass
            self._current_tuned_freq = new_freq
            self._last_hop_timestamp = time.time()
            await self._emit_freq_change()
            return True
        except ValueError:
            return False

    def build_command(self, settings: Dict[str, str]) -> List[str]:
        binary = shutil.which("rtl_433") or "/usr/local/bin/rtl_433"
        device_index = str(settings.get("device_index", "0")).strip() or "0"
        mode = str(settings.get("mode", "hop")).strip().lower()
        raw_gain = str(settings.get("gain", "auto")).strip().replace(",", ".")
        gain = re.sub(r"\s*db$", "", raw_gain, flags=re.IGNORECASE).strip() or "auto"
        ppm = str(settings.get("ppm", "0")).strip().replace(",", ".")
        hop_interval = str(settings.get("hop_interval", "60")).strip() or "60"

        cmd: List[str] = [
            binary,
            "-d",
            device_index,
            "-C",
            "si",
            "-F",
            "json",
            "-F",
            "log",
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

        current_freq, remaining_sec, _ = self._compute_hop_state()
        self._current_tuned_freq = current_freq

        return {
            "running": self._state == "running",
            "state": self._state,
            "pid": self._process.pid if self._process and self._process.returncode is None else None,
            "mode": settings.get("mode", "hop"),
            "device_index": settings.get("device_index", "0"),
            "gain": settings.get("gain", "auto"),
            "ppm": settings.get("ppm", "0"),
            "hop_interval": self._hop_interval,
            "freq": current_freq,
            "current_tuned_freq": current_freq,
            "remaining": remaining_sec,
            "last_hop_timestamp": time.time() - (self._hop_interval - remaining_sec),
            "active_freqs": self._active_freqs,
            "custom_freqs": settings.get("custom_freqs", "433.92M,868.3M"),
            "custom_sample_rate": settings.get("custom_sample_rate", "1024k"),
            "debounce_seconds": float(settings.get("debounce_seconds", "2.0") or 2.0),
            "command": " ".join(self.build_command(settings)),
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
        self._current_cmd = self.build_command(self._get_settings())
        self._restart_event.set()
        await self._terminate_process()
        await asyncio.sleep(0.05)

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
            if not line:
                continue
            if not line.startswith("{"):
                await self._check_and_handle_tuned_line(line)
                continue

            try:
                payload = json.loads(line)
                if not isinstance(payload, dict):
                    continue
            except json.JSONDecodeError:
                continue

            # Only infer frequency from packet in fixed single-frequency mode
            if len(self.hop_freqs) <= 1:
                pkt_freq = extract_freq_mhz(payload)
                if pkt_freq is not None:
                    inferred_band = None
                    if 430.0 <= pkt_freq <= 440.0:
                        inferred_band = "433.92 MHz"
                    elif 860.0 <= pkt_freq <= 875.0:
                        inferred_band = "868.30 MHz"
                    else:
                        inferred_band = f"{pkt_freq:.2f} MHz"

                    if inferred_band and inferred_band != self._current_tuned_freq:
                        self._current_tuned_freq = inferred_band
                        self._last_hop_timestamp = time.time()
                        await self._emit_freq_change()

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

            await self._check_and_handle_tuned_line(line)

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

    async def _hop_tracker_loop(self) -> None:
        while self._state == "running" and self._process and self._process.returncode is None:
            await asyncio.sleep(0.25)
            if len(self.hop_freqs) <= 1 or self.hop_interval <= 0:
                continue
            elapsed = max(0.0, time.monotonic() - self.hop_start_monotonic)
            hop_index = int(elapsed // self.hop_interval) % len(self.hop_freqs)
            current_freq = self.hop_freqs[hop_index]
            if hop_index != self._last_hop_index or current_freq != self._current_tuned_freq:
                self._last_hop_index = hop_index
                self._current_tuned_freq = current_freq
                self._last_hop_timestamp = time.time()
                await self._emit_freq_change()

    async def _watchdog_loop(self) -> None:
        while self._running:
            self._restart_event.clear()
            settings = self._get_settings()
            cmd = self.build_command(settings)
            self._current_cmd = cmd
            try:
                self._hop_interval = max(5, int(settings.get("hop_interval", "60") or 60))
            except (ValueError, TypeError):
                self._hop_interval = 60
            self.hop_interval = self._hop_interval
            self._active_freqs = self._resolve_active_freqs(settings)
            self.hop_freqs = list(self._active_freqs)
            self._current_tuned_freq = self.hop_freqs[0]
            self.hop_start_monotonic = time.monotonic()
            self._last_hop_index = 0
            self._last_hop_timestamp = time.time()

            self._state = "starting"
            await self._on_status_change(self.get_status())

            try:
                logger.info("Starting rtl_433: %s", " ".join(cmd))
                start_line = self._append_stderr(f"Startar: {' '.join(cmd)}")
                await self._on_stderr_line(start_line)

                async with self._process_lock:
                    self._process = await asyncio.create_subprocess_exec(
                        *cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )

                self._started_at = time.time()
                self.hop_start_monotonic = time.monotonic()
                self._last_hop_index = 0
                self._last_hop_timestamp = self._started_at
                self._state = "running"
                self._last_error = ""
                await self._on_status_change(self.get_status())
                await self._emit_freq_change()

                stdout_task = asyncio.create_task(self._read_stdout(self._process.stdout))
                stderr_task = asyncio.create_task(self._read_stderr(self._process.stderr))
                hop_task = asyncio.create_task(self._hop_tracker_loop())

                return_code = await self._process.wait()
                hop_task.cancel()
                await asyncio.gather(stdout_task, stderr_task, hop_task, return_exceptions=True)

                if not self._running:
                    break

                if self._restart_event.is_set():
                    self._restart_count += 1
                    restart_line = self._append_stderr("Omstart begärd, laddar nya inställningar...")
                    await self._on_stderr_line(restart_line)
                    continue

                self._state = "error"
                self._started_at = None
                self._restart_count += 1
                if not self._last_error:
                    self._last_error = f"rtl_433 avslutades oväntat (exit code {return_code})"
                stop_line = self._append_stderr(f"Processen stoppade (kod {return_code}). Försöker igen om 5 sekunder...")
                await self._on_stderr_line(stop_line)
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

