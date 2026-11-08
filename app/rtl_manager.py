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
    "protocol_name",
    "protocol_full_name",
}


def compute_payload_signature(payload: Dict[str, Any]) -> str:
    filtered = {k: v for k, v in payload.items() if k not in VOLATILE_KEYS}
    canonical = json.dumps(filtered, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha1(canonical.encode("utf-8")).hexdigest()


def parse_duration_to_seconds(raw: Any, default_sec: int = 60) -> int:
    """
    Parses a duration string into integer seconds (minimum 5s).
    Supports:
    - 'HH:MM:SS' (e.g. '00:05:00' -> 300, '00:01:00' -> 60)
    - 'MM:SS' (e.g. '05:00' -> 300, '01:00' -> 60)
    - '5m', '1h30m', '90s'
    - Plain integer/float seconds (e.g. '60', '300')
    """
    s = str(raw if raw is not None else "").strip()
    if not s:
        return max(5, default_sec)

    if ":" in s:
        parts = [p.strip() for p in s.split(":")]
        try:
            if len(parts) == 3:
                h, m, sec = int(parts[0] or 0), int(parts[1] or 0), float(parts[2] or 0)
                total = int(round(h * 3600 + m * 60 + sec))
                return max(5, total)
            if len(parts) == 2:
                m, sec = int(parts[0] or 0), float(parts[1] or 0)
                total = int(round(m * 60 + sec))
                return max(5, total)
        except (ValueError, TypeError):
            return max(5, default_sec)

    unit_matches = re.findall(r"(\d+(?:\.\d+)?)\s*([hmsHMS])", s)
    if unit_matches:
        total_f = 0.0
        for val_str, unit_ch in unit_matches:
            v = float(val_str)
            u = unit_ch.lower()
            if u == "h":
                total_f += v * 3600.0
            elif u == "m":
                total_f += v * 60.0
            else:
                total_f += v
        return max(5, int(round(total_f)))

    try:
        return max(5, int(round(float(s))))
    except (ValueError, TypeError):
        return max(5, default_sec)


def format_seconds_to_hhmmss(seconds: Any) -> str:
    sec = parse_duration_to_seconds(seconds, 60)
    h = sec // 3600
    m = (sec % 3600) // 60
    s = sec % 60
    return f"{h:02d}:{m:02d}:{s:02d}"


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
        self.hop_intervals: List[int] = [60, 60]
        self._active_freqs: List[str] = ["433.92 MHz", "868.30 MHz"]
        self.hop_freqs: List[str] = ["433.92 MHz", "868.30 MHz"]
        self._last_hop_index: int = 0

    def reset_stats_and_cache(self) -> None:
        self._debounce_cache.clear()
        self._debounced_count = 0
        self._received_count = 0

    def evict_device(self, model: str, device_id: str) -> None:
        self._debounce_cache.pop(f"{model}:{device_id}", None)

    def _resolve_hop_schedule(self, settings: Dict[str, str]) -> Tuple[List[str], List[str], List[int]]:
        """
        Resolves (raw_rtl_freqs, display_freqs, hop_intervals_seconds) from settings.
        """
        mode = str(settings.get("mode", "hop")).strip().lower()
        base_default_sec = parse_duration_to_seconds(settings.get("hop_interval", "60"), 60)
        sec_433 = parse_duration_to_seconds(settings.get("hop_time_433") or base_default_sec, base_default_sec)
        sec_868 = parse_duration_to_seconds(settings.get("hop_time_868") or base_default_sec, base_default_sec)

        if mode == "433":
            return ["433.92M"], ["433.92 MHz"], [sec_433]
        if mode == "868":
            return ["868.3M"], ["868.30 MHz"], [sec_868]
        if mode == "custom":
            raw_freqs = str(settings.get("custom_freqs", "433.92M,868.3M"))
            raw_items = [f.strip() for f in raw_freqs.replace(";", ",").split(",") if f.strip()]
            if not raw_items:
                raw_items = ["433.92M"]

            raw_hop_str = str(settings.get("hop_interval", "60"))
            hop_tokens = [
                parse_duration_to_seconds(t.strip(), base_default_sec)
                for t in raw_hop_str.replace(";", ",").split(",")
                if t.strip()
            ] or [base_default_sec]

            rtl_freqs: List[str] = []
            disp_freqs: List[str] = []
            intervals: List[int] = []

            for idx, item in enumerate(raw_items):
                inline_dur: Optional[int] = None
                freq_part = item
                if "@" in item:
                    freq_part, dur_part = item.split("@", 1)
                    freq_part = freq_part.strip()
                    inline_dur = parse_duration_to_seconds(dur_part.strip(), base_default_sec)

                rtl_freqs.append(freq_part)
                m = re.match(r"^([0-9.]+)\s*[mM]?(?:[hH][zZ])?$", freq_part)
                disp_f = freq_part
                if m:
                    try:
                        val = float(m.group(1))
                        if val > 1_000_000:
                            val = val / 1_000_000.0
                        disp_f = f"{val:.2f} MHz"
                    except ValueError:
                        pass
                disp_freqs.append(disp_f)

                if inline_dur is not None:
                    intervals.append(inline_dur)
                elif len(hop_tokens) > 1 and idx < len(hop_tokens):
                    intervals.append(hop_tokens[idx])
                elif "433" in disp_f and settings.get("hop_time_433"):
                    intervals.append(sec_433)
                elif "868" in disp_f and settings.get("hop_time_868"):
                    intervals.append(sec_868)
                else:
                    intervals.append(hop_tokens[-1])

            return rtl_freqs, disp_freqs, intervals

        # Default: Dual Hop (433.92 MHz + 868.30 MHz)
        return ["433.92M", "868.3M"], ["433.92 MHz", "868.30 MHz"], [sec_433, sec_868]

    def _resolve_active_freqs(self, settings: Dict[str, str]) -> List[str]:
        _, disp_freqs, _ = self._resolve_hop_schedule(settings)
        return disp_freqs

    def _compute_hop_state(self) -> Tuple[str, int, int, int]:
        freqs = self.hop_freqs or self._active_freqs or ["433.92 MHz"]
        intervals = self.hop_intervals if len(self.hop_intervals) == len(freqs) else [max(5, int(self._hop_interval or 60))] * len(freqs)
        if len(freqs) <= 1 or self._state != "running":
            dur0 = intervals[0] if intervals else max(5, int(self._hop_interval or 60))
            return freqs[0], dur0, 0, dur0

        total_cycle = max(5, sum(max(5, iv) for iv in intervals))
        elapsed = max(0.0, time.monotonic() - self.hop_start_monotonic)
        cycle_pos = elapsed % total_cycle

        acc = 0.0
        for idx, f_name in enumerate(freqs):
            band_dur = max(5, int(intervals[idx]))
            if cycle_pos < acc + band_dur or idx == len(freqs) - 1:
                pos_in_band = max(0.0, cycle_pos - acc)
                remaining_sec = max(1, int(band_dur - pos_in_band))
                return f_name, remaining_sec, idx, band_dur
            acc += band_dur

        return freqs[0], intervals[0], 0, intervals[0]

    def get_freq_state(self) -> Dict[str, Any]:
        settings = self._get_settings()
        current_freq, remaining_sec, _, band_dur = self._compute_hop_state()
        self._current_tuned_freq = current_freq
        return {
            "mode": settings.get("mode", "hop"),
            "freq": current_freq,
            "current_tuned_freq": current_freq,
            "remaining": remaining_sec,
            "last_hop_timestamp": time.time() - (band_dur - remaining_sec),
            "hop_interval": band_dur,
            "hop_intervals": self.hop_intervals,
            "hop_time_433": format_seconds_to_hhmmss(settings.get("hop_time_433") or settings.get("hop_interval", "60")),
            "hop_time_868": format_seconds_to_hhmmss(settings.get("hop_time_868") or settings.get("hop_interval", "60")),
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
                    offset_before = sum(max(5, int(x)) for x in self.hop_intervals[:idx])
                    self.hop_start_monotonic = time.monotonic() - offset_before
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
        rtl_freqs, _, intervals = self._resolve_hop_schedule(settings)

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
            cmd.extend(["-f", "433.92M", "-f", "868.3M"])
            if len(intervals) >= 2 and intervals[0] != intervals[1]:
                cmd.extend(["-H", str(intervals[0]), "-H", str(intervals[1])])
            else:
                cmd.extend(["-H", str(intervals[0] if intervals else 60)])
            cmd.extend(["-s", "1024k"])
        elif mode == "custom":
            for f in rtl_freqs:
                cmd.extend(["-f", f])
            if len(rtl_freqs) > 1:
                if len(set(intervals)) == 1:
                    cmd.extend(["-H", str(intervals[0])])
                else:
                    for iv in intervals:
                        cmd.extend(["-H", str(iv)])
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

        current_freq, remaining_sec, _, band_dur = self._compute_hop_state()
        self._current_tuned_freq = current_freq

        return {
            "running": self._state == "running",
            "state": self._state,
            "pid": self._process.pid if self._process and self._process.returncode is None else None,
            "mode": settings.get("mode", "hop"),
            "device_index": settings.get("device_index", "0"),
            "gain": settings.get("gain", "auto"),
            "ppm": settings.get("ppm", "0"),
            "hop_interval": band_dur,
            "hop_intervals": self.hop_intervals,
            "hop_time_433": format_seconds_to_hhmmss(settings.get("hop_time_433") or settings.get("hop_interval", "60")),
            "hop_time_868": format_seconds_to_hhmmss(settings.get("hop_time_868") or settings.get("hop_interval", "60")),
            "freq": current_freq,
            "current_tuned_freq": current_freq,
            "remaining": remaining_sec,
            "last_hop_timestamp": time.time() - (band_dur - remaining_sec),
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
        from app.sdr_manager import load_rtl433_protocols_from_binary

        try:
            await asyncio.to_thread(load_rtl433_protocols_from_binary)
        except Exception:
            pass
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

    def append_raw_log(self, formatted_line: str) -> str:
        self._stderr_buffer.append(formatted_line)
        return formatted_line

    def _append_stderr(self, line: str) -> str:
        if re.match(r"^\d{2}:\d{2}:\d{2}\s+\|\s+\[", line):
            self._stderr_buffer.append(line)
            return line
        ts = datetime.now(timezone.utc).astimezone().strftime("%H:%M:%S")
        formatted = f"{ts} | [{'SDR':<6}] | {'RTL-SDR V4':<11} | {line}"
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

            proto_raw = payload.get("protocol")
            if proto_raw is not None and str(proto_raw).strip() != "":
                from app.sdr_manager import get_rtl433_protocol_info

                p_short, p_full = get_rtl433_protocol_info(proto_raw, payload.get("model"))
                if p_short:
                    payload["protocol_name"] = p_short
                if p_full and p_full != p_short:
                    payload["protocol_full_name"] = p_full

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
            if len(self.hop_freqs) <= 1:
                continue
            current_freq, _, hop_index, band_dur = self._compute_hop_state()
            if hop_index != self._last_hop_index or current_freq != self._current_tuned_freq:
                self._last_hop_index = hop_index
                self._current_tuned_freq = current_freq
                self._hop_interval = band_dur
                self.hop_interval = band_dur
                self._last_hop_timestamp = time.time()
                ts = datetime.now(timezone.utc).astimezone().strftime("%H:%M:%S")
                freq_col = f"{current_freq[:11]:<11}"
                name_col = f"{f'Frekvenshopp -> {current_freq}':<42}"
                meas_col = f"{f'Lyssnar i {format_seconds_to_hhmmss(band_dur)} ({band_dur}s)':<32}"
                hop_line = self.append_raw_log(
                    f"{ts} | [{'SDR':<6}] | {freq_col} | {name_col} | {meas_col} | RSSI: {'-':>5}    "
                )
                try:
                    await self._on_stderr_line(hop_line)
                except Exception:
                    pass
                await self._emit_freq_change()

    async def _watchdog_loop(self) -> None:
        while self._running:
            self._restart_event.clear()
            settings = self._get_settings()
            cmd = self.build_command(settings)
            self._current_cmd = cmd
            _, disp_freqs, intervals = self._resolve_hop_schedule(settings)
            self._active_freqs = disp_freqs
            self.hop_freqs = list(disp_freqs)
            self.hop_intervals = list(intervals) if intervals else [60]
            self._hop_interval = self.hop_intervals[0]
            self.hop_interval = self._hop_interval
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

