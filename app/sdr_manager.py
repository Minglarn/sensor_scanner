"""SDR / rtl_433 Subprocess & Dual-Hop Frequency Manager."""

from app.rtl_manager import RTLManager, compute_payload_signature

SDRManager = RTLManager

__all__ = ["RTLManager", "SDRManager", "compute_payload_signature"]
