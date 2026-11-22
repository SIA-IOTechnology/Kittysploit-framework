"""Shared HackRF helpers for KittySploit modules."""

from __future__ import annotations

from typing import Any, Dict, List

from core.framework.option import OptString
from lib.protocols.rf.hackrf_client import (
    hackrf_info as probe_hackrf_info,
    hackrf_tools_available,
    hackrf_transfer_tx,
    list_hackrf_devices,
    sweep_peaks,
)


class Hackrf_client:
    device_serial = OptString("", "HackRF serial (empty = first board)", required=False)

    def hackrf_check_tools(self) -> bool:
        if not hackrf_tools_available():
            print_error("Install HackRF host tools (hackrf_info, hackrf_sweep, hackrf_transfer)")
            return False
        return True

    def hackrf_serial(self) -> str:
        return str(getattr(self, "device_serial", "") or "").strip()

    def hackrf_verify_device(self) -> bool:
        if not self.hackrf_check_tools():
            return False
        serial = self.hackrf_serial()
        info = probe_hackrf_info(serial)
        if info.get("error"):
            print_error(info["error"])
            devices = list_hackrf_devices()
            if devices:
                print_info("Detected HackRF USB entries — check drivers and exclusive access")
            return False
        print_success(f"HackRF ready — serial {info.get('serial') or '(default)'}")
        return True

    def hackrf_run_sweep(
        self,
        start_mhz: float,
        stop_mhz: float,
        *,
        bin_width_hz: int = 1_000_000,
        top_n: int = 25,
        lna_gain: int = 16,
        vga_gain: int = 20,
    ) -> Dict[str, Any]:
        return sweep_peaks(
            start_mhz,
            stop_mhz,
            bin_width_hz=bin_width_hz,
            serial=self.hackrf_serial(),
            lna_gain=lna_gain,
            vga_gain=vga_gain,
            top_n=top_n,
        )

    def hackrf_tx_file(
        self,
        iq_path: str,
        freq_hz: int,
        sample_rate_hz: int = 2_000_000,
        tx_gain: int = 0,
        repeat: bool = False,
    ) -> Dict[str, Any]:
        return hackrf_transfer_tx(
            iq_path,
            freq_hz,
            sample_rate_hz=sample_rate_hz,
            tx_gain=tx_gain,
            serial=self.hackrf_serial(),
            repeat=repeat,
        )

    def hackrf_print_peaks(self, peaks: List[Dict[str, Any]], title: str = "Spectrum peaks") -> None:
        if not peaks:
            print_warning(f"{title}: no peaks")
            return
        print_success(f"{title} — {len(peaks)} bins")
        for row in peaks:
            print_info(f"  {row['freq_mhz']:10.3f} MHz  {row['power_db']:6.1f} dB")