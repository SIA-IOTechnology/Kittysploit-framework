#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""HackRF wideband spectrum sweep (authorized spectrum analysis)."""

from __future__ import annotations

from kittysploit import *
from lib.protocols.rf.hackrf_mixin import Hackrf_client


class Module(Auxiliary, Hackrf_client):
    __info__ = {
        "name": "HackRF Spectrum Sweep",
        "description": (
            "Run hackrf_sweep across a MHz span and report the strongest RF bins. "
            "Requires HackRF host tools and a connected HackRF One."
        ),
        "author": ["KittySploit Team"],
        "tags": ["rf", "hackrf", "sdr", "spectrum", "scanner"],
        "references": ["https://greatscottgadgets.com/hackrf/"],
        "attack": {
            "tactics": ["TA0007"],
            "techniques": ["T1016"],
            "prerequisites": [
                "HackRF One + USB drivers",
                "hackrf_sweep in PATH",
                "Spectrum authorization for target bands",
            ],
        },
    }

    start_mhz = OptInteger(2400, "Sweep start (MHz)", required=False)
    stop_mhz = OptInteger(2500, "Sweep stop (MHz)", required=False)
    bin_width_hz = OptInteger(1_000_000, "FFT bin width (Hz)", required=False)
    lna_gain = OptInteger(16, "RX LNA gain (0–40 dB, 8 dB steps)", required=False)
    vga_gain = OptInteger(20, "RX VGA gain (0–62 dB, 2 dB steps)", required=False)
    top_n = OptInteger(25, "Number of peaks to print", required=False)

    def check(self):
        if not self.hackrf_check_tools():
            return False
        return self.hackrf_verify_device()

    def run(self):
        start = float(int(self.start_mhz or 2400))
        stop = float(int(self.stop_mhz or 2500))
        if stop <= start:
            print_error("STOP_MHZ must be greater than START_MHZ")
            return False

        print_info(f"HackRF sweep {start:.0f}–{stop:.0f} MHz …")
        result = self.hackrf_run_sweep(
            start,
            stop,
            bin_width_hz=int(self.bin_width_hz or 1_000_000),
            top_n=int(self.top_n or 25),
            lna_gain=int(self.lna_gain or 16),
            vga_gain=int(self.vga_gain or 20),
        )
        if result.get("error"):
            print_error(result["error"])
            return False
        peaks = result.get("peaks") or []
        self.hackrf_print_peaks(peaks)
        return bool(peaks)