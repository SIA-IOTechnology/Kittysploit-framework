#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Replay a captured HackRF IQ file (authorized lab / red-team transmit only)."""

from __future__ import annotations

import os

from kittysploit import *
from lib.protocols.rf.hackrf_mixin import Hackrf_client


class Module(Auxiliary, Hackrf_client):
    __info__ = {
        "name": "HackRF IQ Replay",
        "description": (
            "Transmit a binary IQ capture via hackrf_transfer for controlled replay tests. "
            "Illegal on public spectrum without explicit authorization."
        ),
        "author": ["KittySploit Team"],
        "tags": ["rf", "hackrf", "transmit", "replay"],
        "references": ["https://attack.mitre.org/techniques/T0862/"],
        "attack": {
            "tactics": ["TA0040"],
            "techniques": ["T0862"],
            "prerequisites": [
                "Signed authorization for target band and ERP",
                "hackrf_transfer in PATH",
                "IQ file captured with matching sample rate",
            ],
        },
    }

    iq_file = OptFile("", "IQ sample file (signed int8 interleaved)", required=True)
    freq_mhz = OptFloat(433.92, "Center frequency (MHz)", required=True)
    sample_rate = OptInteger(2_000_000, "Sample rate (Hz)", required=False)
    tx_gain = OptInteger(0, "TX VGA gain (0–47, start low in shielded lab)", required=False)
    repeat_tx = OptBool(False, "Repeat until stopped (disruptive)", required=False)
    authorized = OptBool(False, "I have written authorization for this transmit", required=True)

    def check(self):
        if not bool(self.authorized):
            print_error("Set AUTHORIZED=true after confirming legal transmit approval")
            return False
        path = str(self.iq_file or "").strip()
        if not path or not os.path.isfile(path):
            print_error("Valid IQ_FILE required")
            return False
        if not self.hackrf_verify_device():
            return False
        return True

    def run(self):
        freq_hz = int(float(self.freq_mhz or 0) * 1_000_000)
        if freq_hz <= 0:
            print_error("FREQ_MHZ required")
            return False
        path = str(self.iq_file)
        rate = int(self.sample_rate or 2_000_000)
        gain = max(0, min(47, int(self.tx_gain or 0)))

        print_warning("Transmitting — ensure shielded enclosure or licensed test range")
        print_info(f"hackrf_transfer {path} @ {freq_hz} Hz, rate={rate}, gain={gain}")
        result = self.hackrf_tx_file(
            path,
            freq_hz,
            sample_rate_hz=rate,
            tx_gain=gain,
            repeat=bool(self.repeat_tx),
        )
        if result.get("error"):
            print_error(result["error"])
            return False
        print_success("Transmit finished")
        return True