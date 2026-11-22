#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""WPS PIN checksum, iteration, and resume state."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterator


def wps_pin_checksum(first_seven: int) -> int:
    accum = 0
    while first_seven > 0:
        accum += first_seven % 10
        first_seven //= 10
    return (10 - (accum % 10)) % 10


def pin_with_checksum(seven_digit: int) -> str:
    if seven_digit < 0 or seven_digit > 9_999_999:
        raise ValueError("PIN prefix must be 0..9999999")
    chk = wps_pin_checksum(seven_digit)
    return f"{seven_digit:07d}{chk}"


def iter_wps_pins(
    start: int = 0,
    end: int = 9_999_999,
) -> Iterator[str]:
    """Yield 8-digit WPS PINs with valid checksum."""
    lo = max(0, int(start))
    hi = min(9_999_999, int(end))
    for prefix in range(lo, hi + 1):
        yield pin_with_checksum(prefix)


def parse_pin_index(pin8: str) -> int:
    text = str(pin8 or "").strip()
    if len(text) != 8 or not text.isdigit():
        raise ValueError("PIN must be 8 digits")
    return int(text[:7])


@dataclass
class WpsPinBruteState:
    bssid: str
    ssid: str
    last_pin: str = "00000000"
    attempts: int = 0
    found_pin: str = ""

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(asdict(self), indent=2), encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path) -> "WpsPinBruteState | None":
        p = Path(path)
        if not p.is_file():
            return None
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            return cls(
                bssid=str(data.get("bssid", "")),
                ssid=str(data.get("ssid", "")),
                last_pin=str(data.get("last_pin", "00000000")),
                attempts=int(data.get("attempts", 0)),
                found_pin=str(data.get("found_pin", "")),
            )
        except Exception:
            return None