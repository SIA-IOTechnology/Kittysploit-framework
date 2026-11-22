#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""CPU WPA-PSK cracker for hash-mode-22000 artifacts (no hashcat/aircrack)."""

from __future__ import annotations

from pathlib import Path
from typing import Callable, Iterable, Iterator

from lib.protocols.wlan.hc22000 import Hc22000Line, parse_hc22000_line
from lib.protocols.wlan.mac import str_to_mac
from lib.protocols.wlan.wpa_crypto import is_valid_psk, pmkid_from_psk, verify_eapol_mic


def try_password_against_line(password: str, line: Hc22000Line) -> bool:
    if not is_valid_psk(password):
        return False
    ssid = line.ssid.encode("utf-8", errors="surrogateescape")
    ap = str_to_mac(":".join(line.mac_ap[i : i + 2] for i in range(0, 12, 2)))
    sta = str_to_mac(":".join(line.mac_sta[i : i + 2] for i in range(0, 12, 2)))
    if line.is_pmkid:
        pmkid = pmkid_from_psk(password, ssid, ap, sta, sha256=line.message_pair == "03")
        return pmkid.hex().lower() == line.pmkid_or_mic.lower()
    try:
        eapol = bytes.fromhex(line.eapol)
        anonce = bytes.fromhex(line.anonce)
        snonce = eapol[17:49]
        mic = bytes.fromhex(line.pmkid_or_mic)
    except ValueError:
        return False
    return verify_eapol_mic(password, ssid, ap, sta, anonce, snonce, eapol, mic)


class WpaCpuCracker:
    def __init__(
        self,
        lines: list[Hc22000Line],
        *,
        on_progress: Callable[[int, str], None] | None = None,
    ) -> None:
        self.lines = lines
        self.on_progress = on_progress

    def crack(
        self,
        passwords: Iterable[str],
        *,
        on_progress: Callable[[int, str], None] | None = None,
    ) -> dict[str, str]:
        found: dict[str, str] = {}
        progress = on_progress or self.on_progress
        for index, pwd in enumerate(passwords):
            if progress and index % 500 == 0:
                progress(index, pwd)
            for line in self.lines:
                key = f"{line.mac_ap}:{line.essid}"
                if key in found:
                    continue
                if try_password_against_line(pwd, line):
                    found[key] = pwd
        return found

    @classmethod
    def from_file(cls, path: str | Path, **kwargs: object) -> "WpaCpuCracker":
        lines: list[Hc22000Line] = []
        for raw in Path(path).read_text(encoding="utf-8", errors="ignore").splitlines():
            parsed = parse_hc22000_line(raw)
            if parsed:
                lines.append(parsed)
        return cls(lines, **kwargs)

    @staticmethod
    def iter_wordlist(path: str | Path) -> Iterator[str]:
        with Path(path).open(encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                text = line.strip()
                if text:
                    yield text