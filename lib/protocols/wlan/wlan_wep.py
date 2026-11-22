#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""WEP capture and wordlist crack mixin."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Callable, Iterable

from core.framework.base_module import BaseModule

from lib.protocols.wlan.wep import WepIvStore, WepSample, parse_wep_data
from lib.protocols.wlan.wep_crypto import wep_key_candidates, wep_unwrap


class Wlan_wep(BaseModule):
    def __init__(self, framework=None):
        super().__init__(framework)
        self._wlan_wep_store: WepIvStore | None = None

    def wlan_wep_store(self) -> WepIvStore:
        if self._wlan_wep_store is None:
            self._wlan_wep_store = WepIvStore()
        return self._wlan_wep_store

    def wlan_wep_reset(self) -> WepIvStore:
        self._wlan_wep_store = WepIvStore()
        return self._wlan_wep_store

    def wlan_wep_ingest(self, raw: bytes) -> WepSample | None:
        sample = parse_wep_data(raw)
        if sample:
            self.wlan_wep_store().add(sample)
        return sample

    def wlan_wep_save_json(self, path: str | Path) -> int:
        rows = [
            {
                "bssid": s.bssid,
                "station": s.station,
                "iv": s.iv.hex(),
                "key_id": s.key_id,
                "ciphertext": s.ciphertext.hex(),
            }
            for s in self.wlan_wep_store().samples
        ]
        Path(path).write_text(json.dumps({"samples": rows}, indent=2), encoding="utf-8")
        return len(rows)

    @staticmethod
    def wlan_wep_load_json(path: str | Path) -> WepIvStore:
        store = WepIvStore()
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        for row in data.get("samples") or []:
            if not isinstance(row, dict):
                continue
            store.add(
                WepSample(
                    bssid=str(row.get("bssid", "")),
                    station=str(row.get("station", "")),
                    iv=bytes.fromhex(str(row.get("iv", ""))),
                    key_id=int(row.get("key_id", 0)),
                    ciphertext=bytes.fromhex(str(row.get("ciphertext", ""))),
                )
            )
        return store

    @staticmethod
    def wlan_wep_crack_samples(
        store: WepIvStore,
        passwords: Iterable[str],
        *,
        len_128: bool = False,
        on_progress: Callable[[int, str], None] | None = None,
    ) -> str | None:
        samples = store.samples
        if not samples:
            return None
        count = 0
        for pwd in passwords:
            count += 1
            if on_progress:
                on_progress(count, pwd)
            for key in wep_key_candidates(pwd, len_128=len_128):
                hits = 0
                for sample in samples[: min(50, len(samples))]:
                    if wep_unwrap(sample.iv, sample.ciphertext, key):
                        hits += 1
                if hits >= 1:
                    return pwd
        return None