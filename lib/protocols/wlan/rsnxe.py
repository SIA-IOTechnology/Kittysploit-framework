#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""RSN Extension (RSNXE) parsing for WPA3 / SAE capabilities."""

from __future__ import annotations

from dataclasses import dataclass

from lib.protocols.wlan.ie import iter_information_elements

RSNXE_IE = 244


@dataclass
class RsnxeInfo:
    caps: int = 0
    sae_h2e: bool = False
    sae_pk: bool = False
    wpa3_only: bool = False


def parse_rsnxe(ies: bytes) -> RsnxeInfo | None:
    for tag, body, _ in iter_information_elements(ies):
        if tag != RSNXE_IE or not body:
            continue
        caps = body[0]
        return RsnxeInfo(
            caps=caps,
            sae_h2e=bool(caps & 0x40),
            sae_pk=bool(caps & 0x20),
            wpa3_only=bool(caps & 0x80),
        )
    return None