"""HackRF host utilities via Great Scott Gadgets command-line tools."""

from __future__ import annotations

import csv
import io
import platform
import re
import shutil
import subprocess
from typing import Any, Dict, List, Optional, Tuple

_WIN_CREATION = getattr(subprocess, "CREATE_NO_WINDOW", 0)
_HACKRF_USB = re.compile(r"1d50:6089", re.I)
_SERIAL_RE = re.compile(r"Serial\s*(?:number)?:\s*([0-9a-f]{32})", re.I)
_BOARD_RE = re.compile(r"Board\s*ID\s*(?:Number)?:\s*(\d+)", re.I)


def hackrf_tools_available() -> bool:
    return bool(shutil.which("hackrf_info"))


def _run(cmd: List[str], timeout: float = 30.0) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        creationflags=_WIN_CREATION,
    )


def parse_hackrf_info(text: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {"serial": "", "board_id": "", "firmware": "", "raw": text.strip()}
    for line in text.splitlines():
        low = line.lower()
        if "firmware" in low and not out["firmware"]:
            out["firmware"] = line.split(":", 1)[-1].strip() if ":" in line else line.strip()
    m = _SERIAL_RE.search(text)
    if m:
        out["serial"] = m.group(1).lower()
    b = _BOARD_RE.search(text)
    if b:
        out["board_id"] = b.group(1)
    return out


def hackrf_info(serial: str = "") -> Dict[str, Any]:
    if not hackrf_tools_available():
        return {"error": "hackrf_info not found — install HackRF host tools", "tools": False}
    cmd = ["hackrf_info"]
    if serial:
        cmd.extend(["-d", serial.strip()])
    proc = _run(cmd, timeout=12)
    merged = (proc.stdout or "") + "\n" + (proc.stderr or "")
    if proc.returncode != 0 and "No HackRF boards found" in merged:
        return {"error": "No HackRF boards found", "tools": True}
    if proc.returncode != 0:
        return {"error": (proc.stderr or proc.stdout or "hackrf_info failed").strip(), "tools": True}
    meta = parse_hackrf_info(merged)
    meta["tools"] = True
    meta["ok"] = True
    return meta


def _usb_hackrf_lines() -> List[str]:
    system = platform.system().lower()
    if system.startswith("win"):
        try:
            proc = _run(
                [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    "Get-PnpDevice -PresentOnly | Where-Object { "
                    "$_.InstanceId -match 'VID_1D50&PID_6089' -or $_.FriendlyName -match 'HackRF' } | "
                    "Select-Object FriendlyName,InstanceId,Status | Format-List",
                ],
                timeout=15,
            )
            if proc.returncode == 0:
                return [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()]
        except (OSError, subprocess.TimeoutExpired):
            pass
        return []
    if shutil.which("lsusb"):
        proc = _run(["lsusb"], timeout=10)
        return [ln for ln in proc.stdout.splitlines() if _HACKRF_USB.search(ln)]
    return []


def list_hackrf_devices() -> List[Dict[str, Any]]:
    """Enumerate HackRF boards (hackrf_info + USB hints)."""
    devices: List[Dict[str, Any]] = []
    tools = hackrf_tools_available()

    if tools:
        meta = hackrf_info()
        if meta.get("ok") and meta.get("serial"):
            devices.append(
                {
                    "id": meta["serial"],
                    "serial": meta["serial"],
                    "name": f"HackRF One ({meta['serial'][:8]}…)",
                    "description": f"Board {meta.get('board_id') or '?'} — firmware {meta.get('firmware') or 'unknown'}",
                    "state": "ok",
                    "source": "hackrf_info",
                    "tools": True,
                }
            )

    for idx, line in enumerate(_usb_hackrf_lines()):
        serial = ""
        if "serial" in line.lower():
            m = re.search(r"([0-9a-f]{32})", line, re.I)
            if m:
                serial = m.group(1).lower()
        dev_id = serial or f"usb-hackrf-{idx}"
        if any(d.get("id") == dev_id or d.get("serial") == dev_id for d in devices):
            continue
        devices.append(
            {
                "id": dev_id,
                "serial": serial,
                "name": "HackRF One (USB)",
                "description": line[:120],
                "state": "usb",
                "source": "usb",
                "tools": tools,
            }
        )

    if not devices and tools:
        probe = hackrf_info()
        if probe.get("error") == "No HackRF boards found":
            pass
    return devices


def _parse_sweep_line(row: List[str]) -> List[Tuple[float, float]]:
    if len(row) < 7:
        return []
    try:
        hz_low = float(row[2])
        hz_high = float(row[3])
        bin_w = float(row[4])
        powers = [float(v) for v in row[6:]]
    except ValueError:
        return []
    if not powers or bin_w <= 0:
        return []
    out: List[Tuple[float, float]] = []
    for i, power in enumerate(powers):
        freq_mhz = (hz_low + (i * bin_w)) / 1_000_000.0
        out.append((freq_mhz, power))
    return out


def parse_hackrf_sweep_csv(text: str, top_n: int = 40) -> List[Dict[str, Any]]:
    peaks: List[Tuple[float, float]] = []
    reader = csv.reader(io.StringIO(text))
    for row in reader:
        if not row or row[0].startswith("#"):
            continue
        peaks.extend(_parse_sweep_line(row))

    if not peaks and text.strip():
        for line in text.splitlines():
            if "," not in line:
                continue
            row = next(csv.reader([line]))
            peaks.extend(_parse_sweep_line(row))

    peaks.sort(key=lambda item: item[1], reverse=True)
    uniq: Dict[str, Dict[str, Any]] = {}
    for freq_mhz, power in peaks:
        key = f"{freq_mhz:.3f}"
        if key not in uniq or power > uniq[key]["power_db"]:
            uniq[key] = {"freq_mhz": round(freq_mhz, 3), "power_db": round(power, 2)}
    ranked = sorted(uniq.values(), key=lambda x: x["power_db"], reverse=True)[: max(1, top_n)]
    return ranked


def sweep_peaks(
    start_mhz: float,
    stop_mhz: float,
    *,
    bin_width_hz: int = 1_000_000,
    serial: str = "",
    lna_gain: int = 16,
    vga_gain: int = 20,
    one_shot: bool = True,
    top_n: int = 40,
    timeout: float = 120.0,
) -> Dict[str, Any]:
    if not hackrf_tools_available():
        return {"error": "hackrf_sweep not available — install HackRF tools", "peaks": []}
    if not shutil.which("hackrf_sweep"):
        return {"error": "hackrf_sweep binary not found", "peaks": []}
    if stop_mhz <= start_mhz:
        return {"error": "stop_mhz must exceed start_mhz", "peaks": []}

    cmd = [
        "hackrf_sweep",
        "-f",
        f"{int(start_mhz)}:{int(stop_mhz)}",
        "-w",
        str(int(bin_width_hz)),
        "-l",
        str(int(lna_gain)),
        "-g",
        str(int(vga_gain)),
    ]
    if one_shot:
        cmd.append("-1")
    if serial:
        cmd.extend(["-d", serial.strip()])

    proc = _run(cmd, timeout=timeout)
    text = (proc.stdout or "") + "\n" + (proc.stderr or "")
    if proc.returncode != 0 and not text.strip():
        return {"error": (proc.stderr or proc.stdout or "hackrf_sweep failed").strip(), "peaks": []}

    peaks = parse_hackrf_sweep_csv(text, top_n=top_n)
    return {
        "peaks": peaks,
        "range_mhz": [start_mhz, stop_mhz],
        "bin_width_hz": bin_width_hz,
        "count": len(peaks),
    }


def hackrf_transfer_tx(
    iq_path: str,
    freq_hz: int,
    sample_rate_hz: int = 2_000_000,
    tx_gain: int = 0,
    serial: str = "",
    repeat: bool = False,
) -> Dict[str, Any]:
    if not shutil.which("hackrf_transfer"):
        return {"error": "hackrf_transfer not found"}
    cmd = [
        "hackrf_transfer",
        "-t",
        iq_path,
        "-f",
        str(int(freq_hz)),
        "-s",
        str(int(sample_rate_hz)),
        "-x",
        str(int(tx_gain)),
    ]
    if repeat:
        cmd.append("-R")
    if serial:
        cmd.extend(["-d", serial.strip()])
    proc = _run(cmd, timeout=600)
    if proc.returncode != 0:
        return {"error": (proc.stderr or proc.stdout or "hackrf_transfer failed").strip()}
    return {"ok": True}