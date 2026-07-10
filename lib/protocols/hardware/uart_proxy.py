#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
UART proxy engine — bidirectional serial MITM with capture, replay, and
in-flight pattern replacement (inspired by Akheron).
"""

from __future__ import annotations

import functools
import operator
import re
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence, Tuple


class ChecksumMethod(Enum):
    NONE = ""
    XOR = "xor"
    MOD256 = "mod256"
    MOD256_PLUS1 = "mod256+1"
    TWOS_COMPLEMENT = "2s"

    @classmethod
    def from_name(cls, value: str) -> "ChecksumMethod":
        raw = str(value or "").strip().lower()
        if not raw:
            return cls.NONE
        for member in cls:
            if member.value == raw or member.name.lower() == raw:
                return member
        raise ValueError(
            f"Unknown checksum method: {value!r} "
            f"(supported: {', '.join(m.value for m in cls if m.value)})"
        )


@dataclass
class ReplaceRule:
    pattern: bytes
    replacement: bytes


@dataclass
class UartProxyConfig:
    port_a: str
    port_b: str
    baud_a: int = 115200
    baud_b: int = 115200
    replace_a: List[ReplaceRule] = field(default_factory=list)
    replace_b: List[ReplaceRule] = field(default_factory=list)
    checksum_a: ChecksumMethod = ChecksumMethod.NONE
    checksum_b: ChecksumMethod = ChecksumMethod.NONE
    exclude_delim_checksum: bool = False
    start_delims: List[bytes] = field(default_factory=list)
    capture_path: Optional[str] = None
    watch: bool = True


_HEX_TOKEN = re.compile(r"0x[0-9a-fA-F]+|[0-9a-fA-F]{2}")


def parse_hex_bytes(text: str) -> bytes:
    """Parse a space-separated hex byte sequence (0x01 or 01)."""
    tokens = _HEX_TOKEN.findall(str(text or "").strip())
    if not tokens:
        return b""
    out = bytearray()
    for token in tokens:
        out.append(int(token, 16))
    return bytes(out)


def parse_delimiter_list(text: str) -> List[bytes]:
    """Parse comma-separated delimiter patterns."""
    raw = str(text or "").strip()
    if not raw:
        return []
    return [parse_hex_bytes(part) for part in raw.split(",") if part.strip()]


def parse_replace_rules(text: str) -> List[ReplaceRule]:
    """
    Parse replacement rules: ``01 02 -> 03 04, AA -> BB``.
    Arrow separates match pattern from replacement bytes.
    """
    raw = str(text or "").strip()
    if not raw:
        return []
    rules: List[ReplaceRule] = []
    for chunk in raw.split(","):
        piece = chunk.strip()
        if not piece or "->" not in piece:
            continue
        lhs, rhs = piece.split("->", 1)
        pattern = parse_hex_bytes(lhs)
        replacement = parse_hex_bytes(rhs)
        if pattern:
            rules.append(ReplaceRule(pattern=pattern, replacement=replacement))
    return rules


def calculate_checksum(data: Sequence[int], method: ChecksumMethod) -> Optional[int]:
    if method == ChecksumMethod.NONE or not data:
        return None
    if method == ChecksumMethod.XOR:
        return functools.reduce(operator.xor, data, 0)
    total = sum(data) % 256
    if method == ChecksumMethod.MOD256:
        return total
    if method == ChecksumMethod.MOD256_PLUS1:
        return (total + 1) % 256
    if method == ChecksumMethod.TWOS_COMPLEMENT:
        return (-(sum(data) % 256)) & 0xFF
    return None


def _index_after_start_delimiter(data: bytearray, delims: Sequence[bytes]) -> int:
    for delim in delims:
        if len(data) >= len(delim) and bytes(data[: len(delim)]) == delim:
            return len(delim)
    return 0


def apply_pattern_replacements(
    data: bytes,
    rules: Sequence[ReplaceRule],
    checksum: ChecksumMethod = ChecksumMethod.NONE,
    start_delims: Optional[Sequence[bytes]] = None,
    exclude_delim_checksum: bool = False,
) -> bytes:
    """Replace byte patterns in-place and optionally refresh the trailing checksum."""
    if not rules and checksum == ChecksumMethod.NONE:
        return data

    buf = bytearray(data)
    for rule in rules:
        pattern = rule.pattern
        replacement = rule.replacement
        if not pattern:
            continue
        idx = 0
        plen = len(pattern)
        while idx <= len(buf) - plen:
            if bytes(buf[idx : idx + plen]) == pattern:
                buf[idx : idx + plen] = replacement
                idx += len(replacement)
            else:
                idx += 1

    if checksum != ChecksumMethod.NONE and buf:
        if exclude_delim_checksum and start_delims:
            start = _index_after_start_delimiter(buf, start_delims)
            payload = buf[start:-1]
        else:
            payload = buf[:-1]
        value = calculate_checksum(payload, checksum)
        if value is not None:
            buf[-1] = value
    return bytes(buf)


def format_hex_line(direction: str, data: bytes) -> str:
    hex_part = " ".join(f"0x{b:02x}" for b in data)
    return f"{direction}: {hex_part} "


def list_serial_ports(verbose: bool = False) -> List[Dict[str, str]]:
    import serial.tools.list_ports

    entries: List[Dict[str, str]] = []
    for info in sorted(serial.tools.list_ports.comports()):
        entry = {"device": info.device, "description": info.description or "", "hwid": info.hwid or ""}
        entries.append(entry)
        if verbose:
            print(f"{info.device}")
            print(f"    desc: {info.description}")
            print(f"    hwid: {info.hwid}")
        else:
            print(info.device)
    return entries


def parse_replay_lines(spec: str, max_line: int) -> List[int]:
    raw = str(spec or "").strip()
    if not raw:
        return list(range(1, max_line + 1))
    selected: List[int] = []
    for chunk in raw.split(","):
        piece = chunk.strip()
        if not piece:
            continue
        if "-" in piece:
            start_s, end_s = piece.split("-", 1)
            start = int(start_s)
            end = int(end_s)
            selected.extend(range(start, end + 1))
        else:
            selected.append(int(piece))
    return sorted(set(line for line in selected if 1 <= line <= max_line))


class UartProxy:
    """Bidirectional UART MITM between two serial devices."""

    def __init__(self, config: UartProxyConfig):
        self.config = config
        self._running = False
        self._threads: List[threading.Thread] = []
        self._ports: Dict[str, object] = {}
        self._locks = {"A": threading.Lock(), "B": threading.Lock()}
        self._capture_file = None
        self._capture_lock = threading.Lock()
        self._writer: Callable[[str, bytes], None] = self._default_writer

    def set_writer(self, writer: Callable[[str, bytes], None]) -> None:
        self._writer = writer

    def _default_writer(self, direction: str, data: bytes) -> None:
        if not self.config.watch:
            return
        line = format_hex_line(direction, data)
        print(line, end="", flush=True)

    def _open_capture(self) -> bool:
        path = self.config.capture_path
        if not path:
            return True
        try:
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            self._capture_file = open(path, "w", encoding="utf-8")
            return True
        except OSError as exc:
            raise RuntimeError(f"Cannot open capture file {path}: {exc}") from exc

    def _close_capture(self) -> None:
        if self._capture_file:
            self._capture_file.close()
            self._capture_file = None

    def _record(self, direction: str, data: bytes) -> None:
        line = format_hex_line(direction, data)
        with self._capture_lock:
            if self._capture_file:
                self._capture_file.write(line + "\n")
                self._capture_file.flush()
        self._writer(direction, data)

    def _process_chunk(self, data: bytes, src: str, dst: str) -> bytes:
        rules = self.config.replace_a if src == "A" else self.config.replace_b
        checksum = self.config.checksum_a if src == "A" else self.config.checksum_b
        return apply_pattern_replacements(
            data,
            rules,
            checksum=checksum,
            start_delims=self.config.start_delims,
            exclude_delim_checksum=self.config.exclude_delim_checksum,
        )

    def _forward_loop(self, src_label: str, dst_label: str) -> None:
        import serial

        src = self._ports[src_label]
        dst = self._ports[dst_label]
        direction = f"{src_label} -> {dst_label}"
        while self._running:
            try:
                waiting = src.in_waiting
                if waiting:
                    raw = src.read(waiting)
                    if not raw:
                        continue
                    processed = self._process_chunk(raw, src_label, dst_label)
                    with self._locks[dst_label]:
                        dst.write(processed)
                    self._record(direction, processed)
                else:
                    time.sleep(0.002)
            except serial.SerialException:
                break

    def start(self) -> bool:
        import serial

        cfg = self.config
        if not cfg.port_a or not cfg.port_b:
            raise ValueError("Both port_a and port_b are required")
        if cfg.port_a == cfg.port_b:
            raise ValueError("port_a and port_b must be different devices")

        try:
            self._ports["A"] = serial.Serial(cfg.port_a, cfg.baud_a, timeout=0)
            self._ports["B"] = serial.Serial(cfg.port_b, cfg.baud_b, timeout=0)
        except serial.SerialException as exc:
            self.stop()
            raise RuntimeError(f"Serial open failed: {exc}") from exc

        self._open_capture()
        self._running = True
        self._threads = [
            threading.Thread(target=self._forward_loop, args=("A", "B"), daemon=True),
            threading.Thread(target=self._forward_loop, args=("B", "A"), daemon=True),
        ]
        for thread in self._threads:
            thread.start()
        return True

    def stop(self) -> None:
        self._running = False
        for thread in self._threads:
            thread.join(timeout=1.5)
        self._threads = []
        for port in self._ports.values():
            try:
                if port.is_open:
                    port.close()
            except Exception:
                pass
        self._ports = {}
        self._close_capture()

    def run_for(self, seconds: int = 0) -> None:
        if seconds <= 0:
            while self._running:
                time.sleep(0.25)
            return
        deadline = time.time() + seconds
        while self._running and time.time() < deadline:
            time.sleep(0.25)


def replay_capture(
    capture_path: str,
    port_a: str,
    port_b: str,
    baud_a: int = 115200,
    baud_b: int = 115200,
    line_spec: str = "",
    replace_a: Optional[Sequence[ReplaceRule]] = None,
    replace_b: Optional[Sequence[ReplaceRule]] = None,
    checksum_a: ChecksumMethod = ChecksumMethod.NONE,
    checksum_b: ChecksumMethod = ChecksumMethod.NONE,
    start_delims: Optional[Sequence[bytes]] = None,
    exclude_delim_checksum: bool = False,
    watch: bool = True,
) -> int:
    """
    Replay lines from an Akheron-style capture file.

    Returns the number of lines replayed.
    """
    import serial

    path = Path(capture_path)
    if not path.is_file():
        raise FileNotFoundError(f"Capture file not found: {capture_path}")

    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    selected = parse_replay_lines(line_spec, len(lines))
    if not selected:
        return 0

    replace_a = list(replace_a or [])
    replace_b = list(replace_b or [])
    start_delims = list(start_delims or [])

    direction = "unknown"
    for index, line in enumerate(lines, start=1):
        if line.startswith("A -> B") or line.startswith("B -> A"):
            direction = line.split(":", 1)[0].strip()
            if index in selected:
                break
    if direction == "unknown":
        raise ValueError("Could not detect replay direction from capture file")

    if direction == "A -> B":
        device, baud = port_a, baud_a
        src, rules, checksum = "A", replace_a, checksum_a
        out_dev_id = "B"
    else:
        device, baud = port_b, baud_b
        src, rules, checksum = "B", replace_b, checksum_b
        out_dev_id = "A"

    replayed = 0
    current_direction = "unknown"
    with serial.Serial(device, baud, timeout=1) as out_port:
        for line_no, line in enumerate(lines, start=1):
            if line.startswith("A -> B") or line.startswith("B -> A"):
                current_direction = line.split(":", 1)[0].strip()
                payload_text = line.split(":", 1)[1]
            else:
                payload_text = line
            if line_no not in selected or current_direction != direction:
                continue
            tokens = _HEX_TOKEN.findall(payload_text)
            if not tokens:
                continue
            data = bytes(int(token, 16) for token in tokens)
            data = apply_pattern_replacements(
                data,
                rules,
                checksum=checksum,
                start_delims=start_delims,
                exclude_delim_checksum=exclude_delim_checksum,
            )
            out_port.write(data)
            replayed += 1
            if watch:
                print(format_hex_line(f"replay {direction} -> {out_dev_id}", data))
    return replayed
