#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Active UART / serial client wrapper around pyserial."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import List, Optional, Union


PARITY_MAP = {
    "N": "N",
    "NONE": "N",
    "E": "E",
    "EVEN": "E",
    "O": "O",
    "ODD": "O",
    "M": "M",
    "MARK": "M",
    "S": "S",
    "SPACE": "S",
}


@dataclass
class UartExchange:
    success: bool
    command: str = ""
    request: bytes = b""
    response: bytes = b""
    text: str = ""
    error: str = ""


class UartClient:
    """Thin pyserial wrapper used by the UART listener and post modules."""

    def __init__(
        self,
        port: str,
        baudrate: int = 115200,
        bytesize: int = 8,
        parity: str = "N",
        stopbits: float = 1,
        timeout: float = 1.0,
        write_timeout: float = 1.0,
        xonxoff: bool = False,
        rtscts: bool = False,
        dsrdtr: bool = False,
    ):
        self.port = str(port)
        self.baudrate = int(baudrate)
        self.bytesize = int(bytesize)
        self.parity = PARITY_MAP.get(str(parity).upper(), "N")
        self.stopbits = float(stopbits)
        self.timeout = float(timeout)
        self.write_timeout = float(write_timeout)
        self.xonxoff = bool(xonxoff)
        self.rtscts = bool(rtscts)
        self.dsrdtr = bool(dsrdtr)
        self._ser = None

    @property
    def connected(self) -> bool:
        return self._ser is not None and getattr(self._ser, "is_open", False)

    def connect(self) -> bool:
        self.close()
        try:
            import serial
        except ImportError as exc:
            raise RuntimeError("pyserial is required (pip install pyserial)") from exc

        bytesize_map = {
            5: serial.FIVEBITS,
            6: serial.SIXBITS,
            7: serial.SEVENBITS,
            8: serial.EIGHTBITS,
        }
        stopbits_map = {
            1: serial.STOPBITS_ONE,
            1.5: serial.STOPBITS_ONE_POINT_FIVE,
            2: serial.STOPBITS_TWO,
        }
        parity_const = {
            "N": serial.PARITY_NONE,
            "E": serial.PARITY_EVEN,
            "O": serial.PARITY_ODD,
            "M": serial.PARITY_MARK,
            "S": serial.PARITY_SPACE,
        }

        try:
            self._ser = serial.Serial(
                port=self.port,
                baudrate=self.baudrate,
                bytesize=bytesize_map.get(self.bytesize, serial.EIGHTBITS),
                parity=parity_const.get(self.parity, serial.PARITY_NONE),
                stopbits=stopbits_map.get(self.stopbits, serial.STOPBITS_ONE),
                timeout=self.timeout,
                write_timeout=self.write_timeout,
                xonxoff=self.xonxoff,
                rtscts=self.rtscts,
                dsrdtr=self.dsrdtr,
            )
        except Exception:
            self._ser = None
            return False
        return True

    def close(self) -> None:
        if self._ser is not None:
            try:
                if self._ser.is_open:
                    self._ser.close()
            except Exception:
                pass
        self._ser = None

    def flush_input(self) -> None:
        if not self.connected:
            return
        try:
            self._ser.reset_input_buffer()
        except Exception:
            pass

    def flush_output(self) -> None:
        if not self.connected:
            return
        try:
            self._ser.reset_output_buffer()
        except Exception:
            pass

    def write(self, data: Union[bytes, str]) -> int:
        if not self.connected:
            raise RuntimeError("UART not connected")
        if isinstance(data, str):
            data = data.encode("utf-8", errors="replace")
        return int(self._ser.write(data) or 0)

    def read(self, size: int = 1024) -> bytes:
        if not self.connected:
            raise RuntimeError("UART not connected")
        return self._ser.read(size) or b""

    def read_available(self) -> bytes:
        if not self.connected:
            return b""
        waiting = getattr(self._ser, "in_waiting", 0) or 0
        if waiting <= 0:
            return b""
        return self._ser.read(waiting) or b""

    def read_for(self, duration: float, max_bytes: int = 65536) -> bytes:
        """Read whatever arrives within ``duration`` seconds."""
        if not self.connected:
            raise RuntimeError("UART not connected")
        deadline = time.time() + max(0.0, float(duration))
        chunks: List[bytes] = []
        total = 0
        while time.time() < deadline and total < max_bytes:
            remaining = deadline - time.time()
            if remaining <= 0:
                break
            old_timeout = self._ser.timeout
            try:
                self._ser.timeout = min(0.1, remaining)
                chunk = self._ser.read(min(4096, max_bytes - total))
            finally:
                self._ser.timeout = old_timeout
            if chunk:
                chunks.append(chunk)
                total += len(chunk)
            else:
                time.sleep(0.01)
        return b"".join(chunks)

    def read_until(self, expected: bytes, timeout: Optional[float] = None, max_bytes: int = 65536) -> bytes:
        if not self.connected:
            raise RuntimeError("UART not connected")
        if isinstance(expected, str):
            expected = expected.encode("utf-8", errors="replace")
        deadline = time.time() + float(timeout if timeout is not None else self.timeout)
        buf = bytearray()
        old_timeout = self._ser.timeout
        try:
            while time.time() < deadline and len(buf) < max_bytes:
                self._ser.timeout = min(0.1, max(0.0, deadline - time.time()))
                chunk = self._ser.read(1)
                if not chunk:
                    continue
                buf.extend(chunk)
                if expected and expected in buf:
                    break
        finally:
            self._ser.timeout = old_timeout
        return bytes(buf)

    def send_line(self, line: str, newline: str = "\r\n") -> int:
        payload = str(line)
        if newline and not payload.endswith(("\r", "\n")):
            payload += newline
        return self.write(payload)

    def exchange(
        self,
        command: str,
        wait: float = 1.0,
        newline: str = "\r\n",
        drain_first: bool = True,
    ) -> UartExchange:
        """Send a command line and collect the response for ``wait`` seconds."""
        try:
            if drain_first:
                self.flush_input()
            req = str(command)
            self.send_line(req, newline=newline)
            raw = self.read_for(wait)
            text = raw.decode("utf-8", errors="replace")
            return UartExchange(success=True, command=req, request=req.encode("utf-8", errors="replace"), response=raw, text=text)
        except Exception as exc:
            return UartExchange(success=False, command=str(command), error=str(exc))

    def send_break(self, duration: float = 0.25) -> None:
        if not self.connected:
            raise RuntimeError("UART not connected")
        # pyserial: duration in seconds
        self._ser.send_break(duration=max(0.01, float(duration)))

    def pulse_dtr(self, low_ms: int = 100) -> None:
        """Toggle DTR (often used as a hardware reset line)."""
        if not self.connected:
            raise RuntimeError("UART not connected")
        self._ser.dtr = False
        time.sleep(max(0.01, low_ms / 1000.0))
        self._ser.dtr = True

    def capture_banner(self, duration: float = 3.0, nudge: bool = True, newline: str = "\r\n") -> bytes:
        """Capture idle / boot output; optionally nudge with a newline."""
        self.flush_input()
        if nudge:
            try:
                self.write(newline.encode("utf-8", errors="replace"))
            except Exception:
                pass
        return self.read_for(duration)

    @staticmethod
    def decode_text(data: bytes) -> str:
        return data.decode("utf-8", errors="replace")

    def connection_summary(self) -> dict:
        return {
            "port": self.port,
            "baudrate": self.baudrate,
            "bytesize": self.bytesize,
            "parity": self.parity,
            "stopbits": self.stopbits,
            "timeout": self.timeout,
            "xonxoff": self.xonxoff,
            "rtscts": self.rtscts,
            "dsrdtr": self.dsrdtr,
            "connected": self.connected,
        }
