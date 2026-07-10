#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Monitor socket-backed sessions and emit disconnect alerts."""

from __future__ import annotations

import errno
import socket
import threading
import time
import uuid
from typing import Any, Callable, Optional


def _resolve_socket(inner: Any):
    if hasattr(inner, "_sock"):
        return inner._sock
    if hasattr(inner, "fileno"):
        return inner
    return None


class PrefixedStream:
    """Prepends bytes to the first recv() calls (unread handshake data)."""

    def __init__(self, inner: Any, prefix: bytes = b""):
        self._inner = inner
        self._prefix = bytearray(prefix or b"")

    def recv(self, bufsize: int) -> bytes:
        if self._prefix:
            out = bytes(self._prefix[:bufsize])
            del self._prefix[: len(out)]
            if len(out) < bufsize and hasattr(self._inner, "recv"):
                out += self._inner.recv(bufsize - len(out))
            return out
        return self._inner.recv(bufsize)

    def sendall(self, data) -> None:
        return self._inner.sendall(data)

    def send(self, data):
        return self._inner.send(data)

    def settimeout(self, timeout) -> None:
        if hasattr(self._inner, "settimeout"):
            self._inner.settimeout(timeout)

    def close(self) -> None:
        if hasattr(self._inner, "close"):
            self._inner.close()

    def shutdown(self, how=socket.SHUT_RDWR) -> None:
        if hasattr(self._inner, "shutdown"):
            self._inner.shutdown(how)

    def getpeername(self):
        return self._inner.getpeername()

    def __getattr__(self, name):
        return getattr(self._inner, name)


class MonitoredConnection:
    """Proxy that notifies when the peer closes the underlying socket (MSG_PEEK)."""

    def __init__(
        self,
        inner: Any,
        *,
        session_id: str,
        on_disconnect: Optional[Callable[[str, str, str], None]] = None,
        label: str = "",
        poll_interval: float = 3.0,
    ):
        self._inner = inner
        self._session_id = session_id
        self._on_disconnect = on_disconnect
        self._label = label or session_id[:8]
        self.connection_id = str(uuid.uuid4())
        self._closed = False
        self._local_close = False
        self._notified = False
        self._lock = threading.Lock()
        self._poll_interval = max(1.0, float(poll_interval))
        self._bootstrap_grace = 2.0
        self._started = time.monotonic()
        self._watch_thread: Optional[threading.Thread] = None
        if _resolve_socket(inner) is not None:
            self._watch_thread = threading.Thread(target=self._watch_loop, daemon=True)
            self._watch_thread.start()

    def _peek_closed(self) -> bool:
        """Return True only when the peer has closed the TCP session (not on recv timeout)."""
        sock = _resolve_socket(self._inner)
        if sock is None:
            return False
        old_timeout = None
        try:
            if hasattr(sock, "gettimeout"):
                try:
                    old_timeout = sock.gettimeout()
                except Exception:
                    old_timeout = None
            if hasattr(sock, "settimeout"):
                sock.settimeout(0.0)
            if hasattr(socket, "MSG_PEEK"):
                chunk = sock.recv(1, socket.MSG_PEEK)
            else:
                return False
            # True EOF: peer closed write side.
            return chunk == b""
        except (BlockingIOError, TimeoutError, socket.timeout):
            # No bytes waiting — normal while the remote is executing a command.
            return False
        except OSError as exc:
            if getattr(exc, "errno", None) in (errno.EAGAIN, errno.EWOULDBLOCK):
                return False
            return True
        finally:
            if hasattr(sock, "settimeout"):
                try:
                    sock.settimeout(old_timeout)
                except Exception:
                    pass

    def _watch_loop(self) -> None:
        time.sleep(self._bootstrap_grace)
        while not self._closed:
            time.sleep(self._poll_interval)
            if self._closed:
                break
            if self._peek_closed():
                self._notify()
                break

    def _notify(self) -> None:
        with self._lock:
            if self._notified or self._local_close:
                return
            self._closed = True
            self._notified = True
        cb = self._on_disconnect
        if cb:
            try:
                cb(self._session_id, self._label, self.connection_id)
            except Exception:
                pass

    def __getattr__(self, name):
        return getattr(self._inner, name)

    def sendall(self, data):
        if self._closed:
            raise BrokenPipeError("session disconnected")
        return self._inner.sendall(data)

    def send(self, data):
        if self._closed:
            raise BrokenPipeError("session disconnected")
        return self._inner.send(data)

    def recv(self, bufsize):
        try:
            data = self._inner.recv(bufsize)
        except TimeoutError:
            raise
        except BlockingIOError:
            raise
        except OSError as exc:
            if exc.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                raise
            self._notify()
            raise
        if not data:
            if time.monotonic() - self._started < self._bootstrap_grace:
                raise TimeoutError("bootstrap grace")
            self._notify()
        return data

    def close(self):
        with self._lock:
            self._local_close = True
            self._closed = True
        if hasattr(self._inner, "close"):
            self._inner.close()

    def shutdown(self, how=socket.SHUT_RDWR):
        with self._lock:
            self._local_close = True
        if hasattr(self._inner, "shutdown"):
            self._inner.shutdown(how)


def wrap_monitored_connection(
    connection: Any,
    session_id: str,
    framework=None,
    *,
    label: str = "",
) -> Any:
    if connection is None or not hasattr(connection, "recv"):
        return connection

    def _on_disconnect(sid: str, lbl: str, connection_token: str) -> None:
        if framework and hasattr(framework, "notify_session_disconnected"):
            framework.notify_session_disconnected(
                sid,
                reason="connection_lost",
                label=lbl,
                connection_token=connection_token,
            )
            return
        from core.output_handler import print_warning

        print_warning(f"Session {sid} disconnected ({lbl})")

    return MonitoredConnection(
        connection,
        session_id=session_id,
        on_disconnect=_on_disconnect,
        label=label,
    )


def read_identity_hello(connection: Any, public_key_pem: str, timeout: float = 3.0) -> tuple[str, Any]:
    """
    Read KSID hello line, verify signature, return (implant_id, stream).

    Remaining bytes are prepended for downstream consumers.
    """
    from lib.implant.identity import verify_identity_hello

    if hasattr(connection, "settimeout"):
        connection.settimeout(timeout)
    buf = b""
    while b"\n" not in buf and len(buf) < 512:
        chunk = connection.recv(1)
        if not chunk:
            break
        buf += chunk
    if b"\n" not in buf:
        return "", PrefixedStream(connection, buf)
    line, _, rest = buf.partition(b"\n")
    implant_id = verify_identity_hello(line.decode("utf-8", errors="replace"), public_key_pem)
    return implant_id, PrefixedStream(connection, rest)
