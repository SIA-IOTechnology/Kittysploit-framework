#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WebSocket reverse listener - accept WebSocket connections for interactive shell.
Differentiates KittySploit from Metasploit (no native WebSocket listener).
"""

from kittysploit import *
import socket
import threading
import queue
import time

try:
    import asyncio
    import websockets
    from websockets.server import serve
    WEBSOCKETS_AVAILABLE = True
except ImportError:
    WEBSOCKETS_AVAILABLE = False


class SyncWebSocketWrapper:
    """Wraps an async WebSocket to provide sync sendall/recv/settimeout for ClassicShell."""

    def __init__(self, ws, loop):
        self._ws = ws
        self._loop = loop
        self._recv_queue = queue.Queue()
        self._timeout = 30.0
        self._closed = False
        self._recv_thread = threading.Thread(target=self._recv_worker, daemon=True)
        self._recv_thread.start()

    def _recv_worker(self):
        while not self._closed and self._ws.open:
            try:
                future = asyncio.run_coroutine_threadsafe(self._ws.recv(), self._loop)
                data = future.result(timeout=1.0)
                if data is None:
                    break
                if isinstance(data, str):
                    data = data.encode('utf-8')
                self._recv_queue.put(data)
            except Exception:
                if self._closed:
                    break
                try:
                    self._recv_queue.put(None)
                except Exception:
                    pass
                break

    def sendall(self, data):
        if isinstance(data, str):
            data = data.encode('utf-8')
        if self._closed or not self._ws.open:
            raise BrokenPipeError("WebSocket closed")
        future = asyncio.run_coroutine_threadsafe(self._ws.send(data), self._loop)
        future.result(timeout=5.0)

    def recv(self, bufsize):
        try:
            data = self._recv_queue.get(timeout=self._timeout)
            if data is None:
                return b''
            return data[:bufsize] if len(data) > bufsize else data
        except queue.Empty:
            raise socket.timeout("recv timeout")

    def settimeout(self, timeout):
        self._timeout = float(timeout) if timeout else 30.0

    def close(self):
        self._closed = True
        if self._ws.open:
            try:
                asyncio.run_coroutine_threadsafe(self._ws.close(), self._loop).result(timeout=2.0)
            except Exception:
                pass

    @property
    def open(self):
        return not self._closed and self._ws.open


class Module(Listener):

    __info__ = {
        'name': 'WebSocket Listener',
        'description': 'Reverse WebSocket listener - accepts WebSocket connections for interactive shell (differentiator vs Metasploit)',
        'author': 'KittySploit Team',
        'version': '1.0.0',
        'handler': Handler.REVERSE,
        'session_type': SessionType.WEBSOCKET,
        'references': [
            'https://datatracker.ietf.org/doc/html/rfc6455',
        ],
        'dependencies': ['websockets'],
    }

    lhost = OptString("0.0.0.0", "Local bind address", True)
    lport = OptPort(8765, "Local WebSocket port", True)
    path = OptString("/ws", "WebSocket path (URL path)", True)

    def run(self):
        if not WEBSOCKETS_AVAILABLE:
            print_error("websockets is required but not installed")
            print_info("Install it with: pip install websockets")
            return False

        host = str(self.lhost).strip() if self.lhost else "0.0.0.0"
        port = int(self.lport) if self.lport else 8765
        path = str(self.path).strip() if self.path else "/ws"
        if not path.startswith("/"):
            path = "/" + path

        # Shared state: filled by server thread when a client connects
        connection_ready = threading.Event()
        accepted_ws_ref = []
        accepted_peer_ref = []
        server_loop_ref = []

        async def handler(websocket, request_path=None):
            remote = getattr(websocket, "remote_address", None)
            if not remote and hasattr(websocket, "request"):
                remote = getattr(getattr(websocket, "request", None), "remote", None)
            if not remote:
                remote = ("0.0.0.0", 0)
            accepted_peer_ref.append((remote[0], remote[1]))
            accepted_ws_ref.append(websocket)
            connection_ready.set()
            try:
                await websocket.wait_closed()
            except Exception:
                pass

        async def run_server():
            async with serve(handler, host, port, ping_interval=20, ping_timeout=20):
                server_loop_ref.append(asyncio.get_running_loop())
                await asyncio.Event().wait()  # run forever until task cancelled

        def server_thread_fn():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                loop.run_until_complete(run_server())
            except asyncio.CancelledError:
                pass
            finally:
                loop.close()

        try:
            print_status(f"Starting WebSocket server on ws://{host}:{port}{path}")
            print_status("Waiting for connection...")
            server_thread = threading.Thread(target=server_thread_fn, daemon=True)
            server_thread.start()
            # Wait for one connection (or stop_flag)
            while not connection_ready.wait(timeout=0.5):
                if self.stop_flag.is_set():
                    return False

            if not accepted_ws_ref or not accepted_peer_ref or not server_loop_ref:
                if self.stop_flag.is_set():
                    return False
                return None

            ws = accepted_ws_ref[0]
            peer = accepted_peer_ref[0]
            target, port_num = peer[0], peer[1]
            loop = server_loop_ref[0]
            print_success(f"WebSocket connection from {target}:{port_num}")

            # Wrapper uses the SAME loop that owns the WebSocket (server thread)
            wrapper = SyncWebSocketWrapper(ws, loop)

            additional_data = {
                'path': path,
                'protocol': 'websocket',
                'connection_type': 'reverse',
            }
            return (wrapper, target, port_num, additional_data)

        except asyncio.CancelledError:
            return None
        except Exception as e:
            if not self.stop_flag.is_set():
                print_error(f"WebSocket listener error: {e}")
            return False

    def shutdown(self):
        try:
            if hasattr(self, '_session_connections'):
                for session_id, conn in list(self._session_connections.items()):
                    if conn and hasattr(conn, 'close'):
                        conn.close()
        except Exception:
            pass
