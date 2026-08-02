#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""RTSP bind listener — opens an interactive RTSP session toward a camera/NVR."""

from kittysploit import *
from lib.protocols.rtsp.client import RTSP_PORT, RtspClient, parse_rtsp_url


class Module(Listener):
    __info__ = {
        "name": "RTSP Client",
        "description": (
            "Connects to an RTSP/RTSPS endpoint, probes OPTIONS/DESCRIBE, and creates "
            "an interactive RTSP shell (describe, setup/play interleaved, teardown)."
        ),
        "author": "KittySploit Team",
        "version": "1.0.0",
        "handler": Handler.BIND,
        "session_type": SessionType.RTSP,
        "protocol": "rtsp",
        "tags": ["iot", "camera", "rtsp"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "produces": ["tech_hints", "endpoints"],
            "chain": {
                "produces_capabilities": ["rtsp_access", "ot_assets"],
                "suggested_followups": [
                    "post/rtsp/gather/describe_dump",
                    "post/rtsp/gather/stream_probe",
                ],
            },
        },
    }

    rhost = OptString("127.0.0.1", "Camera / NVR host", True)
    rport = OptPort(RTSP_PORT, "RTSP TCP port", True)
    path = OptString("/", "RTSP path (e.g. /Streaming/Channels/101)", False)
    url = OptString("", "Full rtsp:// URL (overrides host/port/path)", False)
    username = OptString("", "RTSP username", False)
    password = OptString("", "RTSP password", False)
    ssl = OptBool(False, "Use RTSPS (TLS)", False)

    def run(self):
        timeout = float(self.timeout or 5)
        url = str(self.url or "").strip()
        if url:
            parts = parse_rtsp_url(url)
            host = str(parts.get("host") or "")
            port = int(parts.get("port") or RTSP_PORT)
            path = str(parts.get("path") or "/")
            username = str(self.username or parts.get("username") or "")
            password = str(self.password or parts.get("password") or "")
            use_tls = str(parts.get("scheme") or "").lower() == "rtsps" or bool(self.ssl)
            client = RtspClient(
                url=url,
                username=username,
                password=password,
                timeout=timeout,
                use_tls=use_tls,
            )
        else:
            host = str(self.rhost).strip()
            port = int(self.rport or RTSP_PORT)
            path = str(self.path or "/")
            username = str(self.username or "")
            password = str(self.password or "")
            use_tls = bool(self.ssl)
            client = RtspClient(
                host=host,
                port=port,
                path=path,
                username=username,
                password=password,
                timeout=timeout,
                use_tls=use_tls,
            )

        scheme = "rtsps" if use_tls else "rtsp"
        print_status(f"Probing {scheme}://{host}:{port}{path}...")
        if not client.connect():
            print_error(client.last_error or "RTSP connect/OPTIONS failed")
            return False

        if client.last_options:
            print_success(f"OPTIONS: {', '.join(client.last_options)}")
        if client.server:
            print_info(f"Server: {client.server}")

        desc = client.describe()
        if desc.auth_required:
            print_warning("DESCRIBE requires authentication")
        elif desc.error:
            print_warning(desc.error)
        else:
            print_success(f"DESCRIBE ok — {len(desc.media)} media track(s)")
            for media in desc.media:
                print_info(
                    f"  {media.media_type} encoding={media.encoding or '?'} "
                    f"control={media.control or '-'}"
                )

        additional_data = {
            "host": host,
            "port": port,
            "path": path,
            "url": client.request_uri,
            "username": username,
            "password": password,
            "use_tls": use_tls,
            "ssl": use_tls,
            "protocol": "rtsps" if use_tls else "rtsp",
            "platform": "iot",
            "server": client.server,
            "options": list(client.last_options),
            "timeout": timeout,
        }
        return (client, host, port, additional_data)

    def shutdown(self):
        return True
