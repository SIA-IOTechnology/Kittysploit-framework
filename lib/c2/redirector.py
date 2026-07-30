#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""C2 redirector config generators (nginx / Apache / Caddy)."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from lib.c2.beacon_profile import BeaconProfile, _DEFAULT_DECOYS


SUPPORTED_ENGINES = ("nginx", "apache", "caddy")


@dataclass
class RedirectorSpec:
    """Parameters for generating a C2 redirector / reverse-proxy config."""

    backend_host: str = "127.0.0.1"
    backend_port: int = 8088
    uri_prefix: str = "/c2"
    listen_port: int = 443
    server_name: str = "_"
    decoy_paths: List[str] = field(default_factory=lambda: list(_DEFAULT_DECOYS))
    # Domain fronting: Host header the redirector sends to the teamserver backend
    domain_front_header: str = ""
    # Public CDN / front hostname operators point implants at (docs only in comments)
    payload_comms_host: str = ""
    use_tls: bool = False
    ssl_cert: str = "/etc/ssl/certs/redirector.crt"
    ssl_key: str = "/etc/ssl/private/redirector.key"
    fallback_status: int = 404

    @property
    def prefix(self) -> str:
        return "/" + str(self.uri_prefix or "/c2").strip("/")

    @property
    def poll_uri(self) -> str:
        return f"{self.prefix}/poll"

    @property
    def result_uri(self) -> str:
        return f"{self.prefix}/result"

    @property
    def backend(self) -> str:
        return f"{self.backend_host}:{int(self.backend_port)}"

    def normalized_decoys(self) -> List[str]:
        out: List[str] = []
        seen = set()
        for raw in self.decoy_paths or []:
            path = str(raw or "").strip() or "/"
            if not path.startswith("/"):
                path = "/" + path
            # Avoid shadowing C2 endpoints
            if path.rstrip("/") in (self.prefix.rstrip("/"), self.poll_uri, self.result_uri):
                continue
            if path in seen:
                continue
            seen.add(path)
            out.append(path)
        return out

    @classmethod
    def from_profile(
        cls,
        profile: Optional[BeaconProfile] = None,
        *,
        backend_host: str = "127.0.0.1",
        backend_port: int = 8088,
        uri_prefix: str = "/c2",
        listen_port: int = 443,
        server_name: str = "_",
        use_tls: bool = False,
        **kwargs: Any,
    ) -> "RedirectorSpec":
        profile = profile or BeaconProfile()
        decoys = list(profile.decoy_paths or _DEFAULT_DECOYS)
        return cls(
            backend_host=backend_host,
            backend_port=int(backend_port),
            uri_prefix=uri_prefix or "/c2",
            listen_port=int(listen_port),
            server_name=server_name or "_",
            decoy_paths=decoys,
            domain_front_header=str(
                kwargs.get("domain_front_header")
                or profile.host_header
                or ""
            ).strip(),
            payload_comms_host=str(
                kwargs.get("payload_comms_host")
                or profile.payload_comms_host
                or ""
            ).strip(),
            use_tls=bool(use_tls),
            ssl_cert=str(kwargs.get("ssl_cert") or "/etc/ssl/certs/redirector.crt"),
            ssl_key=str(kwargs.get("ssl_key") or "/etc/ssl/private/redirector.key"),
            fallback_status=int(kwargs.get("fallback_status") or 404),
        )

    @classmethod
    def from_module(cls, module: Any, **overrides: Any) -> "RedirectorSpec":
        """Build from a listener/payload module (uses BeaconProfile.from_opts)."""
        profile = BeaconProfile.from_opts(module)
        decoy_paths = list(getattr(module, "_decoy_paths", None) or profile.decoy_paths)

        def _raw(name: str, default: Any = None) -> Any:
            attr = getattr(module, name, default)
            if hasattr(attr, "value"):
                return getattr(attr, "value")
            return attr if attr is not None else default

        backend_host = str(
            overrides.get("backend_host")
            or _raw("lhost", "127.0.0.1")
            or "127.0.0.1"
        )
        if backend_host in ("0.0.0.0", "::", "[::]"):
            backend_host = "127.0.0.1"
        backend_port = int(overrides.get("backend_port") or _raw("lport", 8088) or 8088)
        uri_prefix = str(overrides.get("uri_prefix") or _raw("url_prefix", "/c2") or "/c2")
        return cls.from_profile(
            profile.with_overrides(decoy_paths=decoy_paths),
            backend_host=backend_host,
            backend_port=backend_port,
            uri_prefix=uri_prefix,
            listen_port=int(overrides.get("listen_port") or 443),
            server_name=str(overrides.get("server_name") or "_"),
            use_tls=bool(overrides.get("use_tls") or False),
            domain_front_header=overrides.get("domain_front_header"),
            payload_comms_host=overrides.get("payload_comms_host"),
            ssl_cert=overrides.get("ssl_cert"),
            ssl_key=overrides.get("ssl_key"),
            fallback_status=overrides.get("fallback_status"),
        )


def _banner(engine: str, spec: RedirectorSpec) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    lines = [
        f"# KittySploit C2 redirector ({engine}) - generated {ts}",
        f"# Backend teamserver: {spec.backend}",
        f"# C2 paths: {spec.poll_uri}  {spec.result_uri}",
    ]
    if spec.payload_comms_host:
        lines.append(
            f"# Implant payload_comms_host / connect host: {spec.payload_comms_host}"
        )
    if spec.domain_front_header:
        lines.append(
            f"# host_header (Host to origin/backend): {spec.domain_front_header}"
        )
        lines.append(
            "# Tip: point implant payload_comms_host at the CDN/front; "
            "set host_header to the origin the CDN expects."
        )
    lines.append("#")
    return "\n".join(lines) + "\n"


def _nginx_proxy_headers(spec: RedirectorSpec, indent: str = "        ") -> str:
    host_line = (
        f"{indent}proxy_set_header Host {spec.domain_front_header};\n"
        if spec.domain_front_header
        else f"{indent}proxy_set_header Host $host;\n"
    )
    return (
        host_line
        + f"{indent}proxy_set_header X-Real-IP $remote_addr;\n"
        + f"{indent}proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n"
        + f"{indent}proxy_set_header X-Forwarded-Proto $scheme;\n"
        + f"{indent}proxy_http_version 1.1;\n"
        + f"{indent}proxy_read_timeout 300;\n"
        + f"{indent}proxy_connect_timeout 10;\n"
    )


def generate_nginx(spec: RedirectorSpec) -> str:
    """Generate an nginx server block that only proxies C2 (+ optional decoys)."""
    listen = f"listen {int(spec.listen_port)}"
    tls_block = ""
    if spec.use_tls:
        listen += " ssl"
        tls_block = (
            f"    ssl_certificate     {spec.ssl_cert};\n"
            f"    ssl_certificate_key {spec.ssl_key};\n"
            "    ssl_protocols       TLSv1.2 TLSv1.3;\n"
        )
    listen += ";"

    locations = []
    for uri in (spec.poll_uri, spec.result_uri):
        locations.append(
            f"    location = {uri} {{\n"
            f"        proxy_pass http://{spec.backend};\n"
            + _nginx_proxy_headers(spec)
            + "    }\n"
        )

    for decoy in spec.normalized_decoys():
        # Exact match static cover — do not hit the teamserver
        locations.append(
            f"    location = {decoy} {{\n"
            "        default_type text/plain;\n"
            '        return 200 "OK\\n";\n'
            "    }\n"
        )

    body = (
        _banner("nginx", spec)
        + "server {\n"
        + f"    {listen}\n"
        + f"    server_name {spec.server_name};\n"
        + tls_block
        + "\n"
        + "".join(locations)
        + "\n"
        + "    location / {\n"
        + f"        return {int(spec.fallback_status)};\n"
        + "    }\n"
        + "}\n"
    )
    return body


def generate_apache(spec: RedirectorSpec) -> str:
    """Generate Apache 2.4 VirtualHost with ProxyPass for C2 endpoints."""
    scheme_listen = f"*:{int(spec.listen_port)}"
    tls_open = ""
    tls_close_notes = ""
    if spec.use_tls:
        tls_open = (
            f"    SSLEngine on\n"
            f"    SSLCertificateFile {spec.ssl_cert}\n"
            f"    SSLCertificateKeyFile {spec.ssl_key}\n"
        )
        tls_close_notes = "# Requires: a2enmod ssl proxy proxy_http headers rewrite\n"
    else:
        tls_close_notes = "# Requires: a2enmod proxy proxy_http headers rewrite\n"

    if spec.domain_front_header:
        request_header = f"    RequestHeader set Host \"{spec.domain_front_header}\"\n"
        preserve = "    ProxyPreserveHost Off\n"
    else:
        request_header = ""
        preserve = "    ProxyPreserveHost On\n"

    proxy_lines = []
    for uri in (spec.poll_uri, spec.result_uri):
        proxy_lines.append(f"    ProxyPass        {uri} http://{spec.backend}{uri}\n")
        proxy_lines.append(f"    ProxyPassReverse {uri} http://{spec.backend}{uri}\n")

    # Cover-traffic paths: answer locally (204) so they never hit the teamserver
    decoy_rewrites = []
    for decoy in spec.normalized_decoys():
        esc = decoy.replace(".", r"\.")
        decoy_rewrites.append(f"    RewriteRule ^{esc}$ - [R=204,L]\n")

    # Fallback 404 must not shadow ProxyPass C2 endpoints
    poll_esc = spec.poll_uri.replace(".", r"\.")
    result_esc = spec.result_uri.replace(".", r"\.")
    fallback = (
        f"    RewriteCond %{{REQUEST_URI}} !^{poll_esc}$\n"
        f"    RewriteCond %{{REQUEST_URI}} !^{result_esc}$\n"
        f"    RewriteRule ^ - [R={int(spec.fallback_status)},L]\n"
    )

    return (
        _banner("apache", spec)
        + tls_close_notes
        + f"<VirtualHost {scheme_listen}>\n"
        + f"    ServerName {spec.server_name}\n"
        + tls_open
        + preserve
        + request_header
        + "    RewriteEngine On\n"
        + "".join(decoy_rewrites)
        + "".join(proxy_lines)
        + f"    # Fallback: everything else -> {spec.fallback_status}\n"
        + fallback
        + "</VirtualHost>\n"
    )


def generate_caddy(spec: RedirectorSpec) -> str:
    """Generate a Caddyfile snippet."""
    addr = f":{int(spec.listen_port)}"
    if spec.server_name and spec.server_name not in ("_", "*"):
        site = spec.server_name
        if spec.listen_port not in (80, 443):
            site = f"{spec.server_name}:{int(spec.listen_port)}"
    else:
        site = addr

    host_hdr = ""
    if spec.domain_front_header:
        host_hdr = f'\n\t\theader_up Host {spec.domain_front_header}'

    blocks = [
        _banner("caddy", spec).rstrip("\n"),
        f"{site} {{",
    ]
    if spec.use_tls and spec.server_name not in ("_", "*"):
        blocks.append(f"\ttls {spec.ssl_cert} {spec.ssl_key}")
    elif not spec.use_tls:
        blocks.append("\ttls internal")

    for uri in (spec.poll_uri, spec.result_uri):
        blocks.append(f"\thandle {uri} {{")
        blocks.append(f"\t\treverse_proxy {spec.backend} {{{host_hdr}")
        blocks.append("\t\t}")
        blocks.append("\t}")

    for decoy in spec.normalized_decoys():
        blocks.append(f"\thandle {decoy} {{")
        blocks.append('\t\trespond "OK" 200')
        blocks.append("\t}")

    blocks.append("\thandle {")
    blocks.append(f"\t\trespond {int(spec.fallback_status)}")
    blocks.append("\t}")
    blocks.append("}")
    blocks.append("")
    return "\n".join(blocks)


def generate(engine: str, spec: RedirectorSpec) -> str:
    """Dispatch to an engine-specific generator."""
    name = str(engine or "").strip().lower()
    if name == "nginx":
        return generate_nginx(spec)
    if name in ("apache", "httpd", "apache2"):
        return generate_apache(spec)
    if name == "caddy":
        return generate_caddy(spec)
    raise ValueError(f"unsupported redirector engine: {engine!r} (use {', '.join(SUPPORTED_ENGINES)})")


def default_output_dir(workspace_name: Optional[str] = None) -> Path:
    """~/.kittysploit/redirectors[/workspace]."""
    base = Path(os.path.expanduser("~/.kittysploit/redirectors"))
    if workspace_name:
        safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in str(workspace_name))
        return base / (safe or "default")
    return base


def write_redirector(
    engine: str,
    spec: RedirectorSpec,
    *,
    output_dir: Optional[Union[str, Path]] = None,
    filename: Optional[str] = None,
) -> Path:
    """Generate and write config; return path written."""
    text = generate(engine, spec)
    out_dir = Path(output_dir) if output_dir else default_output_dir()
    out_dir.mkdir(parents=True, exist_ok=True)
    if not filename:
        ext = {"nginx": "conf", "apache": "conf", "httpd": "conf", "apache2": "conf", "caddy": "Caddyfile"}
        key = str(engine).strip().lower()
        suffix = ext.get(key, "conf")
        if key == "caddy":
            filename = "Caddyfile"
        else:
            filename = f"kittysploit-c2-{key}.{suffix}"
    path = out_dir / filename
    path.write_text(text, encoding="utf-8")
    return path


def fronting_hints(spec: RedirectorSpec) -> Dict[str, str]:
    """Operator mapping for domain-fronting payload options."""
    return {
        "payload_comms_host": spec.payload_comms_host
        or "<CDN or redirector hostname implants connect to>",
        "host_header": spec.domain_front_header
        or "<origin Host header / CDN endpoint>",
        "backend": spec.backend,
        "poll": spec.poll_uri,
        "result": spec.result_uri,
    }
