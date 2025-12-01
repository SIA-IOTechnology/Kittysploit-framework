from kittysploit import *
from lib.utils.threading import Thread_module
import socket

class Module(Auxiliary, Thread_module):

    __info__ = {
        'name': 'Brute Force DNS Subdomains',
        'description': 'Brute force DNS subdomains',
        'author': 'KittySploit Team',
    }

    domain = OptString('', 'Domain name', True)
    wordlist = OptFile("file://wordlists/dns.txt", "User:Pass or file with default credentials (file://)", True)

    def resolve_subdomain(self, subdomain):
        try:
            sock = socket.gethostbyname_ex(subdomain.strip() + "." + self.domain)
            print_status(sock[0] + ' ' + sock[2][0])
        except Exception as e:
            pass

    def run(self):
        self.subdomains = []
        print_success(f'File loaded, {str(len(self.wordlist))} words found')
        self.run_in_threads(self.resolve_subdomain, self.wordlist)

