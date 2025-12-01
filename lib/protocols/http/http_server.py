from core.framework.base_module import BaseModule
from core.framework.option import OptString, OptPort
from core.framework.failure import fail
from core.framework.jobs import Jobs
from core.output_handler import print_status

import http.server
import socketserver
import os

class Http_server(BaseModule):
	
	srvhost = OptString("127.0.0.1", "Address of the HTTP server", True)
	srvport = OptPort(11111, "Port of the HTTP server", True)
	
	template_dir = OptString("/tmp/", "Directory for filename template", advanced=True)

	def web_delivery(self, data=None, forever=False, background=False, path="/", filename=None, download=False):
		

		def get(self):
			if self.path == path:
				print_status(f"Connecting to {self.client_address[0]}...")
				print_status("Sending payload stage...")

				if filename:
					self.send_response(200)
					if download:
						self.send_header("Content-type", "application/octet-stream")
					else:
						self.send_header("Content-type", "text/html")
					self.end_headers()
					self.write_file(filename)
				else:
					self.send_response(200)
					self.send_header("Content-type", "text/html")
					self.end_headers()
					self.write_response(bytes(data, "utf8"))
			else:
				self.send_response(404)
				self.send_header("Content-type", "text/html")
				self.end_headers()
				self.write_response("404 Not Found")

		return self.listen_http({"GET": get}, forever=forever, background=background)

	def _check_if_port_busy(self, lport):

		import socket, errno
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		try:
			s.bind(("127.0.0.1", int(lport)))
		except socket.error as e:
			if e.errno == errno.EADDRINUSE:	
				fail.PortBusy

	def listen_http(self, methods={}, forever=False, background=False):
		""" Start http server """
		
		self._check_if_port_busy(self.srvport)
		try:
			for method in methods:
				setattr(Handler, f"do_{method.upper()}", methods[method])
			Handler.template_http = self.template_dir
			httpd = socketserver.TCPServer((self.srvhost, self.srvport), Handler)
			
			if forever:
				new_job = Jobs()
				new_job.create_job("web delivery", f"http://{self.srvhost}:{self.srvport}", httpd.serve_forever, [])
			else:
				if background:
					new_job = Jobs()
					new_job.create_job("web delivery", f"http://{self.srvhost}:{self.srvport}", httpd.serve_forever, [])
				else:
					httpd.handle_request()
					print_success(f"Server started at http://{self.srvhost}:{self.srvport}")

		except KeyboardInterrupt:
			fail.KeyboardInterrupt
		except Exception:
			fail.Unknown
		
class Handler(http.server.SimpleHTTPRequestHandler):
	
	template_http = ""
	
	def log_request(self, fmt, *args):
		return

	def send_status(self, code=200):
		self.send_response(int(code))
		self.send_header("Content-type", "text/html")
		self.end_headers()

	def write_response(self, data):
		if type(data) == bytes:
			self.wfile.write(data)
		else:
			self.wfile.write(bytes(data, encoding="utf-8"))
	
	def write_file(self, filename):
		if os.path.exists(self.template_http + filename):
			with open(self.template_http + filename, 'r') as f:
				file_content = f.read()
			self.wfile.write(file_content.encode())
		else:
			self.write_response("404 Not Found")

	def get_post_data(self):
		content_length = int(self.headers['Content-Length'])
		post_data = self.rfile.read(content_length)
		return post_data

	def redirect(self, url):
		self.send_response(301)
		self.send_header('Location',url)
		self.end_headers()

	def do_GET(self):
		pass
	
	def do_POST(self):
		pass
	
	def do_PUT(self):
		pass
	
	def do_HEAD(self):
		pass