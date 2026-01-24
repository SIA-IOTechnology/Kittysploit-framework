from kittysploit import *

class Module(BrowserAuxiliary):

	__info__ = {
		"name": "XSS Alert",
		"description": "Execute alert on browser victim",
		"author": "KittySploit Team",
		"tags": ["xss"],
		"browser": Browser.ALL,
		"platform": Platform.ALL,
		"session_type": SessionType.BROWSER,
	}
	
	message = OptString("Python rocks", "Write message into alert", True)

	def run(self):
		return self.send_js(f"alert('{self.message}')")
