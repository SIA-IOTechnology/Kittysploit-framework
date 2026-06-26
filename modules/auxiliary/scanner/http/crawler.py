from kittysploit import *
from lib.protocols.http.http_crawler import Http_crawler
		
class Module(Auxiliary, Http_crawler):


	__info__ = {
		'name': 'Web site crawler',
		'description': 'Crawl a web site and store information about what was found',		
		'agent': {
		    'risk': 'active',
		    'effects': ['network_probe'],
		    'expected_requests': 2,
		    'reversible': True,
		    'approval_required': False,
		    'produces': ['tech_hints', 'risk_signals', 'endpoints', 'params'],
		},
		}
	
	def run(self):
		self.crawler_start()
