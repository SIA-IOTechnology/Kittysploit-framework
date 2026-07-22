from kittysploit import *
from lib.protocols.http.http_crawler import Http_crawler
from core.scanner.http.discovery import summarize_crawl_urls


class Module(Auxiliary, Http_crawler):

	__info__ = {
		'name': 'Web site crawler',
		'description': 'Crawl a web site and store information about what was found',
		'agent': {
		    'risk': 'read',
		    'effects': ['network_probe'],
		    'expected_requests': 4,
		    'reversible': True,
		    'approval_required': False,
		    'produces': ['tech_hints', 'risk_signals', 'endpoints', 'params'],
		    'cost': 1.0,
		    'noise': 0.5,
		    'value': 1.0,
		    'requires': 		    {'min_endpoints': 0,
		     'min_params': 0,
		     'tech_hints_any': [],
		     'tech_hints_all': [],
		     'specializations_any': [],
		     'risk_signals_any': [],
		     'auth_session': False,
		     'capabilities_any': [],
		     'capabilities_all': [],
		     'confidence_min': {},
		     'confidence_min_any': {},
		     'endpoint_pattern_any': [],
		     'param_any': [],
		     'api_surface_ready': False},
		    'chain': 		    {'produces_capabilities': [{'capability': 'endpoints', 'from_detail': ''}],
		     'consumes_capabilities': [],
		     'option_bindings': {},
		     'suggested_followups': ['auxiliary/scanner/http/security_headers']},
		},
		}

	def run(self):
		self.discovered_urls = []
		self.discovered_paths = []
		self.discovered_params = []
		self.crawler_start()
		summary = summarize_crawl_urls(
			list(self._output or []),
			target_host=str(self.target or ""),
		)
		self.discovered_urls = summary["urls"]
		self.discovered_paths = summary["paths"]
		self.discovered_params = summary["params"]
		if self.discovered_paths:
			print_success(
				f"Crawl surface: {len(self.discovered_paths)} path(s), "
				f"{len(self.discovered_params)} query param(s)"
			)
			for path in self.discovered_paths[:8]:
				print_info(f"  → {path}")
			if len(self.discovered_paths) > 8:
				print_info(f"  … and {len(self.discovered_paths) - 8} more")
		else:
			print_warning("Crawler found no in-scope links; downstream scans may fall back to generic probes.")
		return True
