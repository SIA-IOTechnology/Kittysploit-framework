import json

from kittysploit import *
from lib.protocols.elasticsearch.elasticsearch_client import ElasticsearchClient


class Module(Post, ElasticsearchClient):

	__info__ = {
		"name": "Elasticsearch Indices Search",
		"description": "List Elasticsearch indices and optionally run search queries",
		"author": "KittySploit Team",
		"session_type": SessionType.ELASTICSEARCH,
	'agent': {
	    'risk': 'intrusive',
	    'effects': ['active_exploitation'],
	    'expected_requests': 2,
	    'reversible': False,
	    'approval_required': True,
	    'produces': ['risk_signals'],
	    'cost': 1.5,
	    'noise': 0.5,
	    'value': 1.0,
	    'requires': 	    {'min_endpoints': 0,
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
	    'chain': 	    {'produces_capabilities': [],
	     'consumes_capabilities': [],
	     'option_bindings': {},
	     'suggested_followups': []},
	},
	}

	index_pattern = OptString("*", "Index pattern for listing/search", False)
	search_index = OptString("", "Index to search (empty = list only)", False)
	query = OptString("", "Search query JSON (empty = match_all)", False)
	size = OptInteger(10, "Maximum hits to return per search", False)
	show_mapping = OptBool(False, "Show mapping for searched index", False)

	def run(self):
		try:
			info = self.get_session_info()
			print_info("=" * 80)
			print_status("Elasticsearch cluster")
			for key in ("host", "port", "cluster_name", "version"):
				if info.get(key) not in (None, ""):
					print_info(f"  {key}: {info[key]}")

			pattern = str(self.index_pattern or "*").strip() or "*"
			print_info("-" * 80)
			print_status(f"Indices matching: {pattern}")
			indices_text = self.list_indices(pattern)
			if indices_text.strip():
				for line in indices_text.splitlines():
					print_info(f"  {line}")
			else:
				print_info("  (no indices)")

			target_index = str(self.search_index or "").strip()
			if not target_index:
				print_info("=" * 80)
				print_success("Index listing completed")
				return True

			query_body = None
			query_text = str(self.query or "").strip()
			if query_text:
				try:
					query_body = json.loads(query_text)
				except json.JSONDecodeError as exc:
					raise ProcedureError(
						FailureType.ConfigurationError, f"Invalid search query JSON: {exc}"
					)

			print_info("-" * 80)
			print_status(f"Search on index: {target_index}")
			hits = self.search_index(target_index, query_body, size=int(self.size or 10))
			if not hits:
				print_info("  (0 hits)")
			else:
				for i, hit in enumerate(hits, 1):
					print_info(f"  [{i}] {json.dumps(hit, default=str)}")

			if self.show_mapping:
				print_info("-" * 80)
				print_status(f"Mapping for index: {target_index}")
				mapping = self.get_mapping(target_index)
				if mapping:
					print_info(json.dumps(mapping, indent=2, default=str))
				else:
					print_warning("Mapping not found")

			print_info("=" * 80)
			print_success("Elasticsearch indices/search completed")
			return True
		except ProcedureError:
			raise
		except Exception as exc:
			raise ProcedureError(
				FailureType.Unknown, f"Elasticsearch indices/search failed: {exc}"
			)
