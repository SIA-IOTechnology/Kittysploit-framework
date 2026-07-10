from kittysploit import *
from lib.protocols.http.http_client import Http_client
        
class Module(Auxiliary, Http_client):


    __info__ = {
        'name': 'Wordpress user enumeration',
        'description': "Try to extract wordpress user enumeration",
        'tags': ['web', 'scanner', 'wordpress', 'enum'],
    'agent': {
        'risk': 'active',
        'effects': ['network_probe'],
        'expected_requests': 2,
        'reversible': True,
        'approval_required': False,
        'produces': ['tech_hints', 'risk_signals', 'endpoints', 'params'],
        'cost': 1.0,
        'noise': 0.5,
        'value': 1.0,
        'requires':         {'min_endpoints': 0,
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
        'chain':         {'produces_capabilities': [{'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'ssrf_primitive', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }
    
    def check(self):
        response = self.http_request(
                                method="GET",
                                path="/wp-json/wp/v2/users",
        )
        if response.status_code == 200:
            return True
        return False
    
    def run(self):

        response = self.http_request(
                                method="GET",
                                path="/wp-json/wp/v2/users",
        )
        if response and response.status_code == 200:
            users = response.json()
            for user in users:
                print_success(f"ID: {user['id']}, Name: {user['name']}, Username: {user['slug']}")
            self.vulnerability_info = {
                'reason': f"Enumerated {len(users)} WordPress user(s)",
                'severity': 'Info',
            }
            return True
        else:
            self.vulnerability_info = {
                'reason': "WordPress user enumeration endpoint not exposed",
                'severity': 'Info',
            }
            return False
