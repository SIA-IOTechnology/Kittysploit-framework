from core.demo.base import Demo

class ScannerDemo(Demo):
    NAME = "Demo Scanner"
    DESCRIPTION = "A harmless scanner to demonstrate scanning capabilities"
    PATH = "auxiliary/scanner_tcp"
    
    OPTIONS = {
        'target': {
            'description': 'Target IP address or hostname',
            'type': str,
            'required': True,
            'default': '127.0.0.1'
        },
        'ports': {
            'description': 'Ports to scan (e.g. 80,443,8080)',
            'type': str,
            'required': False,
            'default': '80,443'
        }
    }
    
    def run(self, options: dict) -> dict:
        """Simulates a port scan"""
        # Update instance options with provided options
        self.options.update(options)
        
        if not self.validate_options():
            return {'error': 'Required options not set'}
        
        target = self.options.get('target', '127.0.0.1')
        ports = self.options.get('ports', '80,443').split(',')
        
        results = []
        for port in ports:
            # Simulate scan results
            status = 'open' if int(port) % 2 == 0 else 'closed'
            results.append({
                'port': port,
                'status': status,
                'service': f'demo-service-{port}'
            })
        
        return {
            'target': target,
            'scanned_ports': len(ports),
            'results': results
        } 