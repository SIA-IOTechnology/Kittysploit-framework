from kittysploit import *
import re

class Module(Post):

    __info__ = {
        'name': 'Android MAC Address',
        'description': 'Get the MAC address of an Android device',
        'author': 'KittySploit Team',
        'session_type': SessionType.ANDROID,
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
        'chain':         {'produces_capabilities': [],
         'consumes_capabilities': ['shell'],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }
    def run(self):
        try:
            # Use ADB via cmd_execute (requires an android shell auto-created for android sessions).
            # Try multiple methods to get MAC address
            
            # Method 1: Read from sysfs (most reliable for WiFi)
            mac = (self.cmd_execute("cat /sys/class/net/wlan0/address") or "").strip()
            if mac and re.match(r'^([0-9a-f]{2}:){5}[0-9a-f]{2}$', mac.lower()):
                print_success(f"MAC Address (wlan0): {mac}")
                return True
            
            # Method 2: Try system property
            mac = (self.cmd_execute("getprop ro.boot.wifimacaddr") or "").strip()
            if mac and re.match(r'^([0-9a-f]{2}:){5}[0-9a-f]{2}$', mac.lower()):
                print_success(f"MAC Address: {mac}")
                return True
            
            # Method 3: Parse ip link output
            ip_out = self.cmd_execute("ip link show wlan0")
            if ip_out:
                # Look for "link/ether XX:XX:XX:XX:XX:XX"
                match = re.search(r'link/ether\s+([0-9a-f:]+)', ip_out, re.IGNORECASE)
                if match:
                    mac = match.group(1)
                    print_success(f"MAC Address (wlan0): {mac}")
                    return True
            
            # No MAC found
            print_error("Could not retrieve MAC address via ADB.")
            print_info("Try: cat /sys/class/net/wlan0/address or getprop ro.boot.wifimacaddr")
            return False
            
        except Exception as e:
            print_error(f'Error: {e}')
            return False