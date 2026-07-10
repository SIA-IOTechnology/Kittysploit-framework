from kittysploit import *


class Module(Post):

    __info__ = {
        'name': 'Android Get Info',
        'description': 'Get information about an Android device',
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
            def gp(prop: str) -> str:
                return (self.cmd_execute(f"getprop {prop}") or "").strip()

            model = gp("ro.product.model")
            manufacturer = gp("ro.product.manufacturer")
            brand = gp("ro.product.brand")
            device_name = gp("ro.product.device")
            product = gp("ro.product.name")
            release = gp("ro.build.version.release")
            sdk = gp("ro.build.version.sdk")
            build_id = gp("ro.build.id")
            fingerprint = gp("ro.build.fingerprint")

            uname = (self.cmd_execute("uname -a") or "").strip()
            whoami = (self.cmd_execute("whoami") or "").strip()
            uid_line = (self.cmd_execute("id") or "").strip()

            # Serial is often restricted on modern Android; try multiple props.
            serial = gp("ro.serialno") or gp("ro.boot.serialno") or gp("persist.sys.serialnumber")

            print_success("Android device info:")
            if manufacturer or model:
                print_info(f"  Device: {manufacturer} {model}".strip())
            if brand or product or device_name:
                print_info(f"  Product: {brand} {product} ({device_name})".strip())
            if release or sdk or build_id:
                print_info(f"  Android: {release} (SDK {sdk}) Build {build_id}".strip())
            if serial:
                print_info(f"  Serial: {serial}")
            if uname:
                print_info(f"  Kernel: {uname}")
            if whoami:
                print_info(f"  User: {whoami}")
            if uid_line:
                print_info(f"  Id: {uid_line}")
            if fingerprint:
                print_info(f"  Fingerprint: {fingerprint}")
            return True
        except Exception as e:
            print_error(f'Error: {e}')
            return False