from kittysploit import *
import pychromecast

class Module(Auxiliary):

    __info__ = {
            'name': 'ChromeCast Discovery',
            'description': 'Launch this module to discover chromecast within a Network',
            'author': 'KittySploit Team',
        }
        
    timeout = OptInteger(5, "timeout")	

    def check(self):
        """Check if pychromecast is available"""
        try:
            import pychromecast
            return True
        except ImportError:
            print_error("pychromecast library is not installed. Please install it using: pip install pychromecast")
            return False

    def run(self):
        print_info("Searching devices")
        try:
            # get_chromecasts returns a tuple (chromecasts, browser) or just chromecasts depending on version
            result = pychromecast.get_chromecasts(timeout=self.timeout)
            
            # Handle both return formats
            if isinstance(result, tuple):
                chromecasts, browser = result
            else:
                chromecasts = result
                browser = None
            
            if chromecasts:
                for cast in chromecasts:
                    # Access attributes directly on the cast object
                    friendly_name = getattr(cast, 'name', None) or getattr(cast, 'friendly_name', 'Unknown')
                    cast_type = getattr(cast, 'cast_type', 'Unknown')
                    model_name = getattr(cast, 'model_name', 'Unknown')
                    host = getattr(cast, 'host', 'Unknown')
                    
                    print_success(f"{friendly_name} ({cast_type} - {model_name}) => {host}")
                
                # Clean up browser if it was created
                if browser:
                    try:
                        browser.stop_discovery()
                    except:
                        pass
            else:
                fail.NotFound()
        except Exception as e:
            print_error(f"Error discovering Chromecast devices: {e}")
            fail.Unknown()
