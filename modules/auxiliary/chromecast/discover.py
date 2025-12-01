from kittysploit import *
import pychromecast

class Module(Auxiliary):

	__info__ = {
			'name': 'ChromeCast Discovery',
			'description': 'Launch this module to discover chromecast within a Network',
			'author': 'KittySploit Team',
		}
		
	timeout = OptInteger(5, "timeout")	

	def run(self):
        print_info("Searching devices")
        chromecasts = pychromecast.get_chromecasts(timeout=self.timeout)
        if chromecasts:
            for cast in [cc for cc in chromecasts]:
                print_success(f"{cast.device.friendly_name} ({cast.device.cast_type} - {cast.device.manufacturer}) => {cast.host}")
        else:
            fail.NotFound()
