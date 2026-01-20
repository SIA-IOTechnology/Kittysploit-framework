from kittysploit import *
from ppadb.client import Client as AdbClient

class Module(Listener):

    __info__ = {
        'name': 'Android ADB Listener',
        'description': 'Listens for connections from Android devices using ADB',
        'author': 'KittySploit Team',
        'version': '1.0.0',
        'handler': Handler.BIND,
        'session_type': SessionType.ANDROID,
        'dependencies': ['ppadb'],
    }
    
    adb_server_ip = OptString('127.0.0.1', 'IP address of the ADB server', True)
    adb_server_port = OptPort(5037, 'Port number of the ADB server', True)
    adb_device_id = OptString('', 'ID of the Android device to connect to', True)

    def run(self):
        try:
            client = AdbClient(host=self.adb_server_ip, port=self.adb_server_port)
            devices = client.devices()
            if not devices:
                print_error('No Android devices found')
                return False
            for device in devices:
                if device.serial == self.adb_device_id:
                    print_success(f'Connected to {device.serial}')
                    return (device, device.serial, self.adb_server_port)
        except Exception as e:
            print_error(f'Error: {e}')
            return False