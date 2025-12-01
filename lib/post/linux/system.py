from lib.post.file import File

class System(File):

	def __init__(self):
		super(File, self).__init__()
	
	def get_sysinfo(self):
		""" Get system information"""
		etc_files = self.cmd_exec("ls /etc")
		kernel_version = self.cmd_exec("uname -a")
		system_data = {}
		#Debian
		if "debian" in etc_files:
			if "Ubuntu" in kernel_version:
				system_data['distro'] = "ubuntu"
			else:
				system_data['distro'] = "debian"
		
		#Amazon / Centos
		elif "system-release" in etc_files:
			version = self.read_file('/etc/system-release')
			if "CentOS" in version:
				system_data['distro'] = "centos"
			else:
				system_data['distro'] = "amazon"
		
		#Alpine
		elif "alpine-release" in etc_files:
#			version = self.read_file('/etc/alpine-release')
			system_data['distro'] = "amazon"

		else:
			system_data['distro'] = "linux"
		
		return system_data

	def has_gcc(self):
		""" Check if gcc is installed """
		gcc = self.command_exists('gcc')
		if gcc:
			return True
		return False
