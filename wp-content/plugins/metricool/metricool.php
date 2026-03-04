<?php
	/**
	* Plugin Name: Metricool
	* Plugin URI: https://metricool.com/
	* Version: 1.26
	* Author: Metricool
	* Author URI: https://www.metricool.com/
	* Description: Allows you to track your users and readers using metricool.com
	* License: GPL2
	*/

	/*  Copyright 2021 Metricool

	    This program is free software; you can redistribute it and/or modify
	    it under the terms of the GNU General Public License, version 2, as
	    published by the Free Software Foundation.

	    This program is distributed in the hope that it will be useful,
	    but WITHOUT ANY WARRANTY; without even the implied warranty of
	    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	    GNU General Public License for more details.

	    You should have received a copy of the GNU General Public License
	    along with this program; if not, write to the Free Software
	    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
	*/

	class metricool {

		public $plugin;

	        /**
	        * Constructor
	        */
	        public function __construct() {
	                // Plugin Details
	        $this->plugin = new stdClass;
	        $this->plugin->name = 'metricool'; // Plugin Folder
	        $this->plugin->displayName = 'Metricool'; // Plugin Name
	        $this->plugin->version = '1.18';
	        $this->plugin->folder = WP_PLUGIN_DIR.'/'.$this->plugin->name; // Full Path to Plugin Folder
	        $this->plugin->url = WP_PLUGIN_URL.'/'.str_replace(basename( __FILE__),"",plugin_basename(__FILE__));

	                // Hooks
	                add_action('admin_init', array(&$this, 'registerSettings'));
	                add_action('admin_menu', array(&$this, 'adminPanelsAndMetaBoxes'));
	                add_action('admin_bar_menu', array(&$this, 'adminCustomMenu'), 1000);

	                // Frontend Hooks
	                add_action('wp_footer', array(&$this, 'frontendFooter'));
	        }

	        /**
	        * Register Settings
	        */
	        function registerSettings() {
	                register_setting($this->plugin->name, 'metricool_profile_id', 'trim');
	        }

	        /**
	    * Register the plugin settings panel
	    */
	    function adminPanelsAndMetaBoxes() {
	        add_submenu_page('options-general.php', $this->plugin->displayName, $this->plugin->displayName, 'manage_options', $this->plugin->name, array(&$this, 'adminPanel'));
	        }

	    /**
	    * Output the Administration Panel
	    * Save POSTed data from the Administration Panel into a WordPress option
	    */
	   function adminPanel()
	{
	    // Save Settings
	    if (isset($_POST['submit'])) {
	        // Check nonce
	        if (!isset($_POST[$this->plugin->name . '_nonce'])) {
	            // Missing nonce
	            $this->errorMessage = __('nonce field is missing. Settings NOT saved.', $this->plugin->name);
	        } elseif (!wp_verify_nonce($_POST[$this->plugin->name . '_nonce'], $this->plugin->name)) {
	            // Invalid nonce
	            $this->errorMessage = __('Invalid nonce specified. Settings NOT saved.', $this->plugin->name);
	        } elseif (!preg_match('/^[a-z0-9]+$/',$_POST['metricool_profile_id'])) {
	            // Invalid nonce
	            $this->errorMessage = __('Invalid site TOKEN. Settings NOT saved.', $this->plugin->name);
	        }
	        else {
	            // Save
	            update_option('metricool_profile_id', $_POST['metricool_profile_id']);
	            $this->message = __('Settings Saved.', $this->plugin->name);
	        }
	    }

	    // Get latest settings
	    $this->settings = array(
	        'metricool_profile_id' => get_option('metricool_profile_id')
	    );

	    // Load Settings Form
	    include_once(WP_PLUGIN_DIR . '/' . $this->plugin->name . '/views/settings.php');
	}

	    /**
	        * Loads plugin textdomain
	        */
	        function loadLanguageFiles() {
	                load_plugin_textdomain($this->plugin->name, false, $this->plugin->name.'/languages/');
	        }

	        /**
	        * Outputs script / CSS to the frontend footer
	        */
	        function frontendFooter() {
	                $this->output('metricool_profile_id');
	        }

	        /**
	        * Outputs the given setting, if conditions are met
	        *
	        * @param string $setting Setting Name
	        * @return output
	        */
	function output($setting)
	{
	        // Ignore admin, feed, robots or trackbacks
	        if (is_admin() or is_feed() or is_robots() or is_trackback()) {
	                return;
	        }

	        // Get meta
	        $meta = get_option($setting);
	        if (empty($meta)) {
	                return;
	        }
	        if (trim($meta) == '') {
	                return;
	        }

	        if (!preg_match('/^[a-z0-9]+$/',$meta)) {
	                return;
	        }

	        // Output
	        echo stripslashes("<script>function loadScript(a){var b=document.getElementsByTagName(\"head\")[0],c=document.createElement(\"script\");c.type=\"text/javascript\",c.src=\"https://tracker.metricool.com/app/resources/be.js\",c.onreadystatechange=a,c.onload=a,b.appendChild(c)}loadScript(function(){beTracker.t({hash:'" . $meta . "'})})</script>");
	}


	        function adminCustomMenu(){
	                global $wp_admin_bar;

	                if(!is_super_admin() || !is_admin_bar_showing()) return;

	                $menu_id = "metricool_menu";
	            $argsParent = array(
	                "id" => $menu_id,
	                "title" => "Metricool",
	                "href" => "https://metricool.com/"
	            );
	            $wp_admin_bar->add_menu($argsParent);

	                $argsSub1 = array(
	                        "id" => $menu_id,
	                    "parent" => $menu_id,
	                    "title" => "Evolution stats",
	                    "href" => "https://app.metricool.com/evolution",
	                    "meta" => array("target" => "_blank")
	                );
	                $wp_admin_bar->add_menu($argsSub1);

	                $argsSub2 = array(
	                        "id" => $menu_id,
	                    "parent" => $menu_id,
	                    "title" => "Real time",
	                    "href" => "https://app.metricool.com/real-time",
	                    "meta" => array("target" => "_blank")
	                );
	                $wp_admin_bar->add_menu($argsSub2);

	                $argsSub3 = array(
	                        "id" => $menu_id,
	                    "parent" => $menu_id,
	                    "title" => "Planner",
	                    "href" => "https://app.metricool.com/actions",
	                    "meta" => array("target" => "_blank")
	                );
	                $wp_admin_bar->add_menu($argsSub3);

	        }


	}

	$metricool = new metricool();

	add_filter('plugin_action_links_'.plugin_basename(__FILE__), 'metricool_add_plugin_page_settings_link');
	function metricool_add_plugin_page_settings_link( $links ) {
	        $links[] = '<a href="' .
	                admin_url( 'options-general.php?page=metricool' ) .
	                '">' . __('Settings') . '</a>';
	        return $links;
	}
