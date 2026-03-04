<?php
namespace Jet_Engine\Bricks_Views\Dynamic_Data;

use Jet_Engine\Modules\Custom_Content_Types\Module;

if ( ! defined( 'ABSPATH' ) ) {
	exit; // Exit if accessed directly
}

class Provider_Jet_Engine_Data extends \Bricks\Integrations\Dynamic_Data\Providers\Base {

	public $jet_provider_prefix = 'je_current_object_field';

	public function register_tags() {
		$name = $this->jet_provider_prefix;

		$tag = [
			'name'     => '{' . $name . '}',
			'label'    => 'Current Object Field - add key after :',
			'group'    => 'Jet Engine Dynamic Data',
			'field'    => 'text',
			'provider' => $this->name
		];

		$this->tags[ $name ] = $tag;
	}

	public function get_tag_value( $tag, $post, $args, $context ) {
		$post_type = get_post_type( $post );

		if ( isset( $post->ID ) && jet_engine()->post_type->slug() === $post_type ) {
			$preview = new \Jet_Engine_Listings_Preview( [], $post->ID );
			$post = $preview->get_preview_object();
		}

		$post_id = isset( $post->_ID ) ? $post->_ID : '';

		// STEP: Check for filter args
		$filters = $this->get_filters_from_args( $args );

		$key = ! empty( $filters['meta_key'] ) ? $filters['meta_key'] : 'meta';

		$value = jet_engine()->listings->data->get_prop(
			$key,
			jet_engine()->listings->data->get_object_by_context()
		);

		// STEP: Apply context (text, link, image, media)
		$value = $this->format_value_for_context( $value, $tag, $post_id, $filters, $context );

		return $value;
	}

	/**
	 * Get all fields supported
	 *
	 * @return array
	 */
	private static function get_supported_field_types() {
		return [
			'text',
			'textarea',
			'wysiwyg',
			'number',
			'html',

			'date',
			'time',
			'datetime-local',

			'switcher',
			'checkbox',
			'radio',
			'select',

			// 'iconpicker',
			'media',
			'gallery',

			'repeater', // Query Loop

			'posts', // Query Loop (and regular field)

			'colorpicker',
		];
	}
}
