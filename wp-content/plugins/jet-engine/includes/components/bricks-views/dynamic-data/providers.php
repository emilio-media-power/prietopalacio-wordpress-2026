<?php

namespace Jet_Engine\Bricks_Views\Dynamic_Data;

if ( ! defined( 'ABSPATH' ) ) {
	exit; // Exit if accessed directly
}

class Providers {
	/**
	 * Holds the providers
	 *
	 * @var array
	 */
	private $providers_keys = [];

	/**
	 * Holds the providers instances
	 *
	 * @var array
	 */
	private $providers = [];

	/**
	 * Holds the tags instances
	 *
	 * @var array
	 */
	private $tags = [];

	private $allowed_prefixes = [ 'je_cct_' ];

	public function __construct( $providers ) {
		$this->providers_keys = $providers;
	}

	public static function register( $providers = [] ) {
		$instance = new self( $providers );

		// I had a problem that my dynamic tags do not render during an ajax request
		// (listing load more and lazy load, listing calendar and turn month, ...)
		// I tried to join a hook that fires before 'init' and 'wp'.
		//
		// Bricks' Registers class register their tags on hooks 'init' and 'wp'
		// because their Registers classes are connected at a high level.
		add_action( 'wp_loaded', [ $instance, 'register_providers' ], 10 );

		// Priority set to 10000 due to CMB2 priority
//		add_action( 'init', [ $instance, 'register_providers' ], 10000 );

		// Register providers during WP REST API call (priority 7 to run before register_tags() on WP REST API)
//		add_action( 'rest_api_init', [ $instance, 'register_providers' ], 7 );

		add_action( 'wp_loaded', [ $instance, 'register_tags' ], 10 );

		// Register tags before wp_enqueue_scripts (but not before wp to get the post custom fields)
		// Priority = 8 to run before Setup::init_control_options
//		add_action( 'wp', [ $instance, 'register_tags' ], 8 );

		// Hook "wp" doesn't run on AJAX/REST API calls so we need this to register the tags when rendering elements (needed for Posts element) or fetching dynamic data content
//		add_action( 'admin_init', [ $instance, 'register_tags' ], 8 );
//		add_action( 'rest_api_init', [ $instance, 'register_tags' ], 8 );

		add_filter( 'bricks/dynamic_tags_list', [ $instance, 'add_tags_to_builder' ] );

		// Render dynamic data in builder too (when template preview post ID is set)
		add_filter( 'bricks/frontend/render_data', [ $instance, 'render' ], 10, 2 );

		add_filter( 'bricks/dynamic_data/render_content', [ $instance, 'render' ], 10, 3 );

		add_filter( 'bricks/dynamic_data/render_tag', [ $instance, 'get_tag_value' ], 10, 3 );
	}

	public function register_providers() {
		foreach ( $this->providers_keys as $provider => $namespace ) {
			$classname = $namespace . '\Provider_' . str_replace( ' ', '_', ucwords( str_replace( '-', ' ', $provider ) ) );
			$this->providers[ $provider ] = new $classname( str_replace( '-', '_', $provider ) );
		}
	}

	public function register_tags() {
		foreach ( $this->providers as $key => $provider ) {
			$this->tags = array_merge( $this->tags, $provider->get_tags() );

			if ( isset( $provider->jet_provider_prefix ) ) {
				$this->allowed_prefixes[] = $provider->jet_provider_prefix;
			}

		}
	}

	public function get_tags() {
		return $this->tags;
	}

	/**
	 * Adds tags to the tags picker list (used in the builder)
	 *
	 * @param array $tags
	 * @return array
	 */
	public function add_tags_to_builder( $tags ) {
		$list = $this->get_tags();

		foreach ( $list as $tag ) {
			if ( isset( $tag['deprecated'] ) ) {
				continue;
			}

			$tags[] = [
				'name'  => $tag['name'],
				'label' => $tag['label'],
				'group' => $tag['group']
			];
		}

		return $tags;
	}

	/**
	 * Dynamic tag exists in $content: Replaces dynamic tag with requested data
	 *
	 * @param string  $content
	 * @param WP_Post $post
	 */
	public function render( $content, $post, $context = 'text' ) {

		$prefixes = [];

		foreach( $this->allowed_prefixes as $prefix ) {
			$prefixes[] = $prefix . '[\w\-\s\.\/:\(\)\'|,]+';
		}

		$prefixes = implode( '|', $prefixes );
		$pattern  = '/{(' . $prefixes . ')}/';

		preg_match_all( $pattern, $content, $matches );

		if ( empty( $matches[0] ) ) {
			return $content;
		}

		// Get a list of tags to exclude from the Dynamic Data logic
		$exclude_tags = apply_filters( 'bricks/dynamic_data/exclude_tags', [] );

		foreach ( $matches[1] as $key => $match ) {
			$tag = $matches[0][ $key ];

			if ( in_array( $match, $exclude_tags ) ) {
				continue;
			}

			$value = $this->get_tag_value( $match, $post, $context );
			$content = str_replace( $tag, $value, $content );
		}

		return $content;
	}

	public function has_allowed_prefix( $tag ) {
		
		foreach ( $this->allowed_prefixes as $prefix ) {
			if ( false !== strpos( $tag, $prefix ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Get the value of a dynamic data tag
	 *
	 * @param string  $tag (without {})
	 * @param WP_Post $post
	 * @return void
	 */
	public function get_tag_value( $tag, $post, $context = 'text' ) {
		
		if ( ! is_string( $tag ) || ! $this->has_allowed_prefix( $tag ) ) {
			return $tag;
		}

		$tag = str_replace( [ '{', '}' ], '', $tag );

		// Keep the original tag to be used later on in case we don't replace nonexistent tags
		$original_tag = $tag;

		$tags = $this->get_tags();

		// Check if tag has arguments
		$args = strpos( $tag, ':' ) > 0 ? explode( ':', $tag ) : [];

		if ( ! empty( $args ) ) {
			$tag = array_shift( $args );
		}

		if ( ! array_key_exists( $tag, $tags ) ) {
			/**
			 * If true, Bricks replaces not existing DD tags with an empty string
			 *
			 * true caused unwanted replacement of inline <script> & <style> tag data.
			 *
			 * Set to false @since1.4 to render all non-matching DD tags (#2ufh0uf)
			 */
			$replace_tag = apply_filters( 'bricks/dynamic_data/replace_nonexistent_tags', false );

			return $replace_tag ? '' : '{' . $original_tag . '}';
		}

		$provider = str_replace( '_', '-', $tags[ $tag ]['provider'] );

		return $this->providers[ $provider ]->get_tag_value( $tag, $post, $args, $context );
	}
}