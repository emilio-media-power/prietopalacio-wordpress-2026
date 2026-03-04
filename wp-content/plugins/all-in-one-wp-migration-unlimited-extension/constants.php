<?php
/**
 * Copyright (C) 2014-2025 ServMask Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Attribution: This code is part of the All-in-One WP Migration plugin, developed by
 *
 * ███████╗███████╗██████╗ ██╗   ██╗███╗   ███╗ █████╗ ███████╗██╗  ██╗
 * ██╔════╝██╔════╝██╔══██╗██║   ██║████╗ ████║██╔══██╗██╔════╝██║ ██╔╝
 * ███████╗█████╗  ██████╔╝██║   ██║██╔████╔██║███████║███████╗█████╔╝
 * ╚════██║██╔══╝  ██╔══██╗╚██╗ ██╔╝██║╚██╔╝██║██╔══██║╚════██║██╔═██╗
 * ███████║███████╗██║  ██║ ╚████╔╝ ██║ ╚═╝ ██║██║  ██║███████║██║  ██╗
 * ╚══════╝╚══════╝╚═╝  ╚═╝  ╚═══╝  ╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
 */

if ( ! defined( 'ABSPATH' ) ) {
	die( 'Kangaroos cannot jump here' );
}

// ==================
// = Plugin Version =
// ==================
define( 'AI1WMUE_VERSION', '2.82' );

// ===============
// = Plugin Name =
// ===============
define( 'AI1WMUE_PLUGIN_NAME', 'all-in-one-wp-migration-unlimited-extension' );

// ============
// = Lib Path =
// ============
define( 'AI1WMUE_LIB_PATH', AI1WMUE_PATH . DIRECTORY_SEPARATOR . 'lib' );

// ===================
// = Controller Path =
// ===================
define( 'AI1WMUE_CONTROLLER_PATH', AI1WMUE_LIB_PATH . DIRECTORY_SEPARATOR . 'controller' );

// ==============
// = Model Path =
// ==============
define( 'AI1WMUE_MODEL_PATH', AI1WMUE_LIB_PATH . DIRECTORY_SEPARATOR . 'model' );

// =============
// = View Path =
// =============
define( 'AI1WMUE_TEMPLATES_PATH', AI1WMUE_LIB_PATH . DIRECTORY_SEPARATOR . 'view' );

// ===============
// = Vendor Path =
// ===============
define( 'AI1WMUE_VENDOR_PATH', AI1WMUE_LIB_PATH . DIRECTORY_SEPARATOR . 'vendor' );

// ===============
// = Service URL =
// ===============
define( 'AI1WMUE_SERVICE_URL', 'https://plugin-assets.wp-migration.com/v4/unlimited-extension/service.wasm' );

// ==================
// = Retention Path =
// ==================
define( 'AI1WMUE_RETENTION_NAME', 'retention.json' );

// ===============================
// = Minimal Base Plugin Version =
// ===============================
define( 'AI1WMUE_MIN_AI1WM_VERSION', '7.102' );

// ===============
// = Purchase ID =
// ===============
define( 'AI1WMUE_PURCHASE_ID', '1fef7581-a7b3-4083-a7ab-2ef69f393281' );
