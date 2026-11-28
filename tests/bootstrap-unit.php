<?php
/*
 * SPDX-FileCopyrightText: 2026 Thomas Vincent <thomasvincent@gmail.com>
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This file is part of plugin_wordpress, a plugin for Cacti.
 * https://github.com/somethingwithproof/plugin_wordpress
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 */

$GLOBALS['__wp_log']     = [];
$GLOBALS['__wp_options'] = [];

if (!defined('MESSAGE_LEVEL_ERROR')) {
	define('MESSAGE_LEVEL_ERROR', 2);
}

if (!function_exists('__')) {
	function __() {
		$args = func_get_args();

		if (count($args) === 1 || preg_match('/%(%|c|[-0-9.]*[bdeEfFgGhHosuxX])/', (string) $args[0]) !== 1) {
			return (string) $args[0];
		}

		return call_user_func_array('sprintf', $args);
	}
}

if (!function_exists('cacti_log')) {
	function cacti_log($string, $output = false, $environ = 'CMDPHP', $level = '') {
		$GLOBALS['__wp_log'][] = ['message' => (string) $string, 'environ' => (string) $environ];

		return true;
	}
}

if (!function_exists('html_escape')) {
	function html_escape($string) {
		return htmlspecialchars((string) $string, ENT_QUOTES, 'UTF-8', false);
	}
}

if (!function_exists('read_config_option')) {
	function read_config_option($config_name, $force = false) {
		return $GLOBALS['__wp_options'][$config_name] ?? '';
	}
}

if (!function_exists('get_current_page')) {
	function get_current_page() {
		return $GLOBALS['__wp_current_page'] ?? 'index.php';
	}
}

if (!function_exists('api_plugin_is_enabled')) {
	function api_plugin_is_enabled($plugin) {
		return (bool) ($GLOBALS['__wp_enabled'] ?? true);
	}
}

if (!function_exists('api_plugin_user_realm_auth')) {
	function api_plugin_user_realm_auth($filename) {
		return (bool) ($GLOBALS['__wp_realm_auth'][$filename] ?? true);
	}
}

if (!function_exists('is_realm_allowed')) {
	function is_realm_allowed($realm, $user = 0) {
		return in_array((int) $realm, $GLOBALS['__wp_allowed_realms'] ?? [], true);
	}
}

$GLOBALS['config'] = [
	'base_path'    => dirname(__DIR__, 3),
	'library_path' => dirname(__DIR__, 3) . '/lib',
	'poller_id'    => 1,
];

require_once dirname(__DIR__) . '/include/autoload.php';
require_once dirname(__DIR__) . '/setup.php';
require_once dirname(__DIR__) . '/scripts/ss_wordpress_stats.php';
