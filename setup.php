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

/*
 * Cacti includes setup.php on every request regardless of PHP version. Keep
 * this file PHP 8.0 parseable so sites running PHP 8.0 or 8.1 receive a clean
 * refusal instead of a fatal parse error.
 */

/**
 * Check whether the active PHP runtime meets the plugin's minimum PHP 8.2 floor.
 *
 * @return bool
 */
function wordpress_php_supported(): bool {
	return version_compare(PHP_VERSION, '8.2.0', '>=');
}

/**
 * Bootstrap the plugin's zero-dependency PSR-4 autoloader when PHP >= 8.2.
 *
 * @return bool
 */
function wordpress_boot(): bool {
	if (!wordpress_php_supported()) {
		return false;
	}

	require_once(__DIR__ . '/include/autoload.php');

	return true;
}

/**
 * Log and surface a clean refusal when running on PHP < 8.2.
 *
 * @return bool True when PHP is unsupported and execution should stop.
 */
function wordpress_refuse_unsupported_php(): bool {
	if (wordpress_php_supported()) {
		return false;
	}

	$message = __('The WordPress plugin requires PHP %s or later. This server runs PHP %s, so the plugin was not installed or enabled.', '8.2.0', PHP_VERSION, 'wordpress');

	cacti_log('ERROR: ' . $message, false, 'WORDPRESS');

	if (PHP_SAPI === 'cli') {
		fwrite(STDERR, $message . PHP_EOL);
	} elseif (function_exists('raise_message')) {
		raise_message('wordpress_php', $message, MESSAGE_LEVEL_ERROR);
	}

	return true;
}

/**
 * Parse plugin metadata from INFO for Cacti's Plugin Management registry.
 *
 * @return array<string, string>
 */
function plugin_wordpress_version(): array {
	$info = parse_ini_file(__DIR__ . '/INFO', true);

	if (!is_array($info) || !isset($info['info']) || !is_array($info['info'])) {
		return array();
	}

	$version = array();

	foreach ($info['info'] as $key => $value) {
		$version[(string) $key] = is_scalar($value) ? (string) $value : '';
	}

	return $version;
}

/**
 * Cacti plugin install lifecycle callback.
 *
 * @return void
 */
function plugin_wordpress_install(): void {
	if (wordpress_refuse_unsupported_php()) {
		return;
	}

	plugin_wordpress_upgrade();
}

/**
 * Cacti plugin configuration check lifecycle callback.
 *
 * @return bool
 */
function plugin_wordpress_check_config(): bool {
	if (wordpress_refuse_unsupported_php()) {
		return false;
	}

	return plugin_wordpress_upgrade();
}

/**
 * Run idempotent schema migrations, hook registrations, and version recording.
 *
 * @return bool
 */
function plugin_wordpress_upgrade(): bool {
	if (!wordpress_boot()) {
		return false;
	}

	$info   = plugin_wordpress_version();
	$schema = new \Somethingwithproof\WordPress\Schema(false);

	if ($schema->isCurrent() && $schema->recordedPluginVersion() === ($info['version'] ?? '') && $schema->hooksRegistered()) {
		return true;
	}

	if (!$schema->migrate()) {
		return false;
	}

	wordpress_setup_hooks();
	$schema->recordPluginVersion($info['version'] ?? '0.1.0', $info['author'] ?? '', $info['homepage'] ?? '');

	return true;
}

/**
 * Register Cacti hooks and 3-tier RBAC realms.
 *
 * Kept procedural with *_setup_* naming because Cacti's
 * api_plugin_register_hook() and api_plugin_register_realm() validate the
 * caller's function name.
 *
 * @return void
 */
function wordpress_setup_hooks(): void {
	global $config;

	if (!function_exists('replicate_out') && isset($config['library_path']) && is_string($config['library_path']) && is_file($config['library_path'] . '/poller.php')) {
		include_once($config['library_path'] . '/poller.php');
	}

	$enabled = (new \Somethingwithproof\WordPress\Schema(false))->pluginEnabled();

	foreach (\Somethingwithproof\WordPress\Schema::HOOKS as $hook => $function) {
		api_plugin_register_hook('wordpress', $hook, $function, 'setup.php', $enabled);
	}

	foreach (\Somethingwithproof\WordPress\Pages::realms() as $realm) {
		api_plugin_register_realm('wordpress', implode(',', $realm['files']), $realm['name'], $realm['default']);
	}
}

/**
 * Cacti plugin uninstall lifecycle callback honoring table retention settings.
 *
 * @return void
 */
function plugin_wordpress_uninstall(): void {
	if (!wordpress_boot()) {
		return;
	}

	$schema = new \Somethingwithproof\WordPress\Schema(false);

	if (read_config_option('wordpress_uninstall_keep_tables') == 'on') {
		$schema->untrackTables();
		cacti_log('NOTE: Uninstall kept plugin_wordpress tables as configured', false, 'WORDPRESS');
	} else {
		$schema->forgetVersion();
	}
}

/**
 * Load current plugin configuration from Cacti's settings table.
 *
 * @return \Somethingwithproof\WordPress\Settings
 */
function wordpress_settings(): \Somethingwithproof\WordPress\Settings {
	$row = array();

	foreach (\Somethingwithproof\WordPress\Settings::NAMES as $name) {
		$row[$name] = read_config_option($name);
	}

	return \Somethingwithproof\WordPress\Settings::fromRow($row);
}

/**
 * Persist validated plugin configuration into Cacti's settings table.
 *
 * @param \Somethingwithproof\WordPress\Settings $settings Validated settings snapshot.
 * @return bool
 */
function wordpress_save_settings(\Somethingwithproof\WordPress\Settings $settings): bool {
	if (!function_exists('db_execute_prepared')) {
		return false;
	}

	foreach ($settings->toCactiSettingsMap() as $name => $value) {
		$ok = db_execute_prepared(
			'REPLACE INTO settings (name, value) VALUES (?, ?)',
			array($name, $value)
		);

		if (!$ok) {
			return false;
		}
	}

	wordpress_reset_runtime();

	return true;
}

/**
 * Reset cached in-process runtime singletons after configuration updates or in tests.
 *
 * @param \Somethingwithproof\WordPress\Db\DbAdapter|null $dbOverride Optional test DbAdapter override.
 * @param \Somethingwithproof\WordPress\Client\HttpTransport|null $transportOverride Optional test HttpTransport override.
 * @return void
 */
function wordpress_reset_runtime(
	?\Somethingwithproof\WordPress\Db\DbAdapter $dbOverride = null,
	?\Somethingwithproof\WordPress\Client\HttpTransport $transportOverride = null
): void {
	$GLOBALS['__plugin_wordpress_db']        = $dbOverride;
	$GLOBALS['__plugin_wordpress_transport'] = $transportOverride;
	$GLOBALS['__plugin_wordpress_repo']      = null;
	$GLOBALS['__plugin_wordpress_vault']     = null;
	$GLOBALS['__plugin_wordpress_poller']    = null;
}

/**
 * Return the active DbAdapter instance for the current process.
 *
 * @return \Somethingwithproof\WordPress\Db\DbAdapter
 */
function wordpress_db(): \Somethingwithproof\WordPress\Db\DbAdapter {
	if (isset($GLOBALS['__plugin_wordpress_db']) && $GLOBALS['__plugin_wordpress_db'] instanceof \Somethingwithproof\WordPress\Db\DbAdapter) {
		return $GLOBALS['__plugin_wordpress_db'];
	}

	$adapter = function_exists('db_execute_prepared')
		? new \Somethingwithproof\WordPress\Db\CactiDbAdapter(false)
		: new \Somethingwithproof\WordPress\Db\MemoryDbAdapter();

	$GLOBALS['__plugin_wordpress_db'] = $adapter;

	return $adapter;
}

/**
 * Return the singleton SiteRepository instance.
 *
 * @return \Somethingwithproof\WordPress\Repository\SiteRepository
 */
function wordpress_repository(): \Somethingwithproof\WordPress\Repository\SiteRepository {
	if (isset($GLOBALS['__plugin_wordpress_repo']) && $GLOBALS['__plugin_wordpress_repo'] instanceof \Somethingwithproof\WordPress\Repository\SiteRepository) {
		return $GLOBALS['__plugin_wordpress_repo'];
	}

	$repo                               = new \Somethingwithproof\WordPress\Repository\SiteRepository(wordpress_db());
	$GLOBALS['__plugin_wordpress_repo'] = $repo;

	return $repo;
}

/**
 * Return the singleton local AES-256-GCM SecretVault instance.
 *
 * @return \Somethingwithproof\WordPress\Security\SecretVault
 */
function wordpress_vault(): \Somethingwithproof\WordPress\Security\SecretVault {
	if (isset($GLOBALS['__plugin_wordpress_vault']) && $GLOBALS['__plugin_wordpress_vault'] instanceof \Somethingwithproof\WordPress\Security\SecretVault) {
		return $GLOBALS['__plugin_wordpress_vault'];
	}

	$settings                            = wordpress_settings();
	$vault                               = new \Somethingwithproof\WordPress\Security\SecretVault(wordpress_db(), $settings->vaultKeyFile);
	$GLOBALS['__plugin_wordpress_vault'] = $vault;

	return $vault;
}

/**
 * Return the singleton FleetPoller instance configured with OutboundGuard and SecretVault.
 *
 * @return \Somethingwithproof\WordPress\Poller\FleetPoller
 */
function wordpress_poller(): \Somethingwithproof\WordPress\Poller\FleetPoller {
	if (isset($GLOBALS['__plugin_wordpress_poller']) && $GLOBALS['__plugin_wordpress_poller'] instanceof \Somethingwithproof\WordPress\Poller\FleetPoller) {
		return $GLOBALS['__plugin_wordpress_poller'];
	}

	$settings  = wordpress_settings();
	$transport = (isset($GLOBALS['__plugin_wordpress_transport']) && $GLOBALS['__plugin_wordpress_transport'] instanceof \Somethingwithproof\WordPress\Client\HttpTransport)
		? $GLOBALS['__plugin_wordpress_transport']
		: new \Somethingwithproof\WordPress\Client\CurlHttpTransport();

	$guard  = new \Somethingwithproof\WordPress\Security\OutboundGuard(
		$settings->parsedAllowlistHosts(),
		$settings->parsedAllowlistCidrs(),
		$settings->connectTimeout,
		$settings->readTimeout,
		$settings->maxResponseBytes,
		true
	);
	$client = new \Somethingwithproof\WordPress\Client\WordPressClient($transport, $guard, $settings->userAgent, $settings);
	$poller = new \Somethingwithproof\WordPress\Poller\FleetPoller(
		wordpress_repository(),
		wordpress_vault(),
		$client,
		new \Somethingwithproof\WordPress\Metrics\AdaptivePollerSizer(),
		$settings
	);

	$GLOBALS['__plugin_wordpress_poller'] = $poller;

	return $poller;
}

/**
 * Register Console menu entries under Utilities and run automatic upgrade checks.
 *
 * @return void
 */
function wordpress_config_arrays(): void {
	global $menu;

	if (!wordpress_boot()) {
		return;
	}

	foreach (\Somethingwithproof\WordPress\Pages::menu() as $file => $title) {
		$menu[__('Utilities')]['plugins/wordpress/' . $file] = $title;
	}

	if (in_array(get_current_page(), \Somethingwithproof\WordPress\Pages::upgradeTriggers(), true)) {
		plugin_wordpress_upgrade();
	}
}

/**
 * Register the WordPress tab under Console -> Configuration -> Settings for Admin users.
 *
 * @return void
 */
function wordpress_config_settings(): void {
	global $tabs, $settings;

	if (PHP_SAPI !== 'cli' && !api_plugin_user_realm_auth(\Somethingwithproof\WordPress\Pages::ADMIN)) {
		return;
	}

	if (!wordpress_boot()) {
		return;
	}

	$tabs['wordpress']     = __('WordPress', 'wordpress');
	$settings['wordpress'] = \Somethingwithproof\WordPress\Settings::form();
}

/**
 * Register navigation breadcrumbs for plugin_wordpress Console pages.
 *
 * @param array<string, mixed> $nav Existing Cacti navigation breadcrumb map.
 * @return array<string, mixed>
 */
function wordpress_draw_navigation_text(array $nav): array {
	global $current_user;

	if (!wordpress_boot()) {
		return $nav;
	}

	if (get_current_page() === 'settings.php' && (PHP_SAPI === 'cli' || ($current_user['enabled'] ?? '') === 'on')) {
		wordpress_config_settings();
	}

	return array_merge($nav, \Somethingwithproof\WordPress\Pages::navigation());
}

/**
 * Resolve 3-tier realm inheritance: WordPress Admin > WordPress Operator > WordPress View.
 *
 * @return void
 */
function wordpress_auth_alternate_realms(): void {
	global $user_auth_realm_filenames;

	static $deferred = array();

	foreach ($deferred as $file => $realm) {
		$user_auth_realm_filenames[$file] = $realm;
	}
	$deferred = array();

	if (!api_plugin_is_enabled('wordpress')) {
		return;
	}

	if (empty($_SESSION['sess_user_id'])) {
		$page = get_current_page();

		if (in_array($page, array('wordpress_view.php', 'wordpress_operator.php'), true) && isset($user_auth_realm_filenames[$page])) {
			$deferred[$page]                  = $user_auth_realm_filenames[$page];
			$user_auth_realm_filenames[$page] = -1;
		}

		return;
	}

	$adminRealm    = is_numeric($user_auth_realm_filenames['wordpress_admin.php'] ?? null) ? (int) $user_auth_realm_filenames['wordpress_admin.php'] : 0;
	$operatorRealm = is_numeric($user_auth_realm_filenames['wordpress_operator.php'] ?? null) ? (int) $user_auth_realm_filenames['wordpress_operator.php'] : 0;

	if ($adminRealm > 0 && is_realm_allowed($adminRealm)) {
		$user_auth_realm_filenames['wordpress_operator.php'] = $adminRealm;
		$user_auth_realm_filenames['wordpress_view.php']     = $adminRealm;
	} elseif ($operatorRealm > 0 && is_realm_allowed($operatorRealm)) {
		$user_auth_realm_filenames['wordpress_view.php'] = $operatorRealm;
	}
}

/**
 * Determine whether the current authenticated user is authorized for the active plugin page.
 *
 * @return bool
 */
function wordpress_page_allowed(): bool {
	global $user_auth_realm_filenames;

	wordpress_auth_alternate_realms();
	$page  = get_current_page();
	$realm = is_numeric($user_auth_realm_filenames[$page] ?? null) ? (int) $user_auth_realm_filenames[$page] : 0;

	return $realm > 0 && is_realm_allowed($realm);
}

/**
 * Guard plugin Console page execution (boot check, enabled check, and 3-tier RBAC check).
 *
 * @return bool True when page execution may continue; false after rendering notice or HTTP 403.
 */
function wordpress_page_start(): bool {
	if (wordpress_boot() && api_plugin_is_enabled('wordpress')) {
		if (wordpress_page_allowed()) {
			return true;
		}

		http_response_code(403);

		return false;
	}

	top_header();
	html_start_box(__('WordPress Fleet Monitor', 'wordpress'), '100%', false, 3, 'center', '');
	print '<tr><td>' . html_escape(wordpress_php_supported() ? __('The WordPress plugin is not enabled.', 'wordpress') : __('The WordPress plugin requires PHP %s or later.', '8.2.0', 'wordpress')) . '</td></tr>';
	html_end_box();
	bottom_footer();

	return false;
}

/**
 * Poller bottom hook: poll WordPress sites assigned to the active Cacti poller ID.
 *
 * @return void
 */
function wordpress_poller_bottom(): void {
	global $config;

	if (!wordpress_boot()) {
		return;
	}

	$pollerId = isset($config['poller_id']) && is_numeric($config['poller_id']) ? max(1, (int) $config['poller_id']) : 1;

	try {
		$result = wordpress_poller()->pollFleet($pollerId, 1, 1, false);
		\Somethingwithproof\WordPress\Log::info(sprintf(
			'Poller %d completed: polled=%d healthy=%d degraded=%d critical=%d concurrency=%d duration=%.2fms',
			$pollerId,
			$result['polled'],
			$result['healthy'],
			$result['degraded'],
			$result['critical'],
			$result['sizing']['recommendedConcurrency'],
			$result['durationMs']
		));
	} catch (\Throwable $error) {
		\Somethingwithproof\WordPress\Log::warning('Poller bottom skipped: ' . $error->getMessage());
	}
}

/**
 * Cacti replicate_out hook: replicate ONLY non-secret plugin_wordpress_sites rows to remote pollers.
 *
 * Never replicates plugin_wordpress_secrets, keyfile paths, or encrypted Application Passwords.
 *
 * @param array<string, mixed> $data Replication payload containing remote_poller_id, rcnn_id, and class.
 * @return array<string, mixed>
 */
function wordpress_replicate_out(array $data): array {
	if (!wordpress_boot()) {
		return $data;
	}

	$class    = isset($data['class']) && is_string($data['class']) ? $data['class'] : '';
	$pollerId = isset($data['remote_poller_id']) && is_numeric($data['remote_poller_id']) ? (int) $data['remote_poller_id'] : 0;

	if ($pollerId <= 1 || ($class !== '' && $class !== 'all' && $class !== 'wordpress')) {
		return $data;
	}

	$remoteConn = $data['rcnn_id'] ?? false;

	if ($remoteConn instanceof \PDO) {
		$count = wordpress_repository()->replicateSitesToRemote(
			new \Somethingwithproof\WordPress\Db\CactiDbAdapter($remoteConn),
			$pollerId
		);
		\Somethingwithproof\WordPress\Log::info(sprintf('Replicated %d non-secret WordPress site row(s) to remote poller %d.', $count, $pollerId));
	} elseif (isset($data['remote_adapter']) && $data['remote_adapter'] instanceof \Somethingwithproof\WordPress\Db\DbAdapter) {
		$count                           = wordpress_repository()->replicateSitesToRemote($data['remote_adapter'], $pollerId);
		$data['wordpress_replicated']    = $count;
	}

	return $data;
}

/**
 * casc_register_providers hook: register config-only provider for slug "wordpress".
 *
 * @param mixed $registrar Registrar object exposing register().
 * @return void
 */
function wordpress_casc_register_providers(mixed $registrar): void {
	if (!wordpress_boot() || !is_object($registrar)) {
		return;
	}

	\Somethingwithproof\WordPress\Integration\CascProvider::register(
		$registrar,
		static function (): \Somethingwithproof\WordPress\Settings {
			return wordpress_settings();
		},
		static function (\Somethingwithproof\WordPress\Settings $settings): bool {
			return wordpress_save_settings($settings);
		},
		static function (): \Somethingwithproof\WordPress\Repository\SiteRepository {
			return wordpress_repository();
		}
	);
}

/**
 * doctor_register_checks hook: return pre-evaluated WordPress diagnostic check descriptors.
 *
 * @param mixed $context Context map (e.g. ['mode' => 'run'|'list', 'plugin' => 'wordpress']) or prior list.
 * @return mixed
 */
function wordpress_doctor_register_checks(mixed $context): mixed {
	if (!wordpress_boot()) {
		return array();
	}

	$mode = (is_array($context) && isset($context['mode']) && is_string($context['mode']))
		? $context['mode']
		: 'run';

	$built = \Somethingwithproof\WordPress\Integration\DoctorChecks::buildChecks(
		static function (): \Somethingwithproof\WordPress\Security\SecretVault {
			return wordpress_vault();
		},
		static function (): \Somethingwithproof\WordPress\Repository\SiteRepository {
			return wordpress_repository();
		},
		static function (): \Somethingwithproof\WordPress\Settings {
			return wordpress_settings();
		},
		$mode
	);

	if (is_array($context) && array_is_list($context) && $context !== array()) {
		return array_merge($context, $built);
	}

	return $built;
}

/**
 * doctor_register_debug_info hook: return strictly redacted WordPress debug info sections.
 *
 * @param mixed $context Context map (e.g. ['plugin' => 'wordpress']) or prior list of sections.
 * @return mixed
 */
function wordpress_doctor_register_debug_info(mixed $context): mixed {
	if (!wordpress_boot()) {
		return array();
	}

	$sections = \Somethingwithproof\WordPress\Integration\DoctorChecks::buildDebugInfo(
		static function (): \Somethingwithproof\WordPress\Security\SecretVault {
			return wordpress_vault();
		},
		static function (): \Somethingwithproof\WordPress\Repository\SiteRepository {
			return wordpress_repository();
		},
		static function (): \Somethingwithproof\WordPress\Settings {
			return wordpress_settings();
		}
	);

	if (is_array($context) && array_is_list($context) && $context !== array()) {
		return array_merge($context, $sections);
	}

	return $sections;
}

/**
 * abilities_register hook: register read-only WordPress fleet MCP abilities.
 *
 * @param mixed $registrar Registrar object exposing register().
 * @return void
 */
function wordpress_abilities_register(mixed $registrar): void {
	if (!wordpress_boot() || !is_object($registrar)) {
		return;
	}

	\Somethingwithproof\WordPress\Integration\McpAbilities::register(
		$registrar,
		static function (): \Somethingwithproof\WordPress\Repository\SiteRepository {
			return wordpress_repository();
		},
		static function (): \Somethingwithproof\WordPress\Settings {
			return wordpress_settings();
		},
		static function (int $userId): bool {
			return \Somethingwithproof\WordPress\Integration\McpAbilities::userHasViewRealm($userId);
		}
	);
}

/**
 * api_register_resources hook: return plain-array descriptors for wordpressSites and wordpressHealth.
 *
 * @param mixed $resources Existing resource list or context.
 * @return mixed
 */
function wordpress_api_register_resources(mixed $resources): mixed {
	if (!wordpress_boot()) {
		return array();
	}

	$built = \Somethingwithproof\WordPress\Integration\ApiResources::build(
		static function (): \Somethingwithproof\WordPress\Repository\SiteRepository {
			return wordpress_repository();
		},
		static function (): \Somethingwithproof\WordPress\Settings {
			return wordpress_settings();
		}
	);

	if (is_array($resources) && array_is_list($resources) && $resources !== array()) {
		return array_merge($resources, $built);
	}

	return $built;
}
