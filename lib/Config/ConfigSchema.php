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

declare(strict_types=1);

namespace Somethingwithproof\WordPress\Config;

use Somethingwithproof\WordPress\Settings;

/**
 * Runtime validator mirroring schema/wordpress.schema.yaml with strict Config vs. State
 * separation and symbolic vault:wordpress:<slug> secret reference enforcement.
 */
final class ConfigSchema {
	/**
	 * Declarative schema version matching schema/wordpress.schema.yaml.
	 */
	public const SCHEMA_VERSION = '1.0';

	/**
	 * Valid site slug pattern (lowercase alphanumeric, hyphen, underscore, 2-64 chars).
	 */
	public const SLUG_PATTERN = '/^[a-z0-9][a-z0-9_-]{1,63}$/';

	/**
	 * Valid vault secret reference pattern for WordPress Application Passwords.
	 */
	public const SECRET_REF_PATTERN = '/^vault:wordpress:[a-z0-9][a-z0-9_-]{1,63}$/';

	/**
	 * Integer field bounds matching schema/wordpress.schema.yaml.
	 *
	 * @var array<string, array{min: int, max: int}>
	 */
	private const INT_BOUNDS = [
		'wordpress_poll_interval'       => ['min' => 30, 'max' => 86400],
		'wordpress_connect_timeout'     => ['min' => 1, 'max' => 15],
		'wordpress_read_timeout'        => ['min' => 1, 'max' => 60],
		'wordpress_max_response_bytes'  => ['min' => 65536, 'max' => 2097152],
		'wordpress_default_apdex_t_ms'  => ['min' => 50, 'max' => 10000],
		'wordpress_autoload_warn_bytes' => ['min' => 65536, 'max' => 16777216],
		'wordpress_autoload_crit_bytes' => ['min' => 131072, 'max' => 33554432],
		'wordpress_cron_lag_warn_sec'   => ['min' => 60, 'max' => 86400],
		'wordpress_tls_warn_days'       => ['min' => 1, 'max' => 180],
		'wordpress_tls_crit_days'       => ['min' => 1, 'max' => 90],
		'wordpress_codel_target_ms'     => ['min' => 50, 'max' => 10000],
		'wordpress_min_concurrency'     => ['min' => 1, 'max' => 64],
		'wordpress_max_concurrency'     => ['min' => 1, 'max' => 256],
	];

	/**
	 * Keys forbidden in declarative Config documents because they belong to State or raw secrets.
	 */
	private const FORBIDDEN_KEYS = [
		'password',
		'app_password',
		'application_password',
		'ciphertext',
		'secret',
		'secrets',
		'snapshots',
		'poller_state',
	];

	/**
	 * Validate a plugin settings map and optional sites collection against the schema.
	 *
	 * @param array<string, mixed> $config Candidate declarative Config document or flat settings map.
	 * @return list<string> Validation error messages (empty when valid).
	 */
	public static function validate(array $config): array {
		$errors  = [];
		$allowed = array_flip(array_merge(Settings::NAMES, ['sites']));

		foreach ($config as $key => $value) {
			$keyStr = (string) $key;

			if (in_array(strtolower($keyStr), self::FORBIDDEN_KEYS, true)) {
				$errors[] = sprintf('Field "%s" is forbidden in declarative Config (use vault:wordpress:<slug> references only).', $keyStr);

				continue;
			}

			if (!isset($allowed[$keyStr])) {
				$errors[] = sprintf('Unknown configuration field "%s".', $keyStr);

				continue;
			}

			if ($keyStr === 'sites') {
				if (!is_array($value)) {
					$errors[] = 'Field "sites" must be a list of site definitions.';
				} else {
					$errors = array_merge($errors, self::validateSites($value));
				}

				continue;
			}

			if (isset(self::INT_BOUNDS[$keyStr])) {
				$bounds = self::INT_BOUNDS[$keyStr];

				if (!is_int($value) && !(is_string($value) && preg_match('/^-?\d+$/', $value) === 1)) {
					$errors[] = sprintf('Field "%s" must be an integer.', $keyStr);

					continue;
				}

				$intVal = (int) $value;

				if ($intVal < $bounds['min'] || $intVal > $bounds['max']) {
					$errors[] = sprintf('Field "%s" must be between %d and %d.', $keyStr, $bounds['min'], $bounds['max']);
				}

				continue;
			}

			if ($keyStr === 'wordpress_uninstall_keep_tables') {
				if (!is_bool($value) && !in_array($value, ['on', '', '0', '1', 0, 1], true)) {
					$errors[] = 'Field "wordpress_uninstall_keep_tables" must be a boolean.';
				}

				continue;
			}

			if (!is_string($value)) {
				$errors[] = sprintf('Field "%s" must be a string.', $keyStr);

				continue;
			}

			if ($keyStr === 'wordpress_vault_key_file' && $value !== '' && preg_match('/^\/[A-Za-z0-9_.\/-]{1,254}$/', $value) !== 1) {
				$errors[] = 'Field "wordpress_vault_key_file" must be empty or a clean absolute path without traversal.';
			} elseif ($keyStr === 'wordpress_vault_key_file' && str_contains($value, '..')) {
				$errors[] = 'Field "wordpress_vault_key_file" must not contain path traversal segments.';
			} elseif ($keyStr === 'wordpress_allowlist_hosts' && preg_match('/^[A-Za-z0-9.*, _:-]{0,1024}$/', $value) !== 1) {
				$errors[] = 'Field "wordpress_allowlist_hosts" contains unsupported characters.';
			} elseif ($keyStr === 'wordpress_allowlist_cidrs' && preg_match('/^[0-9a-fA-F:.,\/ ]{0,1024}$/', $value) !== 1) {
				$errors[] = 'Field "wordpress_allowlist_cidrs" contains unsupported characters.';
			} elseif ($keyStr === 'wordpress_user_agent' && preg_match('/^[A-Za-z0-9 ._\/+();:-]{1,128}$/', $value) !== 1) {
				$errors[] = 'Field "wordpress_user_agent" must be 1-128 safe printable ASCII characters.';
			}
		}

		if (isset($config['wordpress_autoload_warn_bytes'], $config['wordpress_autoload_crit_bytes'])
			&& is_numeric($config['wordpress_autoload_warn_bytes'])
			&& is_numeric($config['wordpress_autoload_crit_bytes'])
			&& (int) $config['wordpress_autoload_crit_bytes'] < (int) $config['wordpress_autoload_warn_bytes']
		) {
			$errors[] = 'Field "wordpress_autoload_crit_bytes" must be greater than or equal to "wordpress_autoload_warn_bytes".';
		}

		if (isset($config['wordpress_min_concurrency'], $config['wordpress_max_concurrency'])
			&& is_numeric($config['wordpress_min_concurrency'])
			&& is_numeric($config['wordpress_max_concurrency'])
			&& (int) $config['wordpress_max_concurrency'] < (int) $config['wordpress_min_concurrency']
		) {
			$errors[] = 'Field "wordpress_max_concurrency" must be greater than or equal to "wordpress_min_concurrency".';
		}

		return $errors;
	}

	/**
	 * Validate a single site definition array.
	 *
	 * @param array<string, mixed> $site Candidate site record.
	 * @return list<string>
	 */
	public static function validateSite(array $site): array {
		$errors = [];

		foreach (self::FORBIDDEN_KEYS as $forbidden) {
			if (array_key_exists($forbidden, $site)) {
				$errors[] = sprintf('Site config must not contain raw secret field "%s"; use "secret_ref".', $forbidden);
			}
		}

		$slug = $site['slug'] ?? '';

		if (!is_string($slug) || preg_match(self::SLUG_PATTERN, $slug) !== 1) {
			$errors[] = 'Site "slug" must match ^[a-z0-9][a-z0-9_-]{1,63}$.';
		}

		$name = $site['name'] ?? '';

		if (!is_string($name) || trim($name) === '' || strlen($name) > 128) {
			$errors[] = 'Site "name" must be a non-empty string up to 128 characters.';
		}

		$url = $site['base_url'] ?? '';

		if (!is_string($url) || !str_starts_with(strtolower($url), 'https://') || filter_var($url, FILTER_VALIDATE_URL) === false) {
			$errors[] = 'Site "base_url" must be a valid https:// URL.';
		}

		$username = $site['username'] ?? '';

		if (!is_string($username) || trim($username) === '' || strlen($username) > 128) {
			$errors[] = 'Site "username" must be a non-empty string up to 128 characters.';
		}

		if (array_key_exists('secret_ref', $site)) {
			$ref = $site['secret_ref'];

			if (!is_string($ref) || preg_match(self::SECRET_REF_PATTERN, $ref) !== 1) {
				$errors[] = 'Site "secret_ref" must match vault:wordpress:<slug>.';
			} elseif (is_string($slug) && $slug !== '' && $ref !== 'vault:wordpress:' . $slug) {
				$errors[] = sprintf('Site "secret_ref" must reference vault:wordpress:%s.', $slug);
			}
		}

		if (isset($site['poller_id']) && (!is_numeric($site['poller_id']) || (int) $site['poller_id'] < 1)) {
			$errors[] = 'Site "poller_id" must be a positive integer.';
		}

		if (isset($site['telemetry_path']) && (!is_string($site['telemetry_path']) || strlen($site['telemetry_path']) > 255 || ($site['telemetry_path'] !== '' && !str_starts_with($site['telemetry_path'], '/')))) {
			$errors[] = 'Site "telemetry_path" must be empty or start with "/".';
		}

		if (isset($site['timeout_connect']) && (!is_numeric($site['timeout_connect']) || (int) $site['timeout_connect'] < 1 || (int) $site['timeout_connect'] > 15)) {
			$errors[] = 'Site "timeout_connect" must be between 1 and 15 seconds.';
		}

		if (isset($site['timeout_read']) && (!is_numeric($site['timeout_read']) || (int) $site['timeout_read'] < 1 || (int) $site['timeout_read'] > 60)) {
			$errors[] = 'Site "timeout_read" must be between 1 and 60 seconds.';
		}

		if (isset($site['apdex_t_ms']) && (!is_numeric($site['apdex_t_ms']) || (int) $site['apdex_t_ms'] < 50 || (int) $site['apdex_t_ms'] > 10000)) {
			$errors[] = 'Site "apdex_t_ms" must be between 50 and 10000 ms.';
		}

		return $errors;
	}

	/**
	 * Validate an array of site records and ensure slugs are unique.
	 *
	 * @param array<mixed> $sites Candidate sites list.
	 * @return list<string>
	 */
	private static function validateSites(array $sites): array {
		$errors = [];
		$seen   = [];

		foreach ($sites as $index => $site) {
			if (!is_array($site)) {
				$errors[] = sprintf('Site entry #%d must be an associative map.', (int) $index);

				continue;
			}

			/** @var array<string, mixed> $typedSite */
			$typedSite  = $site;
			$siteErrors = self::validateSite($typedSite);

			foreach ($siteErrors as $msg) {
				$errors[] = sprintf('sites[%s]: %s', (string) $index, $msg);
			}

			$slug = $typedSite['slug'] ?? '';

			if (is_string($slug) && $slug !== '') {
				if (isset($seen[$slug])) {
					$errors[] = sprintf('Duplicate site slug "%s".', $slug);
				}

				$seen[$slug] = true;
			}
		}

		return $errors;
	}
}
