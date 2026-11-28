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

namespace Somethingwithproof\WordPress;

/**
 * Typed immutable configuration snapshot for plugin_wordpress settings stored in Cacti.
 */
final class Settings {
	/**
	 * Default maximum outbound HTTP response payload cap (2 MiB).
	 */
	public const DEFAULT_MAX_RESPONSE_BYTES = 2097152;

	/**
	 * Default autoload warning threshold (800 KiB).
	 */
	public const DEFAULT_AUTOLOAD_WARN_BYTES = 819200;

	/**
	 * Default autoload critical threshold (2 MiB).
	 */
	public const DEFAULT_AUTOLOAD_CRIT_BYTES = 2097152;

	/**
	 * Ordered list of Cacti settings table keys managed by plugin_wordpress.
	 */
	public const NAMES = [
		'wordpress_vault_key_file',
		'wordpress_poll_interval',
		'wordpress_connect_timeout',
		'wordpress_read_timeout',
		'wordpress_max_response_bytes',
		'wordpress_allowlist_hosts',
		'wordpress_allowlist_cidrs',
		'wordpress_default_apdex_t_ms',
		'wordpress_autoload_warn_bytes',
		'wordpress_autoload_crit_bytes',
		'wordpress_cron_lag_warn_sec',
		'wordpress_tls_warn_days',
		'wordpress_tls_crit_days',
		'wordpress_codel_target_ms',
		'wordpress_min_concurrency',
		'wordpress_max_concurrency',
		'wordpress_user_agent',
		'wordpress_uninstall_keep_tables',
	];

	/**
	 * Construct a validated Settings value object.
	 *
	 * @param string $vaultKeyFile Absolute path to the external 256-bit AES-GCM vault keyfile.
	 * @param int $pollInterval Fleet polling interval in seconds.
	 * @param int $connectTimeout Outbound TCP/TLS connect timeout in seconds.
	 * @param int $readTimeout Outbound HTTP read timeout in seconds.
	 * @param int $maxResponseBytes Maximum HTTP response body size in bytes (capped at 2 MiB).
	 * @param string $allowlistHosts Comma-separated internal hostnames or wildcard patterns exempt from private-IP SSRF blocking.
	 * @param string $allowlistCidrs Comma-separated internal CIDRs permitted by OutboundGuard.
	 * @param int $defaultApdexTMs Default Apdex satisfied latency threshold T in milliseconds.
	 * @param int $autoloadWarnBytes Autoload bloat warning threshold in bytes.
	 * @param int $autoloadCritBytes Autoload bloat critical threshold in bytes.
	 * @param int $cronLagWarnSec WP-Cron oldest overdue job lag warning threshold in seconds.
	 * @param int $tlsWarnDays TLS expiry warning threshold in days.
	 * @param int $tlsCritDays TLS expiry critical threshold in days.
	 * @param int $codelTargetMs CoDel standing-delay target in milliseconds.
	 * @param int $minConcurrency Minimum adaptive poller concurrency per collector shard.
	 * @param int $maxConcurrency Maximum adaptive poller concurrency per collector shard.
	 * @param string $userAgent Outbound HTTP User-Agent header value.
	 * @param bool $uninstallKeepTables Preserve plugin_wordpress tables when uninstalling.
	 */
	public function __construct(
		public readonly string $vaultKeyFile = '',
		public readonly int $pollInterval = 300,
		public readonly int $connectTimeout = 5,
		public readonly int $readTimeout = 10,
		public readonly int $maxResponseBytes = self::DEFAULT_MAX_RESPONSE_BYTES,
		public readonly string $allowlistHosts = '',
		public readonly string $allowlistCidrs = '',
		public readonly int $defaultApdexTMs = 500,
		public readonly int $autoloadWarnBytes = self::DEFAULT_AUTOLOAD_WARN_BYTES,
		public readonly int $autoloadCritBytes = self::DEFAULT_AUTOLOAD_CRIT_BYTES,
		public readonly int $cronLagWarnSec = 900,
		public readonly int $tlsWarnDays = 30,
		public readonly int $tlsCritDays = 7,
		public readonly int $codelTargetMs = 500,
		public readonly int $minConcurrency = 2,
		public readonly int $maxConcurrency = 32,
		public readonly string $userAgent = 'Cacti-Plugin-WordPress/0.1.0',
		public readonly bool $uninstallKeepTables = false,
	) {
	}

	/**
	 * Hydrate a clamped Settings snapshot from a Cacti settings row or associative config array.
	 *
	 * @param array<string, mixed> $row Raw setting values keyed by Cacti setting name.
	 * @return self
	 */
	public static function fromRow(array $row): self {
		$vaultKeyFile = self::stringVal($row['wordpress_vault_key_file'] ?? '', '');
		$pollInterval = self::clampInt($row['wordpress_poll_interval'] ?? 300, 30, 86400, 300);
		$connect      = self::clampInt($row['wordpress_connect_timeout'] ?? 5, 1, 15, 5);
		$read         = self::clampInt($row['wordpress_read_timeout'] ?? 10, 1, 60, 10);
		$maxBytes     = self::clampInt($row['wordpress_max_response_bytes'] ?? self::DEFAULT_MAX_RESPONSE_BYTES, 65536, self::DEFAULT_MAX_RESPONSE_BYTES, self::DEFAULT_MAX_RESPONSE_BYTES);
		$hosts        = self::stringVal($row['wordpress_allowlist_hosts'] ?? '', '');
		$cidrs        = self::stringVal($row['wordpress_allowlist_cidrs'] ?? '', '');
		$apdexT       = self::clampInt($row['wordpress_default_apdex_t_ms'] ?? 500, 50, 10000, 500);
		$autoWarn     = self::clampInt($row['wordpress_autoload_warn_bytes'] ?? self::DEFAULT_AUTOLOAD_WARN_BYTES, 65536, 16777216, self::DEFAULT_AUTOLOAD_WARN_BYTES);
		$autoCrit     = self::clampInt($row['wordpress_autoload_crit_bytes'] ?? self::DEFAULT_AUTOLOAD_CRIT_BYTES, 131072, 33554432, self::DEFAULT_AUTOLOAD_CRIT_BYTES);

		if ($autoCrit < $autoWarn) {
			$autoCrit = $autoWarn;
		}

		$cronLag    = self::clampInt($row['wordpress_cron_lag_warn_sec'] ?? 900, 60, 86400, 900);
		$tlsWarn    = self::clampInt($row['wordpress_tls_warn_days'] ?? 30, 1, 180, 30);
		$tlsCrit    = self::clampInt($row['wordpress_tls_crit_days'] ?? 7, 1, 90, 7);

		if ($tlsCrit > $tlsWarn) {
			$tlsCrit = $tlsWarn;
		}

		$codelTarget = self::clampInt($row['wordpress_codel_target_ms'] ?? 500, 50, 10000, 500);
		$minConc     = self::clampInt($row['wordpress_min_concurrency'] ?? 2, 1, 64, 2);
		$maxConc     = self::clampInt($row['wordpress_max_concurrency'] ?? 32, 1, 256, 32);

		if ($maxConc < $minConc) {
			$maxConc = $minConc;
		}

		$userAgent = self::stringVal($row['wordpress_user_agent'] ?? '', 'Cacti-Plugin-WordPress/0.1.0');
		$userAgent = $userAgent !== '' ? substr($userAgent, 0, 128) : 'Cacti-Plugin-WordPress/0.1.0';
		$keep      = self::boolVal($row['wordpress_uninstall_keep_tables'] ?? false);

		return new self(
			$vaultKeyFile,
			$pollInterval,
			$connect,
			$read,
			$maxBytes,
			$hosts,
			$cidrs,
			$apdexT,
			$autoWarn,
			$autoCrit,
			$cronLag,
			$tlsWarn,
			$tlsCrit,
			$codelTarget,
			$minConc,
			$maxConc,
			$userAgent,
			$keep,
		);
	}

	/**
	 * Parse allowlisted host patterns into a normalized lowercase list.
	 *
	 * @return list<string>
	 */
	public function parsedAllowlistHosts(): array {
		return self::splitCsv($this->allowlistHosts);
	}

	/**
	 * Parse allowlisted CIDR entries into a normalized list.
	 *
	 * @return list<string>
	 */
	public function parsedAllowlistCidrs(): array {
		return self::splitCsv($this->allowlistCidrs);
	}

	/**
	 * Convert Settings to a declarative Config array suitable for CasC export (zero secrets).
	 *
	 * @return array<string, bool|int|string>
	 */
	public function toConfigArray(): array {
		return [
			'wordpress_vault_key_file'        => $this->vaultKeyFile,
			'wordpress_poll_interval'         => $this->pollInterval,
			'wordpress_connect_timeout'       => $this->connectTimeout,
			'wordpress_read_timeout'          => $this->readTimeout,
			'wordpress_max_response_bytes'    => $this->maxResponseBytes,
			'wordpress_allowlist_hosts'       => $this->allowlistHosts,
			'wordpress_allowlist_cidrs'       => $this->allowlistCidrs,
			'wordpress_default_apdex_t_ms'    => $this->defaultApdexTMs,
			'wordpress_autoload_warn_bytes'   => $this->autoloadWarnBytes,
			'wordpress_autoload_crit_bytes'   => $this->autoloadCritBytes,
			'wordpress_cron_lag_warn_sec'     => $this->cronLagWarnSec,
			'wordpress_tls_warn_days'         => $this->tlsWarnDays,
			'wordpress_tls_crit_days'         => $this->tlsCritDays,
			'wordpress_codel_target_ms'       => $this->codelTargetMs,
			'wordpress_min_concurrency'       => $this->minConcurrency,
			'wordpress_max_concurrency'       => $this->maxConcurrency,
			'wordpress_user_agent'            => $this->userAgent,
			'wordpress_uninstall_keep_tables' => $this->uninstallKeepTables,
		];
	}

	/**
	 * Convert Settings to Cacti's string-encoded settings table representation.
	 *
	 * @return array<string, string>
	 */
	public function toCactiSettingsMap(): array {
		$map = [];

		foreach ($this->toConfigArray() as $key => $value) {
			if (is_bool($value)) {
				$map[$key] = $value ? 'on' : '';
			} else {
				$map[$key] = (string) $value;
			}
		}

		return $map;
	}

	/**
	 * Return Cacti Settings tab form metadata for Console -> Configuration -> Settings.
	 *
	 * @return array<string, array<string, mixed>>
	 */
	public static function form(): array {
		return [
			'wordpress_header_security' => [
				'friendly_name' => __('WordPress Fleet Security & Vault', 'wordpress'),
				'method'        => 'spacer',
			],
			'wordpress_vault_key_file' => [
				'friendly_name' => __('Vault Keyfile Path', 'wordpress'),
				'description'   => __('Absolute path to the external 256-bit AES-GCM keyfile used to encrypt Application Passwords at rest. Never replicated to remote pollers.', 'wordpress'),
				'method'        => 'textbox',
				'default'       => '',
				'max_length'    => 255,
			],
			'wordpress_allowlist_hosts' => [
				'friendly_name' => __('Internal Host Allowlist', 'wordpress'),
				'description'   => __('Comma-separated hostnames or wildcard patterns (e.g. *.corp.example) exempt from private-IP SSRF blocking.', 'wordpress'),
				'method'        => 'textbox',
				'default'       => '',
				'max_length'    => 1024,
			],
			'wordpress_allowlist_cidrs' => [
				'friendly_name' => __('Internal CIDR Allowlist', 'wordpress'),
				'description'   => __('Comma-separated internal CIDR ranges explicitly permitted by OutboundGuard.', 'wordpress'),
				'method'        => 'textbox',
				'default'       => '',
				'max_length'    => 1024,
			],
			'wordpress_header_polling' => [
				'friendly_name' => __('Outbound Client & Adaptive Poller Sizing', 'wordpress'),
				'method'        => 'spacer',
			],
			'wordpress_poll_interval' => [
				'friendly_name' => __('Poll Interval (seconds)', 'wordpress'),
				'description'   => __('Target fleet polling interval in seconds for Little\'s Law concurrency sizing.', 'wordpress'),
				'method'        => 'textbox',
				'default'       => '300',
				'max_length'    => 6,
			],
			'wordpress_connect_timeout' => [
				'friendly_name' => __('Connect Timeout (seconds)', 'wordpress'),
				'description'   => __('Maximum TCP/TLS connect duration per WordPress probe (1-15s).', 'wordpress'),
				'method'        => 'textbox',
				'default'       => '5',
				'max_length'    => 3,
			],
			'wordpress_read_timeout' => [
				'friendly_name' => __('Read Timeout (seconds)', 'wordpress'),
				'description'   => __('Maximum total HTTP read duration per WordPress probe (1-60s).', 'wordpress'),
				'method'        => 'textbox',
				'default'       => '10',
				'max_length'    => 3,
			],
			'wordpress_max_response_bytes' => [
				'friendly_name' => __('Max Response Size (bytes)', 'wordpress'),
				'description'   => __('Hard byte ceiling per HTTP response (capped at 2097152 bytes / 2 MiB).', 'wordpress'),
				'method'        => 'textbox',
				'default'       => (string) self::DEFAULT_MAX_RESPONSE_BYTES,
				'max_length'    => 10,
			],
			'wordpress_codel_target_ms' => [
				'friendly_name' => __('CoDel Target Standing Delay (ms)', 'wordpress'),
				'description'   => __('Queue standing-delay target in milliseconds before adaptive concurrency backs off.', 'wordpress'),
				'method'        => 'textbox',
				'default'       => '500',
				'max_length'    => 6,
			],
			'wordpress_min_concurrency' => [
				'friendly_name' => __('Minimum Concurrency', 'wordpress'),
				'description'   => __('Lower bound on concurrent WordPress probe workers per collector shard.', 'wordpress'),
				'method'        => 'textbox',
				'default'       => '2',
				'max_length'    => 3,
			],
			'wordpress_max_concurrency' => [
				'friendly_name' => __('Maximum Concurrency', 'wordpress'),
				'description'   => __('Upper bound on concurrent WordPress probe workers per collector shard.', 'wordpress'),
				'method'        => 'textbox',
				'default'       => '32',
				'max_length'    => 4,
			],
			'wordpress_user_agent' => [
				'friendly_name' => __('HTTP User-Agent', 'wordpress'),
				'description'   => __('User-Agent header sent on read-only REST and Site Health probes.', 'wordpress'),
				'method'        => 'textbox',
				'default'       => 'Cacti-Plugin-WordPress/0.1.0',
				'max_length'    => 128,
			],
			'wordpress_header_thresholds' => [
				'friendly_name' => __('Fleet Health & Thold Thresholds', 'wordpress'),
				'method'        => 'spacer',
			],
			'wordpress_default_apdex_t_ms' => [
				'friendly_name' => __('Default Apdex T (ms)', 'wordpress'),
				'description'   => __('Satisfied TTFB threshold T in milliseconds (tolerating threshold is 4T).', 'wordpress'),
				'method'        => 'textbox',
				'default'       => '500',
				'max_length'    => 6,
			],
			'wordpress_autoload_warn_bytes' => [
				'friendly_name' => __('Autoload Bloat Warning (bytes)', 'wordpress'),
				'description'   => __('wp_options autoloaded size warning threshold (default 819200 / 800 KiB).', 'wordpress'),
				'method'        => 'textbox',
				'default'       => (string) self::DEFAULT_AUTOLOAD_WARN_BYTES,
				'max_length'    => 10,
			],
			'wordpress_autoload_crit_bytes' => [
				'friendly_name' => __('Autoload Bloat Critical (bytes)', 'wordpress'),
				'description'   => __('wp_options autoloaded size critical threshold (default 2097152 / 2 MiB).', 'wordpress'),
				'method'        => 'textbox',
				'default'       => (string) self::DEFAULT_AUTOLOAD_CRIT_BYTES,
				'max_length'    => 10,
			],
			'wordpress_cron_lag_warn_sec' => [
				'friendly_name' => __('WP-Cron Lag Warning (seconds)', 'wordpress'),
				'description'   => __('Oldest overdue WP-Cron job lag threshold for degraded status.', 'wordpress'),
				'method'        => 'textbox',
				'default'       => '900',
				'max_length'    => 6,
			],
			'wordpress_tls_warn_days' => [
				'friendly_name' => __('TLS Expiry Warning (days)', 'wordpress'),
				'description'   => __('Days before TLS certificate expiry triggering degraded status.', 'wordpress'),
				'method'        => 'textbox',
				'default'       => '30',
				'max_length'    => 4,
			],
			'wordpress_tls_crit_days' => [
				'friendly_name' => __('TLS Expiry Critical (days)', 'wordpress'),
				'description'   => __('Days before TLS certificate expiry triggering critical status.', 'wordpress'),
				'method'        => 'textbox',
				'default'       => '7',
				'max_length'    => 3,
			],
			'wordpress_uninstall_keep_tables' => [
				'friendly_name' => __('Keep Tables on Uninstall', 'wordpress'),
				'description'   => __('Preserve plugin_wordpress database tables when uninstalling the plugin.', 'wordpress'),
				'method'        => 'checkbox',
				'default'       => '',
			],
		];
	}

	/**
	 * Coerce a mixed input into a bounded integer with fallback.
	 *
	 * @param mixed $raw Raw value.
	 * @param int $min Minimum allowed value.
	 * @param int $max Maximum allowed value.
	 * @param int $default Fallback value when input is empty or non-numeric.
	 * @return int
	 */
	private static function clampInt(mixed $raw, int $min, int $max, int $default): int {
		if (!is_numeric($raw)) {
			return $default;
		}

		$val = (int) $raw;

		return max($min, min($max, $val));
	}

	/**
	 * Coerce a mixed input into a trimmed string.
	 *
	 * @param mixed $raw Raw value.
	 * @param string $default Fallback value.
	 * @return string
	 */
	private static function stringVal(mixed $raw, string $default): string {
		if (!is_scalar($raw)) {
			return $default;
		}

		return trim((string) $raw);
	}

	/**
	 * Coerce Cacti checkbox or boolean config values into a strict bool.
	 *
	 * @param mixed $raw Raw value.
	 * @return bool
	 */
	private static function boolVal(mixed $raw): bool {
		if (is_bool($raw)) {
			return $raw;
		}

		if (is_int($raw)) {
			return $raw !== 0;
		}

		if (is_string($raw)) {
			return in_array(strtolower(trim($raw)), ['on', '1', 'true', 'yes'], true);
		}

		return false;
	}

	/**
	 * Split a comma-separated string into non-empty lowercase tokens.
	 *
	 * @param string $csv Comma-separated values.
	 * @return list<string>
	 */
	private static function splitCsv(string $csv): array {
		if (trim($csv) === '') {
			return [];
		}

		$items = [];

		foreach (explode(',', $csv) as $part) {
			$trimmed = strtolower(trim($part));

			if ($trimmed !== '') {
				$items[] = $trimmed;
			}
		}

		return $items;
	}
}
