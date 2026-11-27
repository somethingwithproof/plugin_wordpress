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
 * Plugin schema migrations, hook registration catalog, remote collector replication
 * policy, and uninstall table control for plugin_wordpress.
 */
final class Schema {
	/**
	 * Current database schema version.
	 */
	public const VERSION = 1;

	/**
	 * Cacti plugin hooks registered by plugin_wordpress.
	 */
	public const HOOKS = [
		'auth_alternate_realms'      => 'wordpress_auth_alternate_realms',
		'config_arrays'              => 'wordpress_config_arrays',
		'config_settings'            => 'wordpress_config_settings',
		'draw_navigation_text'       => 'wordpress_draw_navigation_text',
		'poller_bottom'              => 'wordpress_poller_bottom',
		'replicate_out'              => 'wordpress_replicate_out',
		'casc_register_providers'    => 'wordpress_casc_register_providers',
		'doctor_register_checks'     => 'wordpress_doctor_register_checks',
		'doctor_register_debug_info' => 'wordpress_doctor_register_debug_info',
		'abilities_register'         => 'wordpress_abilities_register',
		'api_register_resources'     => 'wordpress_api_register_resources',
	];

	/**
	 * Tables replicated to remote data collectors (strictly non-secret inventory only).
	 */
	public const REPLICATED_TABLES = [
		'plugin_wordpress_sites',
	];

	/**
	 * Tables explicitly excluded from remote collector replication.
	 */
	public const LOCAL_ONLY_TABLES = [
		'plugin_wordpress_secrets',
		'plugin_wordpress_snapshots',
		'plugin_wordpress_poller_state',
	];

	/**
	 * Cacti plugin directory slug.
	 */
	private const PLUGIN = 'wordpress';

	/**
	 * Settings table key tracking installed schema version.
	 */
	private const SETTING = 'wordpress_schema_version';

	/**
	 * Construct a Schema manager bound to an optional database connection.
	 *
	 * @param \PDO|false $connection Cacti PDO connection or false for default session.
	 */
	public function __construct(private readonly \PDO|false $connection = false) {
	}

	/**
	 * Read the currently recorded plugin schema version from Cacti's settings table.
	 *
	 * @return int Recorded schema version, or 0 when not installed.
	 */
	public function storedVersion(): int {
		$value = db_fetch_cell_prepared(
			'SELECT value FROM settings WHERE name = ?',
			[self::SETTING],
			'',
			true,
			$this->connection
		);

		return is_numeric($value) ? (int) $value : 0;
	}

	/**
	 * Determine whether the database schema matches Schema::VERSION.
	 *
	 * @return bool
	 */
	public function isCurrent(): bool {
		return $this->storedVersion() === self::VERSION;
	}

	/**
	 * Create or migrate all plugin_wordpress tables idempotently.
	 *
	 * @return bool True when schema is current after migration; false on downgrade or error.
	 */
	public function migrate(): bool {
		$from = $this->storedVersion();

		if ($from > self::VERSION) {
			Log::error(sprintf('Schema version %d is newer than plugin code (%d); refusing downgrade', $from, self::VERSION));

			return false;
		}

		foreach (self::tables() as $table => $definition) {
			api_plugin_db_table_create(self::PLUGIN, $table, $definition);

			if (!$this->tableExists($table)) {
				Log::error(sprintf('Unable to create table %s; schema left at version %d', $table, $from));

				return false;
			}
		}

		db_execute_prepared(
			'REPLACE INTO settings (name, value) VALUES (?, ?)',
			[self::SETTING, (string) self::VERSION],
			true,
			$this->connection
		);

		if ($from !== self::VERSION) {
			Log::info(sprintf('Schema migrated from version %d to %d', $from, self::VERSION));
		}

		return true;
	}

	/**
	 * Read the plugin version currently recorded in Cacti's plugin_config table.
	 *
	 * @return string
	 */
	public function recordedPluginVersion(): string {
		$value = db_fetch_cell_prepared(
			'SELECT version FROM plugin_config WHERE directory = ?',
			[self::PLUGIN],
			'',
			true,
			$this->connection
		);

		return is_scalar($value) ? (string) $value : '';
	}

	/**
	 * Persist plugin metadata into Cacti's plugin_config row.
	 *
	 * @param string $version Plugin version string from INFO.
	 * @param string $author Plugin author string from INFO.
	 * @param string $homepage Plugin homepage URL from INFO.
	 * @return void
	 */
	public function recordPluginVersion(string $version, string $author, string $homepage): void {
		db_execute_prepared(
			'UPDATE plugin_config SET version = ?, author = ?, webpage = ? WHERE directory = ?',
			[$version, $author, $homepage, self::PLUGIN],
			true,
			$this->connection
		);
	}

	/**
	 * Determine whether plugin_wordpress is currently enabled in plugin_config.
	 *
	 * @return bool
	 */
	public function pluginEnabled(): bool {
		$status = db_fetch_cell_prepared(
			'SELECT status FROM plugin_config WHERE directory = ?',
			[self::PLUGIN],
			'',
			true,
			$this->connection
		);

		return is_numeric($status) && (int) $status === 1;
	}

	/**
	 * Verify that all declared plugin hooks and RBAC realms are registered.
	 *
	 * @return bool
	 */
	public function hooksRegistered(): bool {
		$placeholders = implode(', ', array_fill(0, count(self::HOOKS), '?'));
		$hooks        = db_fetch_cell_prepared(
			"SELECT COUNT(DISTINCT hook) FROM plugin_hooks WHERE name = ? AND hook IN ($placeholders)",
			array_merge([self::PLUGIN], array_keys(self::HOOKS)),
			'',
			true,
			$this->connection
		);
		$realms = db_fetch_cell_prepared(
			'SELECT COUNT(*) FROM plugin_realms WHERE plugin = ?',
			[self::PLUGIN],
			'',
			true,
			$this->connection
		);

		return is_numeric($hooks)
			&& (int) $hooks === count(self::HOOKS)
			&& is_numeric($realms)
			&& (int) $realms === count(Pages::realms());
	}

	/**
	 * Detach plugin tables from plugin_db_changes so Cacti uninstall preserves them.
	 *
	 * @return void
	 */
	public function untrackTables(): void {
		db_execute_prepared(
			"DELETE FROM plugin_db_changes WHERE plugin = ? AND method = 'create'",
			[self::PLUGIN],
			true,
			$this->connection
		);
	}

	/**
	 * Remove the recorded schema version setting during uninstall.
	 *
	 * @return void
	 */
	public function forgetVersion(): void {
		db_execute_prepared(
			'DELETE FROM settings WHERE name = ?',
			[self::SETTING],
			true,
			$this->connection
		);
	}

	/**
	 * Check whether a plugin table exists in the active MariaDB schema.
	 *
	 * @param string $table Unquoted table name.
	 * @return bool
	 */
	private function tableExists(string $table): bool {
		/** @var mixed $count */
		$count = db_fetch_cell_prepared(
			'SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ?',
			[$table],
			'',
			true,
			$this->connection
		);

		return is_numeric($count) && (int) $count > 0;
	}

	/**
	 * Return Cacti api_plugin_db_table_create() definitions for all plugin_wordpress tables.
	 *
	 * @return array<string, array<string, mixed>>
	 */
	public static function tables(): array {
		return [
			'plugin_wordpress_sites' => [
				'columns' => [
					['name' => 'id', 'type' => 'bigint(20)', 'unsigned' => true, 'NULL' => false, 'auto_increment' => true],
					['name' => 'slug', 'type' => 'varchar(64)', 'NULL' => false, 'default' => ''],
					['name' => 'name', 'type' => 'varchar(128)', 'NULL' => false, 'default' => ''],
					['name' => 'base_url', 'type' => 'varchar(255)', 'NULL' => false, 'default' => ''],
					['name' => 'username', 'type' => 'varchar(128)', 'NULL' => false, 'default' => ''],
					['name' => 'telemetry_path', 'type' => 'varchar(255)', 'NULL' => false, 'default' => '/wp-json/cacti-wp/v1/telemetry'],
					['name' => 'poller_id', 'type' => 'int(10)', 'unsigned' => true, 'NULL' => false, 'default' => '1'],
					['name' => 'enabled', 'type' => 'tinyint(1)', 'unsigned' => true, 'NULL' => false, 'default' => '1'],
					['name' => 'verify_tls', 'type' => 'tinyint(1)', 'unsigned' => true, 'NULL' => false, 'default' => '1'],
					['name' => 'allow_private_ip', 'type' => 'tinyint(1)', 'unsigned' => true, 'NULL' => false, 'default' => '0'],
					['name' => 'timeout_connect', 'type' => 'int(10)', 'unsigned' => true, 'NULL' => false, 'default' => '5'],
					['name' => 'timeout_read', 'type' => 'int(10)', 'unsigned' => true, 'NULL' => false, 'default' => '10'],
					['name' => 'apdex_t_ms', 'type' => 'int(10)', 'unsigned' => true, 'NULL' => false, 'default' => '500'],
					['name' => 'created_at', 'type' => 'int(10)', 'unsigned' => true, 'NULL' => false, 'default' => '0'],
					['name' => 'updated_at', 'type' => 'int(10)', 'unsigned' => true, 'NULL' => false, 'default' => '0'],
				],
				'primary'     => 'id',
				'unique_keys' => [
					['name' => 'uniq_wp_slug', 'columns' => 'slug'],
				],
				'keys' => [
					['name' => 'idx_wp_poller_enabled', 'columns' => ['poller_id', 'enabled']],
				],
				'type'    => 'InnoDB',
				'comment' => 'Declarative WordPress fleet site inventory (non-secret; replicated to remote collectors)',
			],
			'plugin_wordpress_secrets' => [
				'columns' => [
					['name' => 'site_slug', 'type' => 'varchar(64)', 'NULL' => false, 'default' => ''],
					['name' => 'ciphertext', 'type' => 'text', 'NULL' => false],
					['name' => 'key_fingerprint', 'type' => 'char(16)', 'NULL' => false, 'default' => ''],
					['name' => 'updated_at', 'type' => 'int(10)', 'unsigned' => true, 'NULL' => false, 'default' => '0'],
				],
				'primary' => 'site_slug',
				'keys'    => [
					['name' => 'idx_wp_secret_updated', 'columns' => 'updated_at'],
				],
				'type'    => 'InnoDB',
				'comment' => 'AES-256-GCM encrypted Application Passwords (local-only, never replicated or exported)',
			],
			'plugin_wordpress_snapshots' => [
				'columns' => [
					['name' => 'site_slug', 'type' => 'varchar(64)', 'NULL' => false, 'default' => ''],
					['name' => 'poller_id', 'type' => 'int(10)', 'unsigned' => true, 'NULL' => false, 'default' => '1'],
					['name' => 'status', 'type' => 'varchar(16)', 'NULL' => false, 'default' => 'unreachable'],
					['name' => 'wp_version', 'type' => 'varchar(32)', 'NULL' => false, 'default' => ''],
					['name' => 'site_name', 'type' => 'varchar(191)', 'NULL' => false, 'default' => ''],
					['name' => 'ttfb_ms', 'type' => 'double', 'NULL' => false, 'default' => '0'],
					['name' => 'ttfb_p95_ms', 'type' => 'double', 'NULL' => false, 'default' => '0'],
					['name' => 'apdex_score', 'type' => 'double', 'NULL' => false, 'default' => '0'],
					['name' => 'health_good', 'type' => 'int(10)', 'unsigned' => true, 'NULL' => false, 'default' => '0'],
					['name' => 'health_recommended', 'type' => 'int(10)', 'unsigned' => true, 'NULL' => false, 'default' => '0'],
					['name' => 'health_critical', 'type' => 'int(10)', 'unsigned' => true, 'NULL' => false, 'default' => '0'],
					['name' => 'plugins_active', 'type' => 'int(10)', 'unsigned' => true, 'NULL' => false, 'default' => '0'],
					['name' => 'plugins_inactive', 'type' => 'int(10)', 'unsigned' => true, 'NULL' => false, 'default' => '0'],
					['name' => 'plugins_updates', 'type' => 'int(10)', 'unsigned' => true, 'NULL' => false, 'default' => '0'],
					['name' => 'themes_active', 'type' => 'int(10)', 'unsigned' => true, 'NULL' => false, 'default' => '0'],
					['name' => 'themes_updates', 'type' => 'int(10)', 'unsigned' => true, 'NULL' => false, 'default' => '0'],
					['name' => 'cron_overdue', 'type' => 'int(10)', 'unsigned' => true, 'NULL' => false, 'default' => '0'],
					['name' => 'cron_oldest_lag_sec', 'type' => 'int(10)', 'unsigned' => true, 'NULL' => false, 'default' => '0'],
					['name' => 'autoload_bytes', 'type' => 'bigint(20)', 'unsigned' => true, 'NULL' => false, 'default' => '0'],
					['name' => 'autoload_rows', 'type' => 'int(10)', 'unsigned' => true, 'NULL' => false, 'default' => '0'],
					['name' => 'object_cache_hit_ratio', 'type' => 'double', 'NULL' => true],
					['name' => 'opcache_hit_ratio', 'type' => 'double', 'NULL' => true],
					['name' => 'opcache_memory_used_pct', 'type' => 'double', 'NULL' => true],
					['name' => 'php_fpm_active', 'type' => 'int(10)', 'unsigned' => true, 'NULL' => true],
					['name' => 'php_fpm_idle', 'type' => 'int(10)', 'unsigned' => true, 'NULL' => true],
					['name' => 'php_fpm_queued', 'type' => 'int(10)', 'unsigned' => true, 'NULL' => true],
					['name' => 'tls_expiry_days', 'type' => 'int(10)', 'NULL' => true],
					['name' => 'http_error_rate_pct', 'type' => 'double', 'NULL' => false, 'default' => '0'],
					['name' => 'xmlrpc_exposed', 'type' => 'tinyint(1)', 'unsigned' => true, 'NULL' => false, 'default' => '0'],
					['name' => 'rest_users_exposed', 'type' => 'tinyint(1)', 'unsigned' => true, 'NULL' => false, 'default' => '0'],
					['name' => 'details_json', 'type' => 'mediumtext', 'NULL' => false],
					['name' => 'last_error', 'type' => 'varchar(512)', 'NULL' => false, 'default' => ''],
					['name' => 'polled_at', 'type' => 'int(10)', 'unsigned' => true, 'NULL' => false, 'default' => '0'],
				],
				'primary' => 'site_slug',
				'keys'    => [
					['name' => 'idx_wp_snap_poller_status', 'columns' => ['poller_id', 'status']],
					['name' => 'idx_wp_snap_polled', 'columns' => 'polled_at'],
				],
				'type'    => 'InnoDB',
				'comment' => 'Latest WordPress fleet telemetry snapshots (State, never exported)',
			],
			'plugin_wordpress_poller_state' => [
				'columns' => [
					['name' => 'poller_id', 'type' => 'int(10)', 'unsigned' => true, 'NULL' => false, 'default' => '1'],
					['name' => 'recommended_concurrency', 'type' => 'int(10)', 'unsigned' => true, 'NULL' => false, 'default' => '2'],
					['name' => 'ewma_latency_ms', 'type' => 'double', 'NULL' => false, 'default' => '0'],
					['name' => 'standing_delay_ms', 'type' => 'double', 'NULL' => false, 'default' => '0'],
					['name' => 'codel_drop_count', 'type' => 'int(10)', 'unsigned' => true, 'NULL' => false, 'default' => '0'],
					['name' => 'last_run_sites', 'type' => 'int(10)', 'unsigned' => true, 'NULL' => false, 'default' => '0'],
					['name' => 'last_run_duration_ms', 'type' => 'double', 'NULL' => false, 'default' => '0'],
					['name' => 'updated_at', 'type' => 'int(10)', 'unsigned' => true, 'NULL' => false, 'default' => '0'],
				],
				'primary' => 'poller_id',
				'type'    => 'InnoDB',
				'comment' => 'Adaptive Little\'s Law and CoDel concurrency state per poller',
			],
		];
	}
}
