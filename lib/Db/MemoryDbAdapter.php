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

namespace Somethingwithproof\WordPress\Db;

/**
 * In-memory SQLite-backed DbAdapter for fast, realistic unit testing of SQL
 * repositories without requiring a live MariaDB server.
 */
final class MemoryDbAdapter implements DbAdapter {
	/**
	 * Underlying PDO SQLite handle.
	 */
	private \PDO $pdo;

	/**
	 * Construct an isolated in-memory SQLite adapter with the plugin_wordpress schema.
	 */
	public function __construct() {
		$this->pdo = new \PDO('sqlite::memory:');
		$this->pdo->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
		$this->initializeSchema();
	}

	/**
	 * Execute a write statement with positional bound parameters.
	 *
	 * @param string $sql Parameterized SQL statement.
	 * @param list<bool|float|int|string|null> $params Positional parameters.
	 * @return bool
	 */
	public function execute(string $sql, array $params = []): bool {
		$stmt = $this->pdo->prepare($this->translateSql($sql));

		return $stmt->execute($this->normalizeParams($params));
	}

	/**
	 * Fetch a single scalar cell value or null when no row matches.
	 *
	 * @param string $sql Parameterized SQL query.
	 * @param list<bool|float|int|string|null> $params Positional parameters.
	 * @return mixed
	 */
	public function fetchCell(string $sql, array $params = []): mixed {
		$stmt = $this->pdo->prepare($this->translateSql($sql));
		$stmt->execute($this->normalizeParams($params));
		$value = $stmt->fetchColumn(0);

		return $value === false ? null : $value;
	}

	/**
	 * Fetch a single associative row or null when no row matches.
	 *
	 * @param string $sql Parameterized SQL query.
	 * @param list<bool|float|int|string|null> $params Positional parameters.
	 * @return array<string, mixed>|null
	 */
	public function fetchRow(string $sql, array $params = []): ?array {
		$stmt = $this->pdo->prepare($this->translateSql($sql));
		$stmt->execute($this->normalizeParams($params));
		$row = $stmt->fetch(\PDO::FETCH_ASSOC);

		if (!is_array($row)) {
			return null;
		}

		/** @var array<string, mixed> $typed */
		$typed = $row;

		return $typed;
	}

	/**
	 * Fetch all matching associative rows.
	 *
	 * @param string $sql Parameterized SQL query.
	 * @param list<bool|float|int|string|null> $params Positional parameters.
	 * @return list<array<string, mixed>>
	 */
	public function fetchAssoc(string $sql, array $params = []): array {
		$stmt = $this->pdo->prepare($this->translateSql($sql));
		$stmt->execute($this->normalizeParams($params));
		$rows = $stmt->fetchAll(\PDO::FETCH_ASSOC);

		$result = [];

		foreach ($rows as $row) {
			if (is_array($row)) {
				/** @var array<string, mixed> $typed */
				$typed    = $row;
				$result[] = $typed;
			}
		}

		return $result;
	}

	/**
	 * Create the four plugin_wordpress tables in the in-memory SQLite instance.
	 *
	 * @return void
	 */
	private function initializeSchema(): void {
		$this->pdo->exec(
			'CREATE TABLE plugin_wordpress_sites (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				slug TEXT NOT NULL UNIQUE,
				name TEXT NOT NULL DEFAULT \'\',
				base_url TEXT NOT NULL DEFAULT \'\',
				username TEXT NOT NULL DEFAULT \'\',
				telemetry_path TEXT NOT NULL DEFAULT \'/wp-json/cacti-wp/v1/telemetry\',
				poller_id INTEGER NOT NULL DEFAULT 1,
				enabled INTEGER NOT NULL DEFAULT 1,
				verify_tls INTEGER NOT NULL DEFAULT 1,
				allow_private_ip INTEGER NOT NULL DEFAULT 0,
				timeout_connect INTEGER NOT NULL DEFAULT 5,
				timeout_read INTEGER NOT NULL DEFAULT 10,
				apdex_t_ms INTEGER NOT NULL DEFAULT 500,
				created_at INTEGER NOT NULL DEFAULT 0,
				updated_at INTEGER NOT NULL DEFAULT 0
			)'
		);

		$this->pdo->exec(
			'CREATE TABLE plugin_wordpress_secrets (
				site_slug TEXT PRIMARY KEY,
				ciphertext TEXT NOT NULL,
				key_fingerprint TEXT NOT NULL DEFAULT \'\',
				updated_at INTEGER NOT NULL DEFAULT 0
			)'
		);

		$this->pdo->exec(
			'CREATE TABLE plugin_wordpress_snapshots (
				site_slug TEXT PRIMARY KEY,
				poller_id INTEGER NOT NULL DEFAULT 1,
				status TEXT NOT NULL DEFAULT \'unreachable\',
				wp_version TEXT NOT NULL DEFAULT \'\',
				site_name TEXT NOT NULL DEFAULT \'\',
				ttfb_ms REAL NOT NULL DEFAULT 0,
				ttfb_p95_ms REAL NOT NULL DEFAULT 0,
				apdex_score REAL NOT NULL DEFAULT 0,
				health_good INTEGER NOT NULL DEFAULT 0,
				health_recommended INTEGER NOT NULL DEFAULT 0,
				health_critical INTEGER NOT NULL DEFAULT 0,
				plugins_active INTEGER NOT NULL DEFAULT 0,
				plugins_inactive INTEGER NOT NULL DEFAULT 0,
				plugins_updates INTEGER NOT NULL DEFAULT 0,
				themes_active INTEGER NOT NULL DEFAULT 0,
				themes_updates INTEGER NOT NULL DEFAULT 0,
				cron_overdue INTEGER NOT NULL DEFAULT 0,
				cron_oldest_lag_sec INTEGER NOT NULL DEFAULT 0,
				autoload_bytes INTEGER NOT NULL DEFAULT 0,
				autoload_rows INTEGER NOT NULL DEFAULT 0,
				object_cache_hit_ratio REAL NULL,
				opcache_hit_ratio REAL NULL,
				opcache_memory_used_pct REAL NULL,
				php_fpm_active INTEGER NULL,
				php_fpm_idle INTEGER NULL,
				php_fpm_queued INTEGER NULL,
				tls_expiry_days INTEGER NULL,
				http_error_rate_pct REAL NOT NULL DEFAULT 0,
				xmlrpc_exposed INTEGER NOT NULL DEFAULT 0,
				rest_users_exposed INTEGER NOT NULL DEFAULT 0,
				details_json TEXT NOT NULL DEFAULT \'{}\',
				last_error TEXT NOT NULL DEFAULT \'\',
				polled_at INTEGER NOT NULL DEFAULT 0
			)'
		);

		$this->pdo->exec(
			'CREATE TABLE plugin_wordpress_poller_state (
				poller_id INTEGER PRIMARY KEY,
				recommended_concurrency INTEGER NOT NULL DEFAULT 2,
				ewma_latency_ms REAL NOT NULL DEFAULT 0,
				standing_delay_ms REAL NOT NULL DEFAULT 0,
				codel_drop_count INTEGER NOT NULL DEFAULT 0,
				last_run_sites INTEGER NOT NULL DEFAULT 0,
				last_run_duration_ms REAL NOT NULL DEFAULT 0,
				updated_at INTEGER NOT NULL DEFAULT 0
			)'
		);
	}

	/**
	 * Normalize SQLite-compatible syntax differences for MariaDB queries.
	 *
	 * @param string $sql Raw SQL query.
	 * @return string
	 */
	private function translateSql(string $sql): string {
		return str_replace('INSERT INTO', 'INSERT INTO', $sql);
	}

	/**
	 * Convert boolean parameters to integers for SQLite PDO binding.
	 *
	 * @param list<bool|float|int|string|null> $params Positional parameters.
	 * @return list<float|int|string|null>
	 */
	private function normalizeParams(array $params): array {
		$out = [];

		foreach ($params as $value) {
			$out[] = is_bool($value) ? ($value ? 1 : 0) : $value;
		}

		return $out;
	}
}
