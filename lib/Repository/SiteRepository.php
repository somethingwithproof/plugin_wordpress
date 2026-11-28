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

namespace Somethingwithproof\WordPress\Repository;

use Somethingwithproof\WordPress\Config\ConfigSchema;
use Somethingwithproof\WordPress\Db\DbAdapter;
use Somethingwithproof\WordPress\Metrics\SiteMetrics;
use Somethingwithproof\WordPress\Security\SecretVault;

/**
 * Data access repository for WordPress site inventory, latest telemetry snapshots,
 * adaptive poller state, and non-secret remote collector replication exports.
 */
final class SiteRepository {
	/**
	 * Construct a SiteRepository backed by a DbAdapter.
	 *
	 * @param DbAdapter $db Database adapter.
	 */
	public function __construct(private readonly DbAdapter $db) {
	}

	/**
	 * List all configured WordPress sites, optionally filtered by poller ID and enabled flag.
	 *
	 * @param int|null $pollerId Optional Cacti poller ID filter (> 0).
	 * @param bool $onlyEnabled When true, return only enabled sites.
	 * @return list<array{
	 *   id: int,
	 *   slug: string,
	 *   name: string,
	 *   base_url: string,
	 *   username: string,
	 *   telemetry_path: string,
	 *   poller_id: int,
	 *   enabled: bool,
	 *   verify_tls: bool,
	 *   allow_private_ip: bool,
	 *   timeout_connect: int,
	 *   timeout_read: int,
	 *   apdex_t_ms: int,
	 *   created_at: int,
	 *   updated_at: int
	 * }>
	 */
	public function listSites(?int $pollerId = null, bool $onlyEnabled = false): array {
		$conditions = [];
		$params     = [];

		if ($pollerId !== null && $pollerId > 0) {
			$conditions[] = 'poller_id = ?';
			$params[]     = $pollerId;
		}

		if ($onlyEnabled) {
			$conditions[] = 'enabled = 1';
		}

		$sql = 'SELECT id, slug, name, base_url, username, telemetry_path, poller_id, enabled, verify_tls, allow_private_ip, timeout_connect, timeout_read, apdex_t_ms, created_at, updated_at FROM plugin_wordpress_sites';

		if ($conditions !== []) {
			$sql .= ' WHERE ' . implode(' AND ', $conditions);
		}

		$sql .= ' ORDER BY slug ASC';

		return array_map([self::class, 'normalizeSiteRow'], $this->db->fetchAssoc($sql, $params));
	}

	/**
	 * Fetch a single WordPress site configuration record by slug.
	 *
	 * @param string $slug Unique site slug.
	 * @return array{
	 *   id: int,
	 *   slug: string,
	 *   name: string,
	 *   base_url: string,
	 *   username: string,
	 *   telemetry_path: string,
	 *   poller_id: int,
	 *   enabled: bool,
	 *   verify_tls: bool,
	 *   allow_private_ip: bool,
	 *   timeout_connect: int,
	 *   timeout_read: int,
	 *   apdex_t_ms: int,
	 *   created_at: int,
	 *   updated_at: int
	 * }|null
	 */
	public function findSite(string $slug): ?array {
		$row = $this->db->fetchRow(
			'SELECT id, slug, name, base_url, username, telemetry_path, poller_id, enabled, verify_tls, allow_private_ip, timeout_connect, timeout_read, apdex_t_ms, created_at, updated_at FROM plugin_wordpress_sites WHERE slug = ?',
			[$slug]
		);

		return $row !== null ? self::normalizeSiteRow($row) : null;
	}

	/**
	 * Insert or update a validated WordPress site record (non-secret fields only).
	 *
	 * @param array<string, mixed> $site Validated site fields.
	 * @return bool
	 * @throws \InvalidArgumentException When schema validation fails.
	 */
	public function upsertSite(array $site): bool {
		$errors = ConfigSchema::validateSite($site);

		if ($errors !== []) {
			throw new \InvalidArgumentException(implode(' ', $errors));
		}

		$slug          = is_string($site['slug'] ?? null) ? $site['slug'] : '';
		$name          = is_string($site['name'] ?? null) ? trim($site['name']) : '';
		$baseUrl       = is_string($site['base_url'] ?? null) ? rtrim(trim($site['base_url']), '/') : '';
		$username      = is_string($site['username'] ?? null) ? trim($site['username']) : '';
		$telemetryPath = is_string($site['telemetry_path'] ?? null) ? trim($site['telemetry_path']) : '/wp-json/cacti-wp/v1/telemetry';
		$pollerId      = is_numeric($site['poller_id'] ?? null) ? max(1, (int) $site['poller_id']) : 1;
		$enabled       = array_key_exists('enabled', $site) ? ((bool) $site['enabled'] ? 1 : 0) : 1;
		$verifyTls     = array_key_exists('verify_tls', $site) ? ((bool) $site['verify_tls'] ? 1 : 0) : 1;
		$allowPrivate  = array_key_exists('allow_private_ip', $site) ? ((bool) $site['allow_private_ip'] ? 1 : 0) : 0;
		$timeoutConn   = is_numeric($site['timeout_connect'] ?? null) ? max(1, min(15, (int) $site['timeout_connect'])) : 5;
		$timeoutRead   = is_numeric($site['timeout_read'] ?? null) ? max(1, min(60, (int) $site['timeout_read'])) : 10;
		$apdexTMs      = is_numeric($site['apdex_t_ms'] ?? null) ? max(50, min(10000, (int) $site['apdex_t_ms'])) : 500;
		$now           = time();

		$existing = $this->findSite($slug);

		if ($existing !== null) {
			return $this->db->execute(
				'UPDATE plugin_wordpress_sites SET name = ?, base_url = ?, username = ?, telemetry_path = ?, poller_id = ?, enabled = ?, verify_tls = ?, allow_private_ip = ?, timeout_connect = ?, timeout_read = ?, apdex_t_ms = ?, updated_at = ? WHERE slug = ?',
				[$name, $baseUrl, $username, $telemetryPath, $pollerId, $enabled, $verifyTls, $allowPrivate, $timeoutConn, $timeoutRead, $apdexTMs, $now, $slug]
			);
		}

		return $this->db->execute(
			'INSERT INTO plugin_wordpress_sites (slug, name, base_url, username, telemetry_path, poller_id, enabled, verify_tls, allow_private_ip, timeout_connect, timeout_read, apdex_t_ms, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
			[$slug, $name, $baseUrl, $username, $telemetryPath, $pollerId, $enabled, $verifyTls, $allowPrivate, $timeoutConn, $timeoutRead, $apdexTMs, $now, $now]
		);
	}

	/**
	 * Delete a WordPress site record along with its latest snapshot (vault secret deleted separately).
	 *
	 * @param string $slug Unique site slug.
	 * @return bool
	 */
	public function deleteSite(string $slug): bool {
		$this->db->execute('DELETE FROM plugin_wordpress_snapshots WHERE site_slug = ?', [$slug]);

		return $this->db->execute('DELETE FROM plugin_wordpress_sites WHERE slug = ?', [$slug]);
	}

	/**
	 * Persist a polled SiteMetrics snapshot into plugin_wordpress_snapshots.
	 *
	 * @param SiteMetrics $metrics Computed site telemetry snapshot.
	 * @return bool
	 */
	public function saveSnapshot(SiteMetrics $metrics): bool {
		$detailsJson = json_encode($metrics->details, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

		if (!is_string($detailsJson)) {
			$detailsJson = '{}';
		}

		return $this->db->execute(
			'REPLACE INTO plugin_wordpress_snapshots (
				site_slug, poller_id, status, wp_version, site_name,
				ttfb_ms, ttfb_p95_ms, apdex_score,
				health_good, health_recommended, health_critical,
				plugins_active, plugins_inactive, plugins_updates,
				themes_active, themes_updates,
				cron_overdue, cron_oldest_lag_sec,
				autoload_bytes, autoload_rows,
				object_cache_hit_ratio, opcache_hit_ratio, opcache_memory_used_pct,
				php_fpm_active, php_fpm_idle, php_fpm_queued,
				tls_expiry_days, http_error_rate_pct,
				xmlrpc_exposed, rest_users_exposed,
				details_json, last_error, polled_at
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
			[
				$metrics->slug,
				$metrics->pollerId,
				$metrics->status,
				$metrics->wpVersion,
				$metrics->siteName,
				$metrics->ttfbMs,
				$metrics->ttfbP95Ms,
				$metrics->apdexScore,
				$metrics->siteHealthGood,
				$metrics->siteHealthRecommended,
				$metrics->siteHealthCritical,
				$metrics->pluginsActive,
				$metrics->pluginsInactive,
				$metrics->pluginsUpdatesPending,
				$metrics->themesActive,
				$metrics->themesUpdatesPending,
				$metrics->cronOverdueCount,
				$metrics->cronOldestLagSeconds,
				$metrics->autoloadBytes,
				$metrics->autoloadRows,
				$metrics->objectCacheHitRatio,
				$metrics->opcacheHitRatio,
				$metrics->opcacheMemoryUsedPct,
				$metrics->phpFpmActive,
				$metrics->phpFpmIdle,
				$metrics->phpFpmQueued,
				$metrics->tlsExpiryDays,
				$metrics->httpErrorRatePct,
				$metrics->xmlrpcExposed ? 1 : 0,
				$metrics->restUsersExposed ? 1 : 0,
				$detailsJson,
				substr($metrics->lastError, 0, 512),
				$metrics->polledAt,
			]
		);
	}

	/**
	 * Load latest SiteMetrics snapshots across the fleet or for a specific poller ID.
	 *
	 * @param int|null $pollerId Optional Cacti poller ID filter (> 0).
	 * @return list<SiteMetrics>
	 */
	public function loadSnapshots(?int $pollerId = null): array {
		$params = [];
		$sql    = 'SELECT s.*, i.base_url, i.apdex_t_ms FROM plugin_wordpress_snapshots AS s LEFT JOIN plugin_wordpress_sites AS i ON i.slug = s.site_slug';

		if ($pollerId !== null && $pollerId > 0) {
			$sql     .= ' WHERE s.poller_id = ?';
			$params[] = $pollerId;
		}

		$sql .= ' ORDER BY s.site_slug ASC';

		$snapshots = [];

		foreach ($this->db->fetchAssoc($sql, $params) as $row) {
			$snapshots[] = SiteMetrics::fromDbRow($row);
		}

		return $snapshots;
	}

	/**
	 * Fetch a single SiteMetrics snapshot by site slug.
	 *
	 * @param string $slug Unique site slug.
	 * @return SiteMetrics|null
	 */
	public function findSnapshot(string $slug): ?SiteMetrics {
		$row = $this->db->fetchRow(
			'SELECT s.*, i.base_url, i.apdex_t_ms FROM plugin_wordpress_snapshots AS s LEFT JOIN plugin_wordpress_sites AS i ON i.slug = s.site_slug WHERE s.site_slug = ?',
			[$slug]
		);

		return $row !== null ? SiteMetrics::fromDbRow($row) : null;
	}

	/**
	 * Read persisted adaptive poller sizing state for a given poller ID.
	 *
	 * @param int $pollerId Cacti poller ID.
	 * @return array{recommendedConcurrency: int, ewmaLatencyMs: float, standingDelayMs: float, codelDropCount: int, lastRunSites: int, lastRunDurationMs: float, updatedAt: int}
	 */
	public function loadPollerState(int $pollerId): array {
		$row = $this->db->fetchRow(
			'SELECT recommended_concurrency, ewma_latency_ms, standing_delay_ms, codel_drop_count, last_run_sites, last_run_duration_ms, updated_at FROM plugin_wordpress_poller_state WHERE poller_id = ?',
			[$pollerId]
		);

		if ($row === null) {
			return [
				'recommendedConcurrency' => 2,
				'ewmaLatencyMs'          => 0.0,
				'standingDelayMs'        => 0.0,
				'codelDropCount'         => 0,
				'lastRunSites'           => 0,
				'lastRunDurationMs'      => 0.0,
				'updatedAt'              => 0,
			];
		}

		return [
			'recommendedConcurrency' => is_numeric($row['recommended_concurrency'] ?? null) ? (int) $row['recommended_concurrency'] : 2,
			'ewmaLatencyMs'          => is_numeric($row['ewma_latency_ms'] ?? null) ? (float) $row['ewma_latency_ms'] : 0.0,
			'standingDelayMs'        => is_numeric($row['standing_delay_ms'] ?? null) ? (float) $row['standing_delay_ms'] : 0.0,
			'codelDropCount'         => is_numeric($row['codel_drop_count'] ?? null) ? (int) $row['codel_drop_count'] : 0,
			'lastRunSites'           => is_numeric($row['last_run_sites'] ?? null) ? (int) $row['last_run_sites'] : 0,
			'lastRunDurationMs'      => is_numeric($row['last_run_duration_ms'] ?? null) ? (float) $row['last_run_duration_ms'] : 0.0,
			'updatedAt'              => is_numeric($row['updated_at'] ?? null) ? (int) $row['updated_at'] : 0,
		];
	}

	/**
	 * Persist adaptive Little's Law and CoDel state for a poller ID.
	 *
	 * @param int $pollerId Cacti poller ID.
	 * @param int $recommendedConcurrency Computed worker concurrency.
	 * @param float $ewmaLatencyMs Updated EWMA probe latency in ms.
	 * @param float $standingDelayMs Observed standing delay in ms.
	 * @param int $codelDropCount Current CoDel drop counter.
	 * @param int $lastRunSites Number of sites polled.
	 * @param float $lastRunDurationMs Total run wall time in ms.
	 * @return bool
	 */
	public function savePollerState(
		int $pollerId,
		int $recommendedConcurrency,
		float $ewmaLatencyMs,
		float $standingDelayMs,
		int $codelDropCount,
		int $lastRunSites,
		float $lastRunDurationMs,
	): bool {
		return $this->db->execute(
			'REPLACE INTO plugin_wordpress_poller_state (poller_id, recommended_concurrency, ewma_latency_ms, standing_delay_ms, codel_drop_count, last_run_sites, last_run_duration_ms, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
			[$pollerId, $recommendedConcurrency, $ewmaLatencyMs, $standingDelayMs, $codelDropCount, $lastRunSites, $lastRunDurationMs, time()]
		);
	}

	/**
	 * Export declarative site inventory records using symbolic vault:wordpress:<slug> references.
	 *
	 * Never includes encrypted ciphertexts, plaintext Application Passwords, or State snapshots.
	 *
	 * @return list<array<string, bool|int|string>>
	 */
	public function exportSitesConfig(): array {
		$out = [];

		foreach ($this->listSites() as $site) {
			$slug  = (string) $site['slug'];
			$out[] = [
				'slug'             => $slug,
				'name'             => (string) $site['name'],
				'base_url'         => (string) $site['base_url'],
				'username'         => (string) $site['username'],
				'secret_ref'       => SecretVault::referenceFor($slug),
				'telemetry_path'   => (string) $site['telemetry_path'],
				'poller_id'        => (int) $site['poller_id'],
				'enabled'          => (bool) $site['enabled'],
				'verify_tls'       => (bool) $site['verify_tls'],
				'allow_private_ip' => (bool) $site['allow_private_ip'],
				'timeout_connect'  => (int) $site['timeout_connect'],
				'timeout_read'     => (int) $site['timeout_read'],
				'apdex_t_ms'       => (int) $site['apdex_t_ms'],
			];
		}

		return $out;
	}

	/**
	 * Replicate non-secret site rows for a remote poller onto a target remote DbAdapter.
	 *
	 * Explicitly syncs ONLY plugin_wordpress_sites rows for the target poller and NEVER
	 * copies plugin_wordpress_secrets or keyfile data.
	 *
	 * @param DbAdapter $remoteDb Remote collector database adapter.
	 * @param int $pollerId Target remote poller ID.
	 * @return int Number of non-secret site rows replicated.
	 */
	public function replicateSitesToRemote(DbAdapter $remoteDb, int $pollerId): int {
		$rows = $this->listSites($pollerId, false);
		$remoteDb->execute('DELETE FROM plugin_wordpress_sites WHERE poller_id = ?', [$pollerId]);
		$count = 0;

		foreach ($rows as $row) {
			$ok = $remoteDb->execute(
				'REPLACE INTO plugin_wordpress_sites (id, slug, name, base_url, username, telemetry_path, poller_id, enabled, verify_tls, allow_private_ip, timeout_connect, timeout_read, apdex_t_ms, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
				[
					(int) $row['id'],
					(string) $row['slug'],
					(string) $row['name'],
					(string) $row['base_url'],
					(string) $row['username'],
					(string) $row['telemetry_path'],
					(int) $row['poller_id'],
					(bool) $row['enabled'] ? 1 : 0,
					(bool) $row['verify_tls'] ? 1 : 0,
					(bool) $row['allow_private_ip'] ? 1 : 0,
					(int) $row['timeout_connect'],
					(int) $row['timeout_read'],
					(int) $row['apdex_t_ms'],
					(int) $row['created_at'],
					(int) $row['updated_at'],
				]
			);

			if ($ok) {
				$count++;
			}
		}

		return $count;
	}

	/**
	 * Normalize numeric and boolean types on a plugin_wordpress_sites row.
	 *
	 * @param array<string, mixed> $row Raw database row.
	 * @return array{
	 *   id: int,
	 *   slug: string,
	 *   name: string,
	 *   base_url: string,
	 *   username: string,
	 *   telemetry_path: string,
	 *   poller_id: int,
	 *   enabled: bool,
	 *   verify_tls: bool,
	 *   allow_private_ip: bool,
	 *   timeout_connect: int,
	 *   timeout_read: int,
	 *   apdex_t_ms: int,
	 *   created_at: int,
	 *   updated_at: int
	 * }
	 */
	private static function normalizeSiteRow(array $row): array {
		return [
			'id'               => is_numeric($row['id'] ?? null) ? (int) $row['id'] : 0,
			'slug'             => is_string($row['slug'] ?? null) ? $row['slug'] : '',
			'name'             => is_string($row['name'] ?? null) ? $row['name'] : '',
			'base_url'         => is_string($row['base_url'] ?? null) ? $row['base_url'] : '',
			'username'         => is_string($row['username'] ?? null) ? $row['username'] : '',
			'telemetry_path'   => is_string($row['telemetry_path'] ?? null) ? $row['telemetry_path'] : '/wp-json/cacti-wp/v1/telemetry',
			'poller_id'        => is_numeric($row['poller_id'] ?? null) ? (int) $row['poller_id'] : 1,
			'enabled'          => !empty($row['enabled']),
			'verify_tls'       => !isset($row['verify_tls']) || !empty($row['verify_tls']),
			'allow_private_ip' => !empty($row['allow_private_ip']),
			'timeout_connect'  => is_numeric($row['timeout_connect'] ?? null) ? (int) $row['timeout_connect'] : 5,
			'timeout_read'     => is_numeric($row['timeout_read'] ?? null) ? (int) $row['timeout_read'] : 10,
			'apdex_t_ms'       => is_numeric($row['apdex_t_ms'] ?? null) ? (int) $row['apdex_t_ms'] : 500,
			'created_at'       => is_numeric($row['created_at'] ?? null) ? (int) $row['created_at'] : 0,
			'updated_at'       => is_numeric($row['updated_at'] ?? null) ? (int) $row['updated_at'] : 0,
		];
	}
}
