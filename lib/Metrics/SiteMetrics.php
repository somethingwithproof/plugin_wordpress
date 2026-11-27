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

namespace Somethingwithproof\WordPress\Metrics;

use Somethingwithproof\WordPress\Settings;

/**
 * Immutable telemetry and health snapshot for a single WordPress site.
 */
final class SiteMetrics {
	/**
	 * Status constant for healthy sites meeting all SLA and security checks.
	 */
	public const STATUS_HEALTHY = 'healthy';

	/**
	 * Status constant for degraded sites with warning conditions (bloat, cron lag, pending updates, TLS warn).
	 */
	public const STATUS_DEGRADED = 'degraded';

	/**
	 * Status constant for critical sites (Site Health critical, severe bloat, imminent TLS expiry, unreachable).
	 */
	public const STATUS_CRITICAL = 'critical';

	/**
	 * Status constant for unreachable sites that failed discovery or security guards.
	 */
	public const STATUS_UNREACHABLE = 'unreachable';

	/**
	 * Construct a SiteMetrics value object.
	 *
	 * @param string $slug Unique site slug.
	 * @param string $siteName WordPress site display name.
	 * @param string $url Base HTTPS URL.
	 * @param int $pollerId Assigned Cacti poller ID.
	 * @param string $status Computed status (healthy, degraded, critical, unreachable).
	 * @param string $wpVersion Detected WordPress core version.
	 * @param float $ttfbMs Primary TTFB in milliseconds.
	 * @param float $ttfbP95Ms 95th percentile TTFB in milliseconds.
	 * @param int $apdexTMs Apdex satisfied latency threshold T in milliseconds.
	 * @param float $apdexScore Computed per-site Apdex score (0.0 to 1.0).
	 * @param int $siteHealthGood Count of Site Health "good" tests.
	 * @param int $siteHealthRecommended Count of Site Health "recommended" tests.
	 * @param int $siteHealthCritical Count of Site Health "critical" tests.
	 * @param int $pluginsActive Active plugin count.
	 * @param int $pluginsInactive Inactive plugin count.
	 * @param int $pluginsUpdatesPending Pending plugin updates count.
	 * @param int $themesActive Active theme count.
	 * @param int $themesInactive Inactive theme count.
	 * @param int $themesUpdatesPending Pending theme updates count.
	 * @param int $cronOverdueCount Overdue WP-Cron jobs count.
	 * @param int $cronOldestLagSeconds Age in seconds of oldest overdue WP-Cron job.
	 * @param int $autoloadBytes Total wp_options autoloaded bytes.
	 * @param int $autoloadRows Total wp_options autoloaded row count.
	 * @param float|null $objectCacheHitRatio Object cache hit ratio percentage (0..100).
	 * @param float|null $opcacheHitRatio OPcache hit ratio percentage (0..100).
	 * @param float|null $opcacheMemoryUsedPct OPcache memory usage percentage (0..100).
	 * @param int|null $phpFpmActive Active PHP-FPM workers.
	 * @param int|null $phpFpmIdle Idle PHP-FPM workers.
	 * @param int|null $phpFpmQueued Queued PHP-FPM listen requests.
	 * @param int|null $tlsExpiryDays Days until TLS leaf certificate expiry.
	 * @param float $httpErrorRatePct Observed HTTP 4xx/5xx error rate percentage.
	 * @param bool $xmlrpcExposed True when XML-RPC / pingback exposure was detected.
	 * @param bool $restUsersExposed True when /wp/v2/users route is exposed.
	 * @param array<string, mixed> $details Non-secret diagnostic metadata (drift, findings, namespaces).
	 * @param string $lastError Redacted last error string (empty on success).
	 * @param int $polledAt Unix timestamp of observation.
	 */
	public function __construct(
		public readonly string $slug,
		public readonly string $siteName,
		public readonly string $url,
		public readonly int $pollerId,
		public readonly string $status,
		public readonly string $wpVersion,
		public readonly float $ttfbMs,
		public readonly float $ttfbP95Ms,
		public readonly int $apdexTMs,
		public readonly float $apdexScore,
		public readonly int $siteHealthGood,
		public readonly int $siteHealthRecommended,
		public readonly int $siteHealthCritical,
		public readonly int $pluginsActive,
		public readonly int $pluginsInactive,
		public readonly int $pluginsUpdatesPending,
		public readonly int $themesActive,
		public readonly int $themesInactive,
		public readonly int $themesUpdatesPending,
		public readonly int $cronOverdueCount,
		public readonly int $cronOldestLagSeconds,
		public readonly int $autoloadBytes,
		public readonly int $autoloadRows,
		public readonly ?float $objectCacheHitRatio,
		public readonly ?float $opcacheHitRatio,
		public readonly ?float $opcacheMemoryUsedPct,
		public readonly ?int $phpFpmActive,
		public readonly ?int $phpFpmIdle,
		public readonly ?int $phpFpmQueued,
		public readonly ?int $tlsExpiryDays,
		public readonly float $httpErrorRatePct,
		public readonly bool $xmlrpcExposed,
		public readonly bool $restUsersExposed,
		public readonly array $details = [],
		public readonly string $lastError = '',
		public readonly int $polledAt = 0,
	) {
	}

	/**
	 * Build a classified SiteMetrics snapshot from raw probe observations.
	 *
	 * @param array<string, mixed> $obs Raw observation map from WordPressClient.
	 * @param Settings|null $settings Threshold settings used for status classification.
	 * @return self
	 */
	public static function fromObservation(array $obs, ?Settings $settings = null): self {
		$cfg          = $settings ?? new Settings();
		$apdexTMs     = is_numeric($obs['apdexTMs'] ?? null) ? max(50, (int) $obs['apdexTMs']) : $cfg->defaultApdexTMs;
		$ttfbMs       = is_numeric($obs['ttfbMs'] ?? null) ? max(0.0, (float) $obs['ttfbMs']) : 0.0;
		$ttfbP95Ms    = is_numeric($obs['ttfbP95Ms'] ?? null) ? max(0.0, (float) $obs['ttfbP95Ms']) : $ttfbMs;
		$rawSamples   = is_array($obs['ttfbSamples'] ?? null) ? $obs['ttfbSamples'] : [$ttfbMs];
		$floatSamples = [];

		foreach ($rawSamples as $s) {
			if (is_numeric($s)) {
				$floatSamples[] = max(0.0, (float) $s);
			}
		}

		$apdexScore       = self::computeApdex($floatSamples, $apdexTMs);
		$healthCritical   = is_numeric($obs['siteHealthCritical'] ?? null) ? max(0, (int) $obs['siteHealthCritical']) : 0;
		$healthRec        = is_numeric($obs['siteHealthRecommended'] ?? null) ? max(0, (int) $obs['siteHealthRecommended']) : 0;
		$healthGood       = is_numeric($obs['siteHealthGood'] ?? null) ? max(0, (int) $obs['siteHealthGood']) : 0;
		$pluginsUpdates   = is_numeric($obs['pluginsUpdatesPending'] ?? null) ? max(0, (int) $obs['pluginsUpdatesPending']) : 0;
		$themesUpdates    = is_numeric($obs['themesUpdatesPending'] ?? null) ? max(0, (int) $obs['themesUpdatesPending']) : 0;
		$cronOverdue      = is_numeric($obs['cronOverdueCount'] ?? null) ? max(0, (int) $obs['cronOverdueCount']) : 0;
		$cronLag          = is_numeric($obs['cronOldestLagSeconds'] ?? null) ? max(0, (int) $obs['cronOldestLagSeconds']) : 0;
		$autoloadBytes    = is_numeric($obs['autoloadBytes'] ?? null) ? max(0, (int) $obs['autoloadBytes']) : 0;
		$tlsExpiryDays    = is_numeric($obs['tlsExpiryDays'] ?? null) ? (int) $obs['tlsExpiryDays'] : null;
		$httpErrorRatePct = is_numeric($obs['httpErrorRatePct'] ?? null) ? max(0.0, (float) $obs['httpErrorRatePct']) : 0.0;
		$lastError        = is_string($obs['lastError'] ?? null) ? $obs['lastError'] : '';

		$status = self::classifyStatus(
			$healthCritical,
			$healthRec,
			$autoloadBytes,
			$cronOverdue,
			$cronLag,
			$tlsExpiryDays,
			$httpErrorRatePct,
			$apdexScore,
			$pluginsUpdates + $themesUpdates,
			$lastError,
			$cfg
		);

		$details = is_array($obs['details'] ?? null) ? $obs['details'] : [];
		/** @var array<string, mixed> $typedDetails */
		$typedDetails = $details;

		return new self(
			is_string($obs['slug'] ?? null) ? $obs['slug'] : 'unknown',
			is_string($obs['siteName'] ?? null) ? $obs['siteName'] : '',
			is_string($obs['url'] ?? null) ? $obs['url'] : '',
			is_numeric($obs['pollerId'] ?? null) ? max(1, (int) $obs['pollerId']) : 1,
			$status,
			is_string($obs['wpVersion'] ?? null) ? $obs['wpVersion'] : '',
			round($ttfbMs, 2),
			round($ttfbP95Ms, 2),
			$apdexTMs,
			$apdexScore,
			$healthGood,
			$healthRec,
			$healthCritical,
			is_numeric($obs['pluginsActive'] ?? null) ? max(0, (int) $obs['pluginsActive']) : 0,
			is_numeric($obs['pluginsInactive'] ?? null) ? max(0, (int) $obs['pluginsInactive']) : 0,
			$pluginsUpdates,
			is_numeric($obs['themesActive'] ?? null) ? max(0, (int) $obs['themesActive']) : 0,
			is_numeric($obs['themesInactive'] ?? null) ? max(0, (int) $obs['themesInactive']) : 0,
			$themesUpdates,
			$cronOverdue,
			$cronLag,
			$autoloadBytes,
			is_numeric($obs['autoloadRows'] ?? null) ? max(0, (int) $obs['autoloadRows']) : 0,
			is_numeric($obs['objectCacheHitRatio'] ?? null) ? (float) $obs['objectCacheHitRatio'] : null,
			is_numeric($obs['opcacheHitRatio'] ?? null) ? (float) $obs['opcacheHitRatio'] : null,
			is_numeric($obs['opcacheMemoryUsedPct'] ?? null) ? (float) $obs['opcacheMemoryUsedPct'] : null,
			is_numeric($obs['phpFpmActive'] ?? null) ? (int) $obs['phpFpmActive'] : null,
			is_numeric($obs['phpFpmIdle'] ?? null) ? (int) $obs['phpFpmIdle'] : null,
			is_numeric($obs['phpFpmQueued'] ?? null) ? (int) $obs['phpFpmQueued'] : null,
			$tlsExpiryDays,
			round($httpErrorRatePct, 2),
			!empty($obs['xmlrpcExposed']),
			!empty($obs['restUsersExposed']),
			$typedDetails,
			$lastError,
			is_numeric($obs['polledAt'] ?? null) ? (int) $obs['polledAt'] : time(),
		);
	}

	/**
	 * Build an unreachable SiteMetrics snapshot when discovery or security validation fails.
	 *
	 * @param string $slug Site slug.
	 * @param string $siteName Site display name.
	 * @param string $url Base URL.
	 * @param int $pollerId Poller ID.
	 * @param string $error Redacted failure description.
	 * @param int $polledAt Unix timestamp.
	 * @param int $apdexTMs Configured Apdex T threshold in ms.
	 * @param float $ttfbMs Optional measured TTFB before error response.
	 * @param int|null $tlsExpiryDays Optional TLS expiry days if handshake succeeded.
	 * @return self
	 */
	public static function unreachable(
		string $slug,
		string $siteName,
		string $url,
		int $pollerId,
		string $error,
		int $polledAt,
		int $apdexTMs = 500,
		float $ttfbMs = 0.0,
		?int $tlsExpiryDays = null,
	): self {
		return new self(
			$slug,
			$siteName,
			$url,
			$pollerId,
			self::STATUS_UNREACHABLE,
			'',
			round($ttfbMs, 2),
			round($ttfbMs, 2),
			$apdexTMs,
			0.0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			0,
			null,
			null,
			null,
			null,
			null,
			null,
			$tlsExpiryDays,
			100.0,
			false,
			false,
			[],
			$error,
			$polledAt,
		);
	}

	/**
	 * Hydrate a SiteMetrics value object from a plugin_wordpress_snapshots database row.
	 *
	 * @param array<string, mixed> $row Database snapshot row joined with optional site fields.
	 * @return self
	 */
	public static function fromDbRow(array $row): self {
		$detailsRaw = is_string($row['details_json'] ?? null) ? $row['details_json'] : '{}';
		$decoded    = json_decode($detailsRaw, true);
		/** @var array<string, mixed> $details */
		$details = is_array($decoded) ? $decoded : [];

		return new self(
			is_string($row['site_slug'] ?? null) ? $row['site_slug'] : '',
			is_string($row['site_name'] ?? null) ? $row['site_name'] : '',
			is_string($row['base_url'] ?? null) ? $row['base_url'] : '',
			is_numeric($row['poller_id'] ?? null) ? (int) $row['poller_id'] : 1,
			is_string($row['status'] ?? null) ? $row['status'] : self::STATUS_UNREACHABLE,
			is_string($row['wp_version'] ?? null) ? $row['wp_version'] : '',
			is_numeric($row['ttfb_ms'] ?? null) ? (float) $row['ttfb_ms'] : 0.0,
			is_numeric($row['ttfb_p95_ms'] ?? null) ? (float) $row['ttfb_p95_ms'] : 0.0,
			is_numeric($row['apdex_t_ms'] ?? null) ? (int) $row['apdex_t_ms'] : 500,
			is_numeric($row['apdex_score'] ?? null) ? (float) $row['apdex_score'] : 0.0,
			is_numeric($row['health_good'] ?? null) ? (int) $row['health_good'] : 0,
			is_numeric($row['health_recommended'] ?? null) ? (int) $row['health_recommended'] : 0,
			is_numeric($row['health_critical'] ?? null) ? (int) $row['health_critical'] : 0,
			is_numeric($row['plugins_active'] ?? null) ? (int) $row['plugins_active'] : 0,
			is_numeric($row['plugins_inactive'] ?? null) ? (int) $row['plugins_inactive'] : 0,
			is_numeric($row['plugins_updates'] ?? null) ? (int) $row['plugins_updates'] : 0,
			is_numeric($row['themes_active'] ?? null) ? (int) $row['themes_active'] : 0,
			0,
			is_numeric($row['themes_updates'] ?? null) ? (int) $row['themes_updates'] : 0,
			is_numeric($row['cron_overdue'] ?? null) ? (int) $row['cron_overdue'] : 0,
			is_numeric($row['cron_oldest_lag_sec'] ?? null) ? (int) $row['cron_oldest_lag_sec'] : 0,
			is_numeric($row['autoload_bytes'] ?? null) ? (int) $row['autoload_bytes'] : 0,
			is_numeric($row['autoload_rows'] ?? null) ? (int) $row['autoload_rows'] : 0,
			is_numeric($row['object_cache_hit_ratio'] ?? null) ? (float) $row['object_cache_hit_ratio'] : null,
			is_numeric($row['opcache_hit_ratio'] ?? null) ? (float) $row['opcache_hit_ratio'] : null,
			is_numeric($row['opcache_memory_used_pct'] ?? null) ? (float) $row['opcache_memory_used_pct'] : null,
			is_numeric($row['php_fpm_active'] ?? null) ? (int) $row['php_fpm_active'] : null,
			is_numeric($row['php_fpm_idle'] ?? null) ? (int) $row['php_fpm_idle'] : null,
			is_numeric($row['php_fpm_queued'] ?? null) ? (int) $row['php_fpm_queued'] : null,
			is_numeric($row['tls_expiry_days'] ?? null) ? (int) $row['tls_expiry_days'] : null,
			is_numeric($row['http_error_rate_pct'] ?? null) ? (float) $row['http_error_rate_pct'] : 0.0,
			!empty($row['xmlrpc_exposed']),
			!empty($row['rest_users_exposed']),
			$details,
			is_string($row['last_error'] ?? null) ? $row['last_error'] : '',
			is_numeric($row['polled_at'] ?? null) ? (int) $row['polled_at'] : 0,
		);
	}

	/**
	 * Compute the standard Apdex score for latency samples against satisfied threshold T.
	 *
	 * Samples <= T count as satisfied (1.0), samples in (T, 4T] count as tolerating (0.5),
	 * and samples > 4T count as frustrated (0.0).
	 *
	 * @param list<float> $samples Latency values in milliseconds.
	 * @param int $thresholdTMs Satisfied threshold T in milliseconds.
	 * @return float Apdex score in [0.0, 1.0].
	 */
	public static function computeApdex(array $samples, int $thresholdTMs): float {
		$total = count($samples);

		if ($total === 0) {
			return 0.0;
		}

		$t          = (float) max(1, $thresholdTMs);
		$fourT      = $t * 4.0;
		$satisfied  = 0;
		$tolerating = 0;

		foreach ($samples as $latency) {
			if ($latency <= $t) {
				$satisfied++;
			} elseif ($latency <= $fourT) {
				$tolerating++;
			}
		}

		return round(($satisfied + (0.5 * $tolerating)) / $total, 4);
	}

	/**
	 * Classify wp_options autoload bloat severity against configured byte thresholds.
	 *
	 * @param Settings|null $settings Threshold settings (defaults: 800 KiB warn, 2 MiB critical).
	 * @return string One of ok, warning, critical.
	 */
	public function autoloadSeverity(?Settings $settings = null): string {
		$cfg = $settings ?? new Settings();

		if ($this->autoloadBytes > $cfg->autoloadCritBytes) {
			return 'critical';
		}

		if ($this->autoloadBytes > $cfg->autoloadWarnBytes) {
			return 'warning';
		}

		return 'ok';
	}

	/**
	 * Classify WP-Cron stall severity for this site.
	 *
	 * @param Settings|null $settings Threshold settings.
	 * @return string One of ok, warning, critical.
	 */
	public function cronSeverity(?Settings $settings = null): string {
		$cfg = $settings ?? new Settings();

		if ($this->cronOldestLagSeconds >= ($cfg->cronLagWarnSec * 4) || $this->cronOverdueCount >= 25) {
			return 'critical';
		}

		if ($this->cronOverdueCount > 0 || $this->cronOldestLagSeconds >= $cfg->cronLagWarnSec) {
			return 'warning';
		}

		return 'ok';
	}

	/**
	 * Classify TLS certificate expiry severity for this site.
	 *
	 * @param Settings|null $settings Threshold settings.
	 * @return string One of ok, warning, critical, unknown.
	 */
	public function tlsSeverity(?Settings $settings = null): string {
		if ($this->tlsExpiryDays === null) {
			return 'unknown';
		}

		$cfg = $settings ?? new Settings();

		if ($this->tlsExpiryDays <= $cfg->tlsCritDays) {
			return 'critical';
		}

		if ($this->tlsExpiryDays <= $cfg->tlsWarnDays) {
			return 'warning';
		}

		return 'ok';
	}

	/**
	 * Return total pending plugin and theme updates for this site.
	 *
	 * @return int
	 */
	public function totalUpdatesPending(): int {
		return $this->pluginsUpdatesPending + $this->themesUpdatesPending;
	}

	/**
	 * Serialize this snapshot to a non-secret associative array for JSON/API/MCP responses.
	 *
	 * @return array<string, mixed>
	 */
	public function toArray(): array {
		return [
			'slug'                   => $this->slug,
			'siteName'               => $this->siteName,
			'url'                    => $this->url,
			'pollerId'               => $this->pollerId,
			'status'                 => $this->status,
			'wpVersion'              => $this->wpVersion,
			'ttfbMs'                 => $this->ttfbMs,
			'ttfbP95Ms'              => $this->ttfbP95Ms,
			'apdexTMs'               => $this->apdexTMs,
			'apdexScore'             => $this->apdexScore,
			'siteHealthGood'         => $this->siteHealthGood,
			'siteHealthRecommended'  => $this->siteHealthRecommended,
			'siteHealthCritical'     => $this->siteHealthCritical,
			'pluginsActive'          => $this->pluginsActive,
			'pluginsInactive'        => $this->pluginsInactive,
			'pluginsUpdatesPending'  => $this->pluginsUpdatesPending,
			'themesActive'           => $this->themesActive,
			'themesUpdatesPending'   => $this->themesUpdatesPending,
			'updatesPending'         => $this->totalUpdatesPending(),
			'cronOverdueCount'       => $this->cronOverdueCount,
			'cronOldestLagSeconds'   => $this->cronOldestLagSeconds,
			'autoloadBytes'          => $this->autoloadBytes,
			'autoloadRows'           => $this->autoloadRows,
			'objectCacheHitRatio'    => $this->objectCacheHitRatio,
			'opcacheHitRatio'        => $this->opcacheHitRatio,
			'opcacheMemoryUsedPct'   => $this->opcacheMemoryUsedPct,
			'phpFpmActive'           => $this->phpFpmActive,
			'phpFpmIdle'             => $this->phpFpmIdle,
			'phpFpmQueued'           => $this->phpFpmQueued,
			'tlsExpiryDays'          => $this->tlsExpiryDays,
			'httpErrorRatePct'       => $this->httpErrorRatePct,
			'xmlrpcExposed'          => $this->xmlrpcExposed,
			'restUsersExposed'       => $this->restUsersExposed,
			'lastError'              => $this->lastError,
			'polledAt'               => $this->polledAt,
		];
	}

	/**
	 * Determine overall site health status from observed telemetry and configured thresholds.
	 *
	 * @param int $healthCritical Site Health critical count.
	 * @param int $healthRecommended Site Health recommended count.
	 * @param int $autoloadBytes Autoloaded bytes.
	 * @param int $cronOverdue Overdue WP-Cron jobs.
	 * @param int $cronLag Oldest overdue cron lag seconds.
	 * @param int|null $tlsExpiryDays Days to TLS expiry.
	 * @param float $httpErrorRatePct HTTP 4xx/5xx error rate percentage.
	 * @param float $apdexScore Per-site Apdex score.
	 * @param int $updatesPending Combined pending plugin/theme updates.
	 * @param string $lastError Last error string.
	 * @param Settings $cfg Active threshold settings.
	 * @return string
	 */
	private static function classifyStatus(
		int $healthCritical,
		int $healthRecommended,
		int $autoloadBytes,
		int $cronOverdue,
		int $cronLag,
		?int $tlsExpiryDays,
		float $httpErrorRatePct,
		float $apdexScore,
		int $updatesPending,
		string $lastError,
		Settings $cfg,
	): string {
		if ($lastError !== '') {
			return self::STATUS_UNREACHABLE;
		}

		if (
			$healthCritical > 0
			|| $autoloadBytes > $cfg->autoloadCritBytes
			|| ($tlsExpiryDays !== null && $tlsExpiryDays <= $cfg->tlsCritDays)
			|| $httpErrorRatePct >= 5.0
			|| $cronLag >= ($cfg->cronLagWarnSec * 4)
			|| $cronOverdue >= 25
		) {
			return self::STATUS_CRITICAL;
		}

		if (
			$healthRecommended > 0
			|| $autoloadBytes > $cfg->autoloadWarnBytes
			|| $cronOverdue > 0
			|| $cronLag >= $cfg->cronLagWarnSec
			|| ($tlsExpiryDays !== null && $tlsExpiryDays <= $cfg->tlsWarnDays)
			|| $httpErrorRatePct >= 1.0
			|| $apdexScore < 0.7
			|| $updatesPending > 0
		) {
			return self::STATUS_DEGRADED;
		}

		return self::STATUS_HEALTHY;
	}
}
