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
 * Fleet-wide WordPress telemetry analyzer computing Apdex scores, MAD-based TTFB
 * latency anomaly detection, autoload bloat severity, WP-Cron stall detection,
 * TLS expiry countdowns, update drift summaries, and Cacti Thold baseline templates.
 *
 * All fleet aggregation passes run in O(N log N) time with flat numeric arrays
 * and zero nested O(N^2) loops so 5,000 to 10,000+ site fleets complete in milliseconds.
 */
final class FleetAnalyzer {
	/**
	 * Consistency scale factor for normal distributions in modified z-score MAD anomaly detection.
	 */
	private const MAD_SCALE = 0.67448975;

	/**
	 * Modified z-score threshold flagging a site as a latency outlier (Iglewicz and Hoaglin).
	 */
	public const MAD_ANOMALY_THRESHOLD = 3.5;

	/**
	 * Maximum anomaly/offender entries returned in fleet summaries to bound payload sizes.
	 */
	private const MAX_SUMMARY_ITEMS = 50;

	/**
	 * Construct a FleetAnalyzer with threshold settings.
	 *
	 * @param Settings|null $settings Plugin threshold settings.
	 */
	public function __construct(private readonly ?Settings $settings = null) {
	}

	/**
	 * Analyze a fleet of WordPress SiteMetrics snapshots in O(N log N) time.
	 *
	 * @param list<SiteMetrics> $sites Fleet snapshots.
	 * @return array{
	 *   counts: array{
	 *     sites_total: int,
	 *     sites_healthy: int,
	 *     sites_degraded: int,
	 *     sites_critical: int,
	 *     sites_unreachable: int,
	 *     updates_pending: int,
	 *     cron_overdue_total: int,
	 *     autoload_bloat_sites: int,
	 *     autoload_warn_sites: int,
	 *     autoload_crit_sites: int,
	 *     ttfb_p95_ms: float,
	 *     tls_min_expiry_days: int|null
	 *   },
	 *   apdex: array{score: float, rating: string, thresholdTMs: int},
	 *   latency: array{medianMs: float, madMs: float, p95Ms: float, anomalyCount: int, anomalies: list<array{slug: string, ttfbMs: float, modifiedZ: float}>},
	 *   cronStalls: list<array{slug: string, overdue: int, oldestLagSec: int, severity: string}>,
	 *   autoloadBloat: list<array{slug: string, bytes: int, rows: int, severity: string}>,
	 *   tlsExpiring: list<array{slug: string, daysRemaining: int, severity: string}>,
	 *   updateDrift: array{totalPending: int, sitesWithUpdates: int, latestWpVersion: string, wpVersionCounts: array<string, int>, sitesBehindCore: int}
	 * }
	 */
	public function analyze(array $sites): array {
		$cfg         = $this->settings ?? new Settings();
		$total       = count($sites);
		$healthy     = 0;
		$degraded    = 0;
		$critical    = 0;
		$unreachable = 0;

		$updatesPending     = 0;
		$sitesWithUpdates   = 0;
		$cronOverdueTotal   = 0;
		$autoloadWarnSites  = 0;
		$autoloadCritSites  = 0;
		$tlsMinExpiryDays   = null;
		$apdexSatisfied     = 0;
		$apdexTolerating    = 0;
		$apdexSampleCount   = 0;
		$tMs                = (float) $cfg->defaultApdexTMs;
		$fourTMs            = $tMs * 4.0;

		$ttfbs           = [];
		$ttfbIndices     = [];
		$cronStalls      = [];
		$autoloadBloat   = [];
		$tlsExpiring     = [];
		$wpVersionCounts = [];

		foreach ($sites as $idx => $site) {
			if ($site->status === SiteMetrics::STATUS_HEALTHY) {
				$healthy++;
			} elseif ($site->status === SiteMetrics::STATUS_DEGRADED) {
				$degraded++;
			} elseif ($site->status === SiteMetrics::STATUS_UNREACHABLE) {
				$unreachable++;
				$critical++;
			} else {
				$critical++;
			}

			$siteUpdates = $site->totalUpdatesPending();

			if ($siteUpdates > 0) {
				$updatesPending += $siteUpdates;
				$sitesWithUpdates++;
			}

			if ($site->wpVersion !== '') {
				$wpVersionCounts[$site->wpVersion] = ($wpVersionCounts[$site->wpVersion] ?? 0) + 1;
			}

			if ($site->cronOverdueCount > 0 || $site->cronOldestLagSeconds >= $cfg->cronLagWarnSec) {
				$cronOverdueTotal += $site->cronOverdueCount;
				$cronSeverity      = $site->cronSeverity($cfg);

				if (count($cronStalls) < self::MAX_SUMMARY_ITEMS) {
					$cronStalls[] = [
						'slug'         => $site->slug,
						'overdue'      => $site->cronOverdueCount,
						'oldestLagSec' => $site->cronOldestLagSeconds,
						'severity'     => $cronSeverity,
					];
				}
			}

			$autoSeverity = $site->autoloadSeverity($cfg);

			if ($autoSeverity === 'critical') {
				$autoloadCritSites++;
				$autoloadBloat[] = [
					'slug'     => $site->slug,
					'bytes'    => $site->autoloadBytes,
					'rows'     => $site->autoloadRows,
					'severity' => 'critical',
				];
			} elseif ($autoSeverity === 'warning') {
				$autoloadWarnSites++;
				$autoloadBloat[] = [
					'slug'     => $site->slug,
					'bytes'    => $site->autoloadBytes,
					'rows'     => $site->autoloadRows,
					'severity' => 'warning',
				];
			}

			if ($site->tlsExpiryDays !== null) {
				if ($tlsMinExpiryDays === null || $site->tlsExpiryDays < $tlsMinExpiryDays) {
					$tlsMinExpiryDays = $site->tlsExpiryDays;
				}

				$tlsSev = $site->tlsSeverity($cfg);

				if ($tlsSev === 'critical' || $tlsSev === 'warning') {
					$tlsExpiring[] = [
						'slug'          => $site->slug,
						'daysRemaining' => $site->tlsExpiryDays,
						'severity'      => $tlsSev,
					];
				}
			}

			if ($site->status !== SiteMetrics::STATUS_UNREACHABLE && $site->ttfbMs > 0.0) {
				$ttfbs[]       = $site->ttfbMs;
				$ttfbIndices[] = $idx;
				$apdexSampleCount++;

				if ($site->ttfbMs <= $tMs) {
					$apdexSatisfied++;
				} elseif ($site->ttfbMs <= $fourTMs) {
					$apdexTolerating++;
				}
			}
		}

		$apdexScore = $apdexSampleCount > 0
			? round(($apdexSatisfied + (0.5 * $apdexTolerating)) / $apdexSampleCount, 4)
			: 0.0;

		$latency = $this->analyzeLatencyMad($sites, $ttfbs, $ttfbIndices);

		if (count($autoloadBloat) > 1) {
			usort($autoloadBloat, static fn (array $a, array $b): int => $b['bytes'] <=> $a['bytes']);
		}

		if (count($autoloadBloat) > self::MAX_SUMMARY_ITEMS) {
			$autoloadBloat = array_slice($autoloadBloat, 0, self::MAX_SUMMARY_ITEMS);
		}

		if (count($tlsExpiring) > 1) {
			usort($tlsExpiring, static fn (array $a, array $b): int => $a['daysRemaining'] <=> $b['daysRemaining']);
		}

		if (count($tlsExpiring) > self::MAX_SUMMARY_ITEMS) {
			$tlsExpiring = array_slice($tlsExpiring, 0, self::MAX_SUMMARY_ITEMS);
		}

		$latestWp        = self::highestVersion(array_keys($wpVersionCounts));
		$sitesBehindCore = 0;

		if ($latestWp !== '') {
			foreach ($wpVersionCounts as $ver => $count) {
				if (version_compare($ver, $latestWp, '<')) {
					$sitesBehindCore += $count;
				}
			}
		}

		krsort($wpVersionCounts, SORT_NATURAL);

		return [
			'counts' => [
				'sites_total'          => $total,
				'sites_healthy'        => $healthy,
				'sites_degraded'       => $degraded,
				'sites_critical'       => $critical,
				'sites_unreachable'    => $unreachable,
				'updates_pending'      => $updatesPending,
				'cron_overdue_total'   => $cronOverdueTotal,
				'autoload_bloat_sites' => $autoloadWarnSites + $autoloadCritSites,
				'autoload_warn_sites'  => $autoloadWarnSites,
				'autoload_crit_sites'  => $autoloadCritSites,
				'ttfb_p95_ms'          => $latency['p95Ms'],
				'tls_min_expiry_days'  => $tlsMinExpiryDays,
			],
			'apdex' => [
				'score'        => $apdexScore,
				'rating'       => self::apdexRating($apdexScore),
				'thresholdTMs' => $cfg->defaultApdexTMs,
			],
			'latency'       => $latency,
			'cronStalls'    => $cronStalls,
			'autoloadBloat' => $autoloadBloat,
			'tlsExpiring'   => $tlsExpiring,
			'updateDrift'   => [
				'totalPending'     => $updatesPending,
				'sitesWithUpdates' => $sitesWithUpdates,
				'latestWpVersion'  => $latestWp,
				'wpVersionCounts'  => $wpVersionCounts,
				'sitesBehindCore'  => $sitesBehindCore,
			],
		];
	}

	/**
	 * Return Cacti Thold baseline threshold template definitions for WordPress fleet metrics.
	 *
	 * @param Settings|null $settings Active settings supplying default warning/critical thresholds.
	 * @return list<array{
	 *   name: string,
	 *   dataSource: string,
	 *   metricField: string,
	 *   unit: string,
	 *   warnHigh: float|int|null,
	 *   critHigh: float|int|null,
	 *   warnLow: float|int|null,
	 *   critLow: float|int|null,
	 *   triggerCount: int,
	 *   rationale: string
	 * }>
	 */
	public static function tholdTemplates(?Settings $settings = null): array {
		$cfg = $settings ?? new Settings();

		return [
			[
				'name'         => 'WordPress Fleet TTFB p95 Latency',
				'dataSource'   => 'ss_wordpress_stats',
				'metricField'  => 'ttfb_p95_ms',
				'unit'         => 'ms',
				'warnHigh'     => $cfg->defaultApdexTMs * 2,
				'critHigh'     => $cfg->defaultApdexTMs * 4,
				'warnLow'      => null,
				'critLow'      => null,
				'triggerCount' => 2,
				'rationale'    => 'Alerts when fleet p95 TTFB moves into tolerating (2T) or frustrated (4T) Apdex bands.',
			],
			[
				'name'         => 'WordPress Autoload Bloat Sites',
				'dataSource'   => 'ss_wordpress_stats',
				'metricField'  => 'autoload_bloat_sites',
				'unit'         => 'sites',
				'warnHigh'     => 1,
				'critHigh'     => 5,
				'warnLow'      => null,
				'critLow'      => null,
				'triggerCount' => 1,
				'rationale'    => 'Tracks sites exceeding wp_options autoload warning (800 KiB) or critical (2 MiB) budgets.',
			],
			[
				'name'         => 'WordPress WP-Cron Overdue Backlog',
				'dataSource'   => 'ss_wordpress_stats',
				'metricField'  => 'cron_overdue_total',
				'unit'         => 'jobs',
				'warnHigh'     => 5,
				'critHigh'     => 25,
				'warnLow'      => null,
				'critLow'      => null,
				'triggerCount' => 2,
				'rationale'    => 'Detects stalled WP-Cron runners before scheduled publishing and cache purges back up.',
			],
			[
				'name'         => 'WordPress Minimum TLS Certificate Expiry',
				'dataSource'   => 'ss_wordpress_stats',
				'metricField'  => 'tls_min_expiry_days',
				'unit'         => 'days',
				'warnHigh'     => null,
				'critHigh'     => null,
				'warnLow'      => $cfg->tlsWarnDays,
				'critLow'      => $cfg->tlsCritDays,
				'triggerCount' => 1,
				'rationale'    => 'Triggers renewal alerts before the soonest expiring certificate in the fleet lapses.',
			],
			[
				'name'         => 'WordPress Critical Sites Count',
				'dataSource'   => 'ss_wordpress_stats',
				'metricField'  => 'sites_critical',
				'unit'         => 'sites',
				'warnHigh'     => 1,
				'critHigh'     => 3,
				'warnLow'      => null,
				'critLow'      => null,
				'triggerCount' => 1,
				'rationale'    => 'Escalates immediately when sites become unreachable or report critical Site Health failures.',
			],
			[
				'name'         => 'WordPress Pending Security/Plugin Updates',
				'dataSource'   => 'ss_wordpress_stats',
				'metricField'  => 'updates_pending',
				'unit'         => 'updates',
				'warnHigh'     => 10,
				'critHigh'     => 50,
				'warnLow'      => null,
				'critLow'      => null,
				'triggerCount' => 3,
				'rationale'    => 'Tracks fleet plugin and theme patch drift across maintenance windows.',
			],
		];
	}

	/**
	 * Compute median, MAD, p95, and modified z-score TTFB latency anomalies in O(N log N) time.
	 *
	 * @param list<SiteMetrics> $sites Full site list.
	 * @param list<float> $ttfbs Observed positive TTFB values aligned with $ttfbIndices.
	 * @param list<int> $ttfbIndices Original site indices for each TTFB entry.
	 * @return array{medianMs: float, madMs: float, p95Ms: float, anomalyCount: int, anomalies: list<array{slug: string, ttfbMs: float, modifiedZ: float}>}
	 */
	private function analyzeLatencyMad(array $sites, array $ttfbs, array $ttfbIndices): array {
		$n = count($ttfbs);

		if ($n === 0) {
			return [
				'medianMs'     => 0.0,
				'madMs'        => 0.0,
				'p95Ms'        => 0.0,
				'anomalyCount' => 0,
				'anomalies'    => [],
			];
		}

		$sorted = $ttfbs;
		sort($sorted, SORT_NUMERIC);

		$median = self::medianOfSorted($sorted, $n);
		$p95Idx = max(0, min($n - 1, (int) ceil(0.95 * $n) - 1));
		$p95    = round($sorted[$p95Idx], 2);

		$absDevs = [];

		for ($i = 0; $i < $n; $i++) {
			$absDevs[] = abs($sorted[$i] - $median);
		}

		sort($absDevs, SORT_NUMERIC);
		$mad = self::medianOfSorted($absDevs, $n);

		$anomalies    = [];
		$anomalyCount = 0;

		if ($mad > 0.0) {
			$factor = self::MAD_SCALE / $mad;

			for ($i = 0; $i < $n; $i++) {
				$value = $ttfbs[$i];

				if ($value <= $median) {
					continue;
				}

				$modZ = ($value - $median) * $factor;

				if ($modZ > self::MAD_ANOMALY_THRESHOLD) {
					$anomalyCount++;
					$anomalies[] = [
						'slug'      => $sites[$ttfbIndices[$i]]->slug,
						'ttfbMs'    => round($value, 2),
						'modifiedZ' => round($modZ, 2),
					];
				}
			}
		} elseif ($n >= 3) {
			// When MAD is 0 (over half of sites share identical latency), flag spikes > 2x median + 100ms.
			$fallbackLimit = ($median * 2.0) + 100.0;

			for ($i = 0; $i < $n; $i++) {
				$value = $ttfbs[$i];

				if ($value > $fallbackLimit) {
					$anomalyCount++;
					$anomalies[] = [
						'slug'      => $sites[$ttfbIndices[$i]]->slug,
						'ttfbMs'    => round($value, 2),
						'modifiedZ' => round(($value - $median) / max(1.0, $median), 2),
					];
				}
			}
		}

		if (count($anomalies) > 1) {
			usort($anomalies, static fn (array $a, array $b): int => $b['modifiedZ'] <=> $a['modifiedZ']);
		}

		if (count($anomalies) > self::MAX_SUMMARY_ITEMS) {
			$anomalies = array_slice($anomalies, 0, self::MAX_SUMMARY_ITEMS);
		}

		return [
			'medianMs'     => round($median, 2),
			'madMs'        => round($mad, 2),
			'p95Ms'        => $p95,
			'anomalyCount' => $anomalyCount,
			'anomalies'    => $anomalies,
		];
	}

	/**
	 * Compute the exact median of an already-sorted non-empty numeric array.
	 *
	 * @param list<float> $sorted Ascending sorted numeric values.
	 * @param int $n Element count (>= 1).
	 * @return float
	 */
	private static function medianOfSorted(array $sorted, int $n): float {
		$mid = intdiv($n, 2);

		if (($n & 1) === 1) {
			return $sorted[$mid];
		}

		return ($sorted[$mid - 1] + $sorted[$mid]) * 0.5;
	}

	/**
	 * Return the highest semantic version string from a list of WordPress core versions.
	 *
	 * @param list<string> $versions Observed version strings.
	 * @return string
	 */
	private static function highestVersion(array $versions): string {
		$best = '';

		foreach ($versions as $ver) {
			if ($best === '' || version_compare($ver, $best, '>')) {
				$best = $ver;
			}
		}

		return $best;
	}

	/**
	 * Map a numeric Apdex score to its standard qualitative band.
	 *
	 * @param float $score Apdex score in [0.0, 1.0].
	 * @return string
	 */
	private static function apdexRating(float $score): string {
		if ($score >= 0.94) {
			return 'excellent';
		}

		if ($score >= 0.85) {
			return 'good';
		}

		if ($score >= 0.70) {
			return 'fair';
		}

		if ($score >= 0.50) {
			return 'poor';
		}

		return 'unacceptable';
	}
}
