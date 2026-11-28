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
 * PHP 8.0-parseable Cacti Script Server data source script emitting aggregate
 * WordPress fleet health metrics with strict 'U' (RRDtool unknown) fallback on error.
 */

/**
 * Format the RRDtool unknown fallback output line for all fleet metric fields.
 *
 * @return string
 */
function ss_wordpress_stats_unknown(): string {
	return 'sites_total:U sites_healthy:U sites_degraded:U sites_critical:U updates_pending:U cron_overdue_total:U autoload_bloat_sites:U ttfb_p95_ms:U tls_min_expiry_days:U';
}

/**
 * Format analyzed fleet counts into Cacti script-server key:value output.
 *
 * @param array<string, mixed> $counts FleetAnalyzer counts array.
 * @return string
 */
function ss_wordpress_stats_format(array $counts): string {
	$tlsMin = isset($counts['tls_min_expiry_days']) && is_numeric($counts['tls_min_expiry_days'])
		? (string) (int) $counts['tls_min_expiry_days']
		: 'U';

	$ttfbP95 = isset($counts['ttfb_p95_ms']) && is_numeric($counts['ttfb_p95_ms'])
		? sprintf('%.2f', (float) $counts['ttfb_p95_ms'])
		: 'U';

	return sprintf(
		'sites_total:%d sites_healthy:%d sites_degraded:%d sites_critical:%d updates_pending:%d cron_overdue_total:%d autoload_bloat_sites:%d ttfb_p95_ms:%s tls_min_expiry_days:%s',
		isset($counts['sites_total']) && is_numeric($counts['sites_total']) ? (int) $counts['sites_total'] : 0,
		isset($counts['sites_healthy']) && is_numeric($counts['sites_healthy']) ? (int) $counts['sites_healthy'] : 0,
		isset($counts['sites_degraded']) && is_numeric($counts['sites_degraded']) ? (int) $counts['sites_degraded'] : 0,
		isset($counts['sites_critical']) && is_numeric($counts['sites_critical']) ? (int) $counts['sites_critical'] : 0,
		isset($counts['updates_pending']) && is_numeric($counts['updates_pending']) ? (int) $counts['updates_pending'] : 0,
		isset($counts['cron_overdue_total']) && is_numeric($counts['cron_overdue_total']) ? (int) $counts['cron_overdue_total'] : 0,
		isset($counts['autoload_bloat_sites']) && is_numeric($counts['autoload_bloat_sites']) ? (int) $counts['autoload_bloat_sites'] : 0,
		$ttfbP95,
		$tlsMin
	);
}

/**
 * Cacti script-server entry point returning WordPress fleet health metrics.
 *
 * Returns 'U' across all fields on runtime error so RRDtool records a gap rather
 * than injecting misleading zero values into graphs and Thold alerts.
 *
 * @param mixed $pollerId Optional Cacti poller ID filter (0 or empty for entire fleet).
 * @return string
 */
function ss_wordpress_stats(mixed $pollerId = 0): string {
	try {
		if (!function_exists('wordpress_boot')) {
			$setupFile = dirname(__DIR__) . '/setup.php';

			if (is_file($setupFile)) {
				require_once($setupFile);
			}
		}

		if (!function_exists('wordpress_boot') || !wordpress_boot()) {
			return ss_wordpress_stats_unknown();
		}

		$filterPoller = is_numeric($pollerId) && (int) $pollerId > 0 ? (int) $pollerId : null;
		$snapshots    = wordpress_repository()->loadSnapshots($filterPoller);
		$analysis     = (new \Somethingwithproof\WordPress\Metrics\FleetAnalyzer(wordpress_settings()))->analyze($snapshots);

		return ss_wordpress_stats_format($analysis['counts']);
	} catch (\Throwable) {
		return ss_wordpress_stats_unknown();
	}
}

if (!isset($called_by_script_server) && PHP_SAPI === 'cli' && isset($_SERVER['SCRIPT_FILENAME']) && is_string($_SERVER['SCRIPT_FILENAME']) && realpath($_SERVER['SCRIPT_FILENAME']) === realpath(__FILE__)) {
	$cactiCliCheck = dirname(__DIR__, 3) . '/include/cli_check.php';

	if (is_file($cactiCliCheck)) {
		require_once($cactiCliCheck);
	}

	$argPoller = isset($argv[1]) && is_numeric($argv[1]) ? (int) $argv[1] : 0;
	print ss_wordpress_stats($argPoller) . PHP_EOL;
}
