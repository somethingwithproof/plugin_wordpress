#!/usr/bin/env php
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

if (PHP_SAPI !== 'cli') {
	exit(1);
}

chdir(__DIR__ . '/../..');

require('./include/cli_check.php');
require_once($config['base_path'] . '/plugins/wordpress/setup.php');

if (wordpress_refuse_unsupported_php()) {
	exit(1);
}

wordpress_boot();

$pollerId   = isset($config['poller_id']) && is_numeric($config['poller_id']) ? max(1, (int) $config['poller_id']) : 1;
$shardIndex = 1;
$shardCount = 1;
$dryRun     = false;
$format     = 'text';
$singleSite = '';

foreach (array_slice($argv, 1) as $arg) {
	if (strpos($arg, '--poller=') === 0) {
		$pollerId = max(1, (int) substr($arg, 9));
	} elseif (strpos($arg, '--shard=') === 0) {
		try {
			$parsed     = \Somethingwithproof\WordPress\Metrics\AdaptivePollerSizer::parseShardSpec(substr($arg, 8));
			$shardIndex = $parsed['index'];
			$shardCount = $parsed['count'];
		} catch (\InvalidArgumentException $error) {
			fwrite(STDERR, $error->getMessage() . PHP_EOL);
			exit(2);
		}
	} elseif (strpos($arg, '--site=') === 0) {
		$singleSite = trim(substr($arg, 7));
	} elseif ($arg === '--dry-run') {
		$dryRun = true;
	} elseif (strpos($arg, '--format=') === 0) {
		$format = strtolower(trim(substr($arg, 9)));
	}
}

$poller = wordpress_poller();

if ($singleSite !== '') {
	$metrics = $poller->probeSite($singleSite, !$dryRun);

	if ($metrics === null) {
		fwrite(STDERR, sprintf("Unknown site slug \"%s\".\n", $singleSite));
		exit(1);
	}

	if ($format === 'json') {
		fwrite(STDOUT, json_encode($metrics->toArray(), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL);
	} else {
		fwrite(STDOUT, sprintf("site=%s status=%s ttfb_ms=%.2f apdex=%.2f\n", $metrics->slug, $metrics->status, $metrics->ttfbMs, $metrics->apdexScore));
	}

	exit(0);
}

$result = $poller->pollFleet($pollerId, $shardIndex, $shardCount, $dryRun);

if ($format === 'json') {
	$summary              = $result;
	$summary['snapshots'] = array_map(
		static function (\Somethingwithproof\WordPress\Metrics\SiteMetrics $m): array {
			return $m->toArray();
		},
		$result['snapshots']
	);
	fwrite(STDOUT, json_encode($summary, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL);
} else {
	fwrite(STDOUT, sprintf(
		"poller=%d shard=%s polled=%d healthy=%d degraded=%d critical=%d recommended_concurrency=%d duration_ms=%.2f\n",
		$result['pollerId'],
		$result['shard'],
		$result['polled'],
		$result['healthy'],
		$result['degraded'],
		$result['critical'],
		$result['sizing']['recommendedConcurrency'],
		$result['durationMs']
	));
}

exit(0);
