#!/usr/bin/env php
<?php
/*
 * SPDX-FileCopyrightText: 2026 Thomas Vincent <thomasvincent@gmail.com>
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This file is part of plugin_wordpress, a plugin for Cacti.
 * https://github.com/somethingwithproof/plugin_wordpress
 *
 * Real PHP performance benchmark profiling FleetAnalyzer, WordPressClient parsers,
 * AdaptivePollerSizer, and SecretVault at 5,000 and 10,000 WordPress sites.
 */

declare(strict_types=1);

require_once dirname(__DIR__) . '/include/autoload.php';

use Somethingwithproof\WordPress\Client\WordPressClient;
use Somethingwithproof\WordPress\Db\MemoryDbAdapter;
use Somethingwithproof\WordPress\Metrics\AdaptivePollerSizer;
use Somethingwithproof\WordPress\Metrics\FleetAnalyzer;
use Somethingwithproof\WordPress\Metrics\SiteMetrics;
use Somethingwithproof\WordPress\Security\SecretVault;
use Somethingwithproof\WordPress\Settings;

$settings = new Settings();
$analyzer = new FleetAnalyzer($settings);
$sizer    = new AdaptivePollerSizer();

$sampleDiscovery = (string) json_encode([
	'name'       => 'Enterprise WP Site',
	'wp_version' => '6.7.2',
	'namespaces' => ['wp/v2', 'wp-site-health/v1', 'cacti-wp/v1'],
	'routes'     => ['/wp/v2/posts' => []],
]);
$samplePlugins = (string) json_encode([
	['plugin' => 'akismet/akismet.php', 'status' => 'active', 'version' => '5.3.0', 'update' => ['version' => '5.3.5']],
	['plugin' => 'redis-cache/redis-cache.php', 'status' => 'active', 'version' => '2.5.4'],
	['plugin' => 'wp-crontrol/wp-crontrol.php', 'status' => 'active', 'version' => '1.17.0'],
	['plugin' => 'hello.php', 'status' => 'inactive', 'version' => '1.7.2'],
]);
$sampleTelemetry = (string) json_encode([
	'wp_cron'         => ['overdue_count' => 1, 'oldest_lag_seconds' => 320],
	'autoload'        => ['bytes' => 524288, 'rows' => 410],
	'object_cache'    => ['hit_ratio_pct' => 97.2],
	'opcache'         => ['hit_ratio_pct' => 99.3, 'memory_used_pct' => 54.0],
	'php_fpm'         => ['active' => 8, 'idle' => 12, 'queued' => 0],
	'http'            => ['homepage_ttfb_ms' => 172.5, 'ttfb_p95_ms' => 235.0, 'error_rate_pct' => 0.2],
	'tls_expiry_days' => 52,
]);

$keyFile = tempnam(sys_get_temp_dir(), 'wpbench_');
file_put_contents($keyFile, bin2hex(random_bytes(32)));
chmod($keyFile, 0600);

$results = [
	'phpVersion' => PHP_VERSION,
	'os'         => PHP_OS_FAMILY,
	'scales'     => [],
];

try {
	$vault = new SecretVault(new MemoryDbAdapter(), $keyFile);

	foreach ([5000, 10000] as $n) {
		gc_collect_cycles();
		$sites     = [];
		$inventory = [];

		for ($i = 0; $i < $n; $i++) {
			$slug        = sprintf('wp-site-%05d', $i);
			$isAnomaly   = ($i % 250) === 0;
			$isBloat     = ($i % 50) === 0;
			$isCritBloat = ($i % 200) === 0;
			$ttfb        = $isAnomaly ? 2400.0 + ($i % 400) : 120.0 + (($i * 17) % 140);
			$autoload    = $isCritBloat ? 2600000 : ($isBloat ? 1050000 : 280000 + (($i * 97) % 300000));
			$sites[]     = new SiteMetrics(
				$slug,
				'Site ' . $i,
				'https://' . $slug . '.example.com',
				($i % 4) + 1,
				$isCritBloat ? SiteMetrics::STATUS_CRITICAL : ($isBloat ? SiteMetrics::STATUS_DEGRADED : SiteMetrics::STATUS_HEALTHY),
				($i % 10 === 0) ? '6.6.2' : '6.7.2',
				$ttfb,
				$ttfb * 1.25,
				500,
				$isAnomaly ? 0.0 : 1.0,
				5,
				$isBloat ? 1 : 0,
				$isCritBloat ? 1 : 0,
				18,
				2,
				$i % 7 === 0 ? 2 : 0,
				1,
				1,
				0,
				$i % 80 === 0 ? 3 : 0,
				$i % 80 === 0 ? 1400 : 0,
				$autoload,
				400,
				96.5,
				99.1,
				55.0,
				6,
				14,
				0,
				($i % 120 === 0) ? 12 : 65,
				0.1,
				false,
				false,
				[],
				'',
				1700000000
			);
			$inventory[] = ['slug' => $slug];
		}

		// 1. FleetAnalyzer::analyze()
		$t0       = hrtime(true);
		$analysis = $analyzer->analyze($sites);
		$tAnalyze = (hrtime(true) - $t0) / 1e6;

		// 2. WordPressClient payload parsers across N sites
		$t0 = hrtime(true);

		for ($i = 0; $i < $n; $i++) {
			WordPressClient::parseDiscoveryPayload($sampleDiscovery);
			WordPressClient::parsePluginsPayload($samplePlugins);
			WordPressClient::parseTelemetryPayload($sampleTelemetry);
		}

		$tParse = (hrtime(true) - $t0) / 1e6;

		// 3. AdaptivePollerSizer (sharding N sites across 4 shards + sizing step)
		$t0     = hrtime(true);
		$sharded = AdaptivePollerSizer::shardSites($inventory, 1, 4);
		$sizing = $sizer->size(count($sharded), 300, 380.0, 120.0, [], 500, 2, 64);
		$tSizer = (hrtime(true) - $t0) / 1e6;

		// 4. SecretVault AES-256-GCM encrypt + decrypt round-trip for N sites
		$t0 = hrtime(true);

		for ($i = 0; $i < $n; $i++) {
			$slug = sprintf('wp-site-%05d', $i);
			$env  = $vault->encrypt($slug, 'AbCd 1234 EfGh 5678 IjKl 9012');
			$vault->decrypt($slug, $env);
		}

		$tVault = (hrtime(true) - $t0) / 1e6;

		$results['scales'][(string) $n] = [
			'sites'                    => $n,
			'fleetAnalyzerMs'          => round($tAnalyze, 2),
			'fleetAnalyzerSitesPerSec' => (int) round($n / max(0.0001, $tAnalyze / 1000.0)),
			'anomaliesDetected'        => $analysis['latency']['anomalyCount'],
			'parsersMs'                => round($tParse, 2),
			'parsersSitesPerSec'       => (int) round($n / max(0.0001, $tParse / 1000.0)),
			'adaptiveSizerMs'          => round($tSizer, 2),
			'shard1Count'              => count($sharded),
			'recommendedConcurrency'   => $sizing['recommendedConcurrency'],
			'vaultRoundTripMs'         => round($tVault, 2),
			'vaultOpsPerSec'           => (int) round(($n * 2) / max(0.0001, $tVault / 1000.0)),
			'peakRssMiB'               => round(memory_get_peak_usage(true) / 1048576.0, 2),
		];
	}
} finally {
	@unlink($keyFile);
}

echo json_encode($results, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;
