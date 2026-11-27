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

namespace Somethingwithproof\WordPress\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Somethingwithproof\WordPress\Client\HttpResponse;
use Somethingwithproof\WordPress\Client\HttpTransport;
use Somethingwithproof\WordPress\Client\WordPressClient;
use Somethingwithproof\WordPress\Db\MemoryDbAdapter;
use Somethingwithproof\WordPress\Metrics\AdaptivePollerSizer;
use Somethingwithproof\WordPress\Metrics\FleetAnalyzer;
use Somethingwithproof\WordPress\Metrics\SiteMetrics;
use Somethingwithproof\WordPress\Poller\FleetPoller;
use Somethingwithproof\WordPress\Repository\SiteRepository;
use Somethingwithproof\WordPress\Security\OutboundGuard;
use Somethingwithproof\WordPress\Security\SecretVault;
use Somethingwithproof\WordPress\Settings;

final class FleetAnalyticsAndPollerTest extends TestCase {
	public function testFleetAnalyzerApdexMadAnomaliesBloatCronTlsAndTholdTemplates(): void {
		$settings = new Settings();
		$sites    = [];

		// 18 normal healthy sites around 140-180ms TTFB.
		for ($i = 1; $i <= 18; $i++) {
			$sites[] = SiteMetrics::fromObservation([
				'slug'          => sprintf('wp-%02d', $i),
				'siteName'      => 'Site ' . $i,
				'url'           => sprintf('https://wp-%02d.example.com', $i),
				'wpVersion'     => '6.7.2',
				'ttfbMs'        => 140.0 + ($i * 2.0),
				'ttfbP95Ms'     => 160.0 + ($i * 2.0),
				'autoloadBytes' => 250000,
				'autoloadRows'  => 240,
				'tlsExpiryDays' => 60,
			], $settings);
		}

		// 1 degraded site with autoload warning (>800 KiB), cron overdue, pending updates, TLS warn, and MAD latency spike.
		$sites[] = SiteMetrics::fromObservation([
			'slug'                  => 'wp-slow-bloat',
			'siteName'              => 'Slow Bloat',
			'url'                   => 'https://slow.example.com',
			'wpVersion'             => '6.6.2',
			'ttfbMs'                => 1850.0,
			'ttfbP95Ms'             => 2200.0,
			'autoloadBytes'         => 1100000,
			'autoloadRows'          => 920,
			'cronOverdueCount'      => 4,
			'cronOldestLagSeconds'  => 1200,
			'pluginsUpdatesPending' => 3,
			'themesUpdatesPending'  => 1,
			'tlsExpiryDays'         => 18,
		], $settings);

		// 1 critical site with >2 MiB autoload bloat, critical Site Health, and imminent TLS expiry (<=7d).
		$sites[] = SiteMetrics::fromObservation([
			'slug'                  => 'wp-crit',
			'siteName'              => 'Crit Site',
			'url'                   => 'https://crit.example.com',
			'wpVersion'             => '6.5.5',
			'ttfbMs'                => 3100.0,
			'ttfbP95Ms'             => 3400.0,
			'siteHealthCritical'    => 1,
			'autoloadBytes'         => 3145728,
			'autoloadRows'          => 1800,
			'cronOverdueCount'      => 30,
			'cronOldestLagSeconds'  => 5000,
			'tlsExpiryDays'         => 4,
		], $settings);

		$analysis = (new FleetAnalyzer($settings))->analyze($sites);

		$this->assertSame(20, $analysis['counts']['sites_total']);
		$this->assertSame(18, $analysis['counts']['sites_healthy']);
		$this->assertSame(1, $analysis['counts']['sites_degraded']);
		$this->assertSame(1, $analysis['counts']['sites_critical']);
		$this->assertSame(4, $analysis['counts']['updates_pending']);
		$this->assertSame(34, $analysis['counts']['cron_overdue_total']);
		$this->assertSame(2, $analysis['counts']['autoload_bloat_sites']);
		$this->assertSame(1, $analysis['counts']['autoload_warn_sites']);
		$this->assertSame(1, $analysis['counts']['autoload_crit_sites']);
		$this->assertSame(4, $analysis['counts']['tls_min_expiry_days']);

		$this->assertGreaterThan(0.85, $analysis['apdex']['score']);
		$this->assertGreaterThanOrEqual(2, $analysis['latency']['anomalyCount']);
		$this->assertSame('wp-crit', $analysis['latency']['anomalies'][0]['slug']);
		$this->assertSame('wp-crit', $analysis['autoloadBloat'][0]['slug']);
		$this->assertSame('wp-crit', $analysis['tlsExpiring'][0]['slug']);
		$this->assertSame('6.7.2', $analysis['updateDrift']['latestWpVersion']);
		$this->assertSame(2, $analysis['updateDrift']['sitesBehindCore']);

		$templates = FleetAnalyzer::tholdTemplates($settings);
		$this->assertCount(6, $templates);
		$this->assertSame('ttfb_p95_ms', $templates[0]['metricField']);
	}

	public function testAdaptivePollerSizerLittlesLawCodelAndSharding(): void {
		$sizer = new AdaptivePollerSizer();

		// 600 sites / 300s = 2 sites/sec; W = 2.0s => L = 4.0 * 1.25 = 5.0
		$steady = $sizer->size(600, 300, 2000.0, 50.0, [], 500, 2, 32);
		$this->assertSame('steady', $steady['codelState']);
		$this->assertGreaterThanOrEqual(5, $steady['recommendedConcurrency']);
		$this->assertSame(2.0, $steady['arrivalRatePerSec']);

		// CoDel standing delay breach triggers inverse-sqrt backoff.
		$backoff1 = $sizer->size(600, 300, 2000.0, 900.0, ['recommendedConcurrency' => 16, 'ewmaLatencyMs' => 2000.0, 'codelDropCount' => 1], 500, 2, 32);
		$this->assertSame('backoff', $backoff1['codelState']);
		$this->assertSame(2, $backoff1['codelDropCount']);
		$this->assertLessThan(16, $backoff1['recommendedConcurrency']);

		// Deterministic sharding covers 100% of sites with zero overlap across 4 shards.
		$inventory = [];

		for ($i = 1; $i <= 40; $i++) {
			$inventory[] = ['slug' => 'site-' . $i];
		}

		$seen = [];

		for ($k = 1; $k <= 4; $k++) {
			$part = AdaptivePollerSizer::shardSites($inventory, $k, 4);

			foreach ($part as $item) {
				$seen[] = (string) $item['slug'];
			}
		}

		sort($seen);
		$this->assertCount(40, array_unique($seen));

		$parsed = AdaptivePollerSizer::parseShardSpec('2/4');
		$this->assertSame(['index' => 2, 'count' => 4], $parsed);

		$this->expectException(\InvalidArgumentException::class);
		AdaptivePollerSizer::parseShardSpec('5/4');
	}

	public function testFleetPollerPersistsSnapshotsAndPollerState(): void {
		$db      = new MemoryDbAdapter();
		$repo    = new SiteRepository($db);
		$keyFile = tempnam(sys_get_temp_dir(), 'wppoll_');
		file_put_contents($keyFile, bin2hex(random_bytes(32)));
		chmod($keyFile, 0600);

		try {
			$vault    = new SecretVault($db, $keyFile);
			$settings = new Settings(vaultKeyFile: $keyFile);

			$repo->upsertSite([
				'slug'      => 'shop-us',
				'name'      => 'Shop US',
				'base_url'  => 'https://shop.example.com',
				'username'  => 'monitor',
				'poller_id' => 1,
				'enabled'   => true,
			]);
			$repo->upsertSite([
				'slug'      => 'blog-eu',
				'name'      => 'Blog EU',
				'base_url'  => 'https://eu.example.com',
				'username'  => 'monitor',
				'poller_id' => 2,
				'enabled'   => true,
			]);
			$vault->store('shop-us', 'AbCd 1111 EfGh 2222 IjKl 3333');

			$transport = new class implements HttpTransport {
				public function get(string $url, array $headers, int $connectTimeout, int $readTimeout, int $maxBytes, bool $verifyTls, ?string $pinnedIp = null): HttpResponse {
					if (str_ends_with($url, '/wp-json/')) {
						return new HttpResponse(200, '{"name":"Shop US","wp_version":"6.7.2","namespaces":["wp/v2"]}', [], 120.0, 140.0, 75);
					}

					return new HttpResponse(404, '{}', [], 50.0, 55.0);
				}
			};

			$guard  = new OutboundGuard([], [], 5, 10, 2097152, true, static fn (string $h): array => ['93.184.216.34']);
			$client = new WordPressClient($transport, $guard, $settings->userAgent, $settings);
			$poller = new FleetPoller($repo, $vault, $client, new AdaptivePollerSizer(), $settings);

			$run = $poller->pollFleet(1, 1, 1, false);
			$this->assertSame(1, $run['polled']);
			$this->assertSame(1, $run['healthy']);

			$snaps = $repo->loadSnapshots(1);
			$this->assertCount(1, $snaps);
			$this->assertSame('shop-us', $snaps[0]->slug);

			$pollerState = $repo->loadPollerState(1);
			$this->assertSame(1, $pollerState['lastRunSites']);
			$this->assertGreaterThanOrEqual(2, $pollerState['recommendedConcurrency']);

			$probe = $poller->probeSite('shop-us', false);
			$this->assertNotNull($probe);
			$this->assertSame(SiteMetrics::STATUS_HEALTHY, $probe->status);
			$this->assertNull($poller->probeSite('missing-site', false));
		} finally {
			@unlink($keyFile);
		}
	}
}
