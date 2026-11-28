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
use Somethingwithproof\WordPress\Cli\CliRunner;
use Somethingwithproof\WordPress\Client\HttpResponse;
use Somethingwithproof\WordPress\Client\HttpTransport;
use Somethingwithproof\WordPress\Client\WordPressClient;
use Somethingwithproof\WordPress\Config\ConfigSchema;
use Somethingwithproof\WordPress\Config\YamlXmlCodec;
use Somethingwithproof\WordPress\Db\MemoryDbAdapter;
use Somethingwithproof\WordPress\Integration\ApiResources;
use Somethingwithproof\WordPress\Integration\CascProvider;
use Somethingwithproof\WordPress\Integration\DoctorChecks;
use Somethingwithproof\WordPress\Integration\McpAbilities;
use Somethingwithproof\WordPress\Metrics\AdaptivePollerSizer;
use Somethingwithproof\WordPress\Metrics\FleetAnalyzer;
use Somethingwithproof\WordPress\Metrics\SiteMetrics;
use Somethingwithproof\WordPress\Poller\FleetPoller;
use Somethingwithproof\WordPress\Repository\SiteRepository;
use Somethingwithproof\WordPress\Security\OutboundGuard;
use Somethingwithproof\WordPress\Security\SecretVault;
use Somethingwithproof\WordPress\Security\SecurityException;
use Somethingwithproof\WordPress\Settings;

final class EdgeCasesAndCoverageTest extends TestCase {
	public function testDoctorChecksAllSeverityBranches(): void {
		$db      = new MemoryDbAdapter();
		$repo    = new SiteRepository($db);
		$keyFile = tempnam(sys_get_temp_dir(), 'wpdoc_');
		file_put_contents($keyFile, bin2hex(random_bytes(32)));
		chmod($keyFile, 0600);

		try {
			$settings = new Settings(vaultKeyFile: $keyFile);
			$vault    = new SecretVault($db, $keyFile);

			// 1. All healthy -> all 4 checks return 'ok'.
			$repo->saveSnapshot(SiteMetrics::fromObservation([
				'slug'          => 'healthy-wp',
				'siteName'      => 'Healthy',
				'url'           => 'https://healthy.example.com',
				'wpVersion'     => '6.7.2',
				'ttfbMs'        => 120.0,
				'autoloadBytes' => 100000,
				'tlsExpiryDays' => 80,
			], $settings));

			$okChecks = DoctorChecks::buildChecks(static fn (): SecretVault => $vault, static fn (): SiteRepository => $repo, static fn (): Settings => $settings, 'run');

			foreach ($okChecks as $check) {
				$this->assertSame('ok', $check['status'], $check['id']);
			}

			// 2. Degraded fleet -> warn statuses for fleet, cron/autoload, TLS.
			$repo->saveSnapshot(SiteMetrics::fromObservation([
				'slug'                 => 'warn-wp',
				'siteName'             => 'Warn',
				'url'                  => 'https://warn.example.com',
				'wpVersion'            => '6.7.2',
				'ttfbMs'               => 220.0,
				'autoloadBytes'        => 950000,
				'cronOverdueCount'     => 2,
				'cronOldestLagSeconds' => 950,
				'tlsExpiryDays'        => 15,
			], $settings));

			$warnChecks = DoctorChecks::buildChecks(static fn (): SecretVault => $vault, static fn (): SiteRepository => $repo, static fn (): Settings => $settings, 'run');
			$this->assertSame('ok', $warnChecks[0]['status']);
			$this->assertSame('warn', $warnChecks[1]['status']);
			$this->assertSame('warn', $warnChecks[2]['status']);
			$this->assertSame('warn', $warnChecks[3]['status']);

			// 3. Critical fleet + unreadable keyfile -> fail statuses across all 4 checks.
			$repo->saveSnapshot(SiteMetrics::fromObservation([
				'slug'                 => 'fail-wp',
				'siteName'             => 'Fail',
				'url'                  => 'https://fail.example.com',
				'wpVersion'            => '6.5.0',
				'ttfbMs'               => 3000.0,
				'siteHealthCritical'   => 1,
				'autoloadBytes'        => 3500000,
				'cronOverdueCount'     => 30,
				'cronOldestLagSeconds' => 4000,
				'tlsExpiryDays'        => 2,
			], $settings));

			$badVault   = new SecretVault($db, '/nonexistent/vault.key');
			$failChecks = DoctorChecks::buildChecks(static fn (): SecretVault => $badVault, static fn (): SiteRepository => $repo, static fn (): Settings => $settings, 'run');
			$this->assertSame('fail', $failChecks[0]['status']);
			$this->assertSame('fail', $failChecks[1]['status']);
			$this->assertSame('fail', $failChecks[2]['status']);
			$this->assertSame('fail', $failChecks[3]['status']);
		} finally {
			@unlink($keyFile);
		}
	}

	public function testFleetAnalyzerEmptyZeroMadAndAllApdexBands(): void {
		$settings = new Settings();
		$analyzer = new FleetAnalyzer($settings);

		// Empty fleet.
		$empty = $analyzer->analyze([]);
		$this->assertSame(0, $empty['counts']['sites_total']);
		$this->assertSame('unacceptable', $empty['apdex']['rating']);
		$this->assertSame(0.0, SiteMetrics::computeApdex([], 500));

		// Zero-MAD constant baseline + extreme outlier triggers MAD==0 fallback detection.
		$flatSites = [];

		for ($i = 0; $i < 6; $i++) {
			$flatSites[] = SiteMetrics::fromObservation(['slug' => 'flat-' . $i, 'ttfbMs' => 200.0], $settings);
		}

		$flatSites[] = SiteMetrics::fromObservation(['slug' => 'spike-1', 'ttfbMs' => 1500.0], $settings);
		$flatSites[] = SiteMetrics::unreachable('down-1', 'Down', 'https://down.example.com', 1, 'Timeout', time());

		$res = $analyzer->analyze($flatSites);
		$this->assertSame(0.0, $res['latency']['madMs']);
		$this->assertSame(1, $res['latency']['anomalyCount']);
		$this->assertSame('spike-1', $res['latency']['anomalies'][0]['slug']);
		$this->assertSame(1, $res['counts']['sites_unreachable']);

		// Cover Apdex rating bands: poor (~0.50), fair (~0.75), good (~0.90), excellent (~1.0).
		$poor = $analyzer->analyze([
			SiteMetrics::fromObservation(['slug' => 'p1', 'ttfbMs' => 1000.0], $settings),
			SiteMetrics::fromObservation(['slug' => 'p2', 'ttfbMs' => 1000.0], $settings),
		]);
		$this->assertSame('poor', $poor['apdex']['rating']);

		$fair = $analyzer->analyze([
			SiteMetrics::fromObservation(['slug' => 'f1', 'ttfbMs' => 100.0], $settings),
			SiteMetrics::fromObservation(['slug' => 'f2', 'ttfbMs' => 1000.0], $settings),
		]);
		$this->assertSame('fair', $fair['apdex']['rating']);

		$good = $analyzer->analyze([
			SiteMetrics::fromObservation(['slug' => 'g1', 'ttfbMs' => 100.0], $settings),
			SiteMetrics::fromObservation(['slug' => 'g2', 'ttfbMs' => 100.0], $settings),
			SiteMetrics::fromObservation(['slug' => 'g3', 'ttfbMs' => 100.0], $settings),
			SiteMetrics::fromObservation(['slug' => 'g4', 'ttfbMs' => 100.0], $settings),
			SiteMetrics::fromObservation(['slug' => 'g5', 'ttfbMs' => 1000.0], $settings),
		]);
		$this->assertSame('good', $good['apdex']['rating']);
	}

	public function testCascProviderPlanApplyCreateUpdateAndErrors(): void {
		$db       = new MemoryDbAdapter();
		$repo     = new SiteRepository($db);
		$settings = new Settings();
		$saved    = $settings;

		$repo->upsertSite([
			'slug'     => 'existing-wp',
			'name'     => 'Existing',
			'base_url' => 'https://existing.example.com',
			'username' => 'ro',
		]);

		// Invalid registrar without register() returns false.
		$this->assertFalse(CascProvider::register(new \stdClass(), static fn (): Settings => $saved, static fn (Settings $s): bool => true, static fn (): SiteRepository => $repo));

		$desc = CascProvider::descriptor(
			static function () use (&$saved): Settings {
				return $saved;
			},
			static function (Settings $s) use (&$saved): bool {
				$saved = $s;

				return true;
			},
			static fn (): SiteRepository => $repo
		);

		$this->assertNotEmpty(($desc['validate'])(['unknown' => 1]));
		$errPlan = ($desc['plan'])(['unknown' => 1], []);
		$this->assertSame('error', $errPlan[0]['operation']);

		$errApply = ($desc['apply'])(['unknown' => 1], 'hash', []);
		$this->assertFalse($errApply['ok']);

		// Create new site + update existing site in one plan/apply.
		$desired = [
			'wordpress_poll_interval' => 450,
			'sites'                   => [
				[
					'slug'       => 'existing-wp',
					'name'       => 'Existing Renamed',
					'base_url'   => 'https://existing.example.com',
					'username'   => 'ro',
					'secret_ref' => 'vault:wordpress:existing-wp',
				],
				[
					'slug'       => 'new-wp',
					'name'       => 'New Site',
					'base_url'   => 'https://new.example.com',
					'username'   => 'ro2',
					'secret_ref' => 'vault:wordpress:new-wp',
				],
			],
		];

		$plan     = ($desc['plan'])($desired, []);
		$planHash = YamlXmlCodec::planHash($desired, $plan);
		$applied  = ($desc['apply'])($desired, $planHash, []);

		$this->assertTrue($applied['ok']);
		$this->assertSame(2, $applied['sitesApplied']);
		$this->assertSame(450, $saved->pollInterval);
		$this->assertSame('Existing Renamed', $repo->findSite('existing-wp')['name']);
		$this->assertNotNull($repo->findSite('new-wp'));
	}

	public function testCliRunnerFileOptionsErrorPathsAndYamlXmlEdgeCases(): void {
		$db       = new MemoryDbAdapter();
		$repo     = new SiteRepository($db);
		$settings = new Settings();
		$saved    = $settings;

		$transport = new class implements HttpTransport {
			public function get(string $url, array $headers, int $connectTimeout, int $readTimeout, int $maxBytes, bool $verifyTls, ?string $pinnedIp = null): HttpResponse {
				return new HttpResponse(200, '{"name":"Site","wp_version":"6.7.2"}', [], 80.0, 90.0, 40);
			}
		};
		$guard  = new OutboundGuard([], [], 5, 10, 2097152, true, static fn (string $h): array => ['93.184.216.34']);
		$poller = new FleetPoller($repo, new SecretVault($db, ''), new WordPressClient($transport, $guard), new AdaptivePollerSizer(), $settings);
		$runner = new CliRunner(
			static fn (): Settings => $saved,
			static function (Settings $s) use (&$saved): bool {
				$saved = $s;

				return true;
			},
			$repo,
			$poller
		);

		// Export to temp file, validate, plan in text format, probe JSON + missing --site, invalid health format.
		$tmpYaml = tempnam(sys_get_temp_dir(), 'wpcli_');
		$exported = $runner->run(['export', '--format=yaml'])['stdout'];
		file_put_contents($tmpYaml, $exported);

		try {
			$this->assertSame(0, $runner->run(['validate', '--file', $tmpYaml])['exitCode']);
			$this->assertSame(0, $runner->run(['plan', '--file=' . $tmpYaml])['exitCode']);
			$this->assertSame(1, $runner->run(['validate', '--file=/nonexistent/file.yaml'])['exitCode']);
			$this->assertSame(1, $runner->run(['validate'], "settings:\n  unknown_key: 1\n")['exitCode']);
			$this->assertSame(1, $runner->run(['plan'], "settings:\n  unknown_key: 1\n")['exitCode']);
			$this->assertSame(2, $runner->run(['health', '--format=xml'])['exitCode']);
			$this->assertSame(2, $runner->run(['probe'])['exitCode']);
			$this->assertSame(1, $runner->run(['probe', '--site=nope'])['exitCode']);

			$repo->upsertSite([
				'slug'     => 'cli-site',
				'name'     => 'CLI Site',
				'base_url' => 'https://cli.example.com',
				'username' => 'ro',
			]);
			$probeJson = $runner->run(['probe', '--site=cli-site', '--format=json']);
			$this->assertSame(0, $probeJson['exitCode']);
			$this->assertStringContainsString('"cli-site"', $probeJson['stdout']);
		} finally {
			@unlink($tmpYaml);
		}

		// Empty and malformed XML/YAML decoding.
		try {
			YamlXmlCodec::decode("   ");
			$this->fail('Expected empty config rejection');
		} catch (\InvalidArgumentException) {
			$this->addToAssertionCount(1);
		}

		try {
			YamlXmlCodec::decode('<unclosed>');
			$this->fail('Expected malformed XML rejection');
		} catch (\InvalidArgumentException) {
			$this->addToAssertionCount(1);
		}

		// Double-quoted YAML scalars and comments.
		$parsed = YamlXmlCodec::decode("# comment\nsettings:\n  wordpress_user_agent: \"Custom-Agent/1.0\"\n  wordpress_uninstall_keep_tables: true\nsites: []\n");
		$this->assertSame('Custom-Agent/1.0', $parsed['settings']['wordpress_user_agent']);
		$this->assertTrue($parsed['settings']['wordpress_uninstall_keep_tables']);
	}

	public function testOutboundGuardSettingsRepositoryAndSetupEdgeCases(): void {
		// Settings clamping edge cases (crit < warn, tlsCrit > tlsWarn, maxConc < minConc, bool strings).
		$s = Settings::fromRow([
			'wordpress_autoload_warn_bytes'   => 2000000,
			'wordpress_autoload_crit_bytes'   => 500000,
			'wordpress_tls_warn_days'         => 10,
			'wordpress_tls_crit_days'         => 30,
			'wordpress_min_concurrency'       => 16,
			'wordpress_max_concurrency'       => 4,
			'wordpress_allowlist_hosts'       => ' a.internal , *.b.internal ',
			'wordpress_allowlist_cidrs'       => ' 10.0.0.0/8 ',
			'wordpress_uninstall_keep_tables' => 'on',
		]);
		$this->assertSame(2000000, $s->autoloadCritBytes);
		$this->assertSame(10, $s->tlsCritDays);
		$this->assertSame(16, $s->maxConcurrency);
		$this->assertSame(['a.internal', '*.b.internal'], $s->parsedAllowlistHosts());
		$this->assertSame(['10.0.0.0/8'], $s->parsedAllowlistCidrs());
		$this->assertTrue($s->uninstallKeepTables);
		$this->assertSame('on', $s->toCactiSettingsMap()['wordpress_uninstall_keep_tables']);

		// OutboundGuard IPv6, CIDR invalid masks, exact host allowlist.
		$guard = new OutboundGuard(['exact.internal'], ['fc00::/7']);
		$this->assertTrue($guard->isHostAllowlisted('exact.internal'));
		$this->assertTrue($guard->isIpAllowlisted('fd12:3456::1'));
		$this->assertTrue($guard->isBlockedIp('not-an-ip'));
		$this->assertFalse(OutboundGuard::ipInCidr('10.0.0.1', 'invalid-cidr'));
		$this->assertFalse(OutboundGuard::ipInCidr('10.0.0.1', '10.0.0.0/99'));
		$this->assertFalse(OutboundGuard::ipInCidr('10.0.0.1', '::1/128'));

		// ConfigSchema site validation edge cases.
		$siteErrors = ConfigSchema::validateSite([
			'slug'            => 'BAD SLUG',
			'name'            => '',
			'base_url'        => 'http://insecure.example.com',
			'username'        => '',
			'secret_ref'      => 'raw-secret',
			'poller_id'       => 0,
			'telemetry_path'  => 'no-leading-slash',
			'timeout_connect' => 99,
			'timeout_read'    => 99,
			'apdex_t_ms'      => 1,
		]);
		$this->assertCount(10, $siteErrors);

		// Duplicate slugs and non-array sites entry.
		$dupErrors = ConfigSchema::validate([
			'sites' => [
				['slug' => 'dup-1', 'name' => 'A', 'base_url' => 'https://a.example.com', 'username' => 'u', 'secret_ref' => 'vault:wordpress:dup-1'],
				['slug' => 'dup-1', 'name' => 'B', 'base_url' => 'https://b.example.com', 'username' => 'u', 'secret_ref' => 'vault:wordpress:dup-1'],
			],
		]);
		$this->assertNotEmpty($dupErrors);

		// AdaptivePollerSizer convergence downward and invalid shard index.
		$sizer = new AdaptivePollerSizer();
		$down  = $sizer->size(10, 300, 100.0, 10.0, ['recommendedConcurrency' => 12, 'ewmaLatencyMs' => 100.0, 'codelDropCount' => 1], 500, 2, 32);
		$this->assertSame(11, $down['recommendedConcurrency']);
		$this->assertSame(0, $down['codelDropCount']);

		// Repository upsert update + delete + invalid upsert exception.
		$repo = new SiteRepository(new MemoryDbAdapter());
		$this->assertTrue($repo->upsertSite(['slug' => 'up-1', 'name' => 'V1', 'base_url' => 'https://v1.example.com', 'username' => 'u']));
		$this->assertTrue($repo->upsertSite(['slug' => 'up-1', 'name' => 'V2', 'base_url' => 'https://v1.example.com', 'username' => 'u']));
		$this->assertSame('V2', $repo->findSite('up-1')['name']);
		$this->assertTrue($repo->deleteSite('up-1'));
		$this->assertNull($repo->findSite('up-1'));

		// McpAbilities invalid registrar + userHasViewRealm without DB returns false.
		McpAbilities::register(new \stdClass(), static fn (): SiteRepository => $repo, static fn (): Settings => $s, static fn (int $u): bool => false);
		$this->assertFalse(McpAbilities::userHasViewRealm(0));

		// ApiResources list handlers on empty repo.
		$api = ApiResources::build(static fn (): SiteRepository => $repo, static fn (): Settings => $s);
		$this->assertSame([], ($api[0]['handlers']['list'])());
		$this->assertSame([], ($api[1]['handlers']['list'])());

		// Setup denied 403 path and wordpress_save_settings without DB returns false.
		$GLOBALS['__wp_current_page']   = 'wordpress_admin.php';
		$GLOBALS['__wp_allowed_realms'] = [];
		$_SESSION['sess_user_id']       = 5;
		$this->assertFalse(wordpress_page_start());
		$this->assertFalse(wordpress_save_settings($s));

		$this->expectException(\InvalidArgumentException::class);
		$repo->upsertSite(['slug' => 'INVALID!']);
	}
}
