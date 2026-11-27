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
use Somethingwithproof\WordPress\Db\DbAdapter;
use Somethingwithproof\WordPress\Db\MemoryDbAdapter;
use Somethingwithproof\WordPress\Metrics\SiteMetrics;
use Somethingwithproof\WordPress\Pages;
use Somethingwithproof\WordPress\Schema;
use Somethingwithproof\WordPress\Settings;

final class SetupHooksAndScriptServerTest extends TestCase {
	protected function setUp(): void {
		$GLOBALS['__wp_options']        = [];
		$GLOBALS['__wp_log']            = [];
		$GLOBALS['__wp_enabled']        = true;
		$GLOBALS['__wp_current_page']   = 'wordpress_view.php';
		$GLOBALS['__wp_allowed_realms'] = [];
		$_SESSION                       = [];
		wordpress_reset_runtime(new MemoryDbAdapter());
	}

	public function testMetadataPagesSettingsAndRealmInheritance(): void {
		$info = plugin_wordpress_version();
		$this->assertSame('wordpress', $info['name']);
		$this->assertStringContainsString('remote_collect:1', $info['capabilities']);
		$this->assertTrue(wordpress_php_supported());
		$this->assertFalse(wordpress_refuse_unsupported_php());

		$this->assertCount(3, Pages::realms());
		$this->assertCount(3, Pages::files());
		$this->assertArrayHasKey('wordpress_view.php:', Pages::navigation());
		$this->assertArrayHasKey('wordpress_vault_key_file', Settings::form());
		$this->assertArrayHasKey('plugin_wordpress_sites', Schema::tables());
		$this->assertArrayHasKey('plugin_wordpress_secrets', Schema::tables());

		$GLOBALS['menu']              = [];
		$GLOBALS['tabs']              = [];
		$GLOBALS['settings']          = [];
		$GLOBALS['__wp_current_page'] = 'index.php';
		wordpress_config_arrays();
		$this->assertArrayHasKey('plugins/wordpress/wordpress_view.php', $GLOBALS['menu']['Utilities']);

		wordpress_config_settings();
		$this->assertArrayHasKey('wordpress', $GLOBALS['tabs']);

		$nav = wordpress_draw_navigation_text([]);
		$this->assertArrayHasKey('wordpress_admin.php:', $nav);

		// 3-tier realm inheritance: Admin > Operator > View.
		$GLOBALS['__wp_current_page'] = 'wordpress_view.php';
		$GLOBALS['user_auth_realm_filenames'] = [
			'wordpress_view.php'     => 101,
			'wordpress_operator.php' => 102,
			'wordpress_admin.php'    => 103,
		];
		$_SESSION['sess_user_id']       = 1;
		$GLOBALS['__wp_allowed_realms'] = [103];
		$this->assertTrue(wordpress_page_allowed());
		$this->assertSame(103, $GLOBALS['user_auth_realm_filenames']['wordpress_view.php']);
		$this->assertSame(103, $GLOBALS['user_auth_realm_filenames']['wordpress_operator.php']);
		$this->assertTrue(wordpress_page_start());

		// Operator inherits View.
		$GLOBALS['user_auth_realm_filenames'] = [
			'wordpress_view.php'     => 101,
			'wordpress_operator.php' => 102,
			'wordpress_admin.php'    => 103,
		];
		$GLOBALS['__wp_allowed_realms'] = [102];
		$this->assertTrue(wordpress_page_allowed());
		$this->assertSame(102, $GLOBALS['user_auth_realm_filenames']['wordpress_view.php']);

		// Unauthenticated session defers view/operator realm access.
		$_SESSION = [];
		wordpress_auth_alternate_realms();
		$this->assertSame(-1, $GLOBALS['user_auth_realm_filenames']['wordpress_view.php']);
	}

	public function testScriptServerOutputAndUnknownFallbackOnError(): void {
		$repo = wordpress_repository();
		$repo->upsertSite([
			'slug'      => 'ss-alpha',
			'name'      => 'SS Alpha',
			'base_url'  => 'https://ss.example.com',
			'username'  => 'monitor',
			'poller_id' => 1,
		]);
		$repo->saveSnapshot(SiteMetrics::fromObservation([
			'slug'                  => 'ss-alpha',
			'siteName'              => 'SS Alpha',
			'url'                   => 'https://ss.example.com',
			'pollerId'              => 1,
			'wpVersion'             => '6.7.2',
			'ttfbMs'                => 225.5,
			'ttfbP95Ms'             => 225.5,
			'pluginsUpdatesPending' => 2,
			'cronOverdueCount'      => 1,
			'autoloadBytes'         => 900000,
			'tlsExpiryDays'         => 41,
		], new Settings()));

		$out = ss_wordpress_stats(1);
		$this->assertSame(
			'sites_total:1 sites_healthy:0 sites_degraded:1 sites_critical:0 updates_pending:2 cron_overdue_total:1 autoload_bloat_sites:1 ttfb_p95_ms:225.50 tls_min_expiry_days:41',
			$out
		);

		// When database adapter throws, script server emits 'U' for every metric (never 0).
		$failingDb = new class implements DbAdapter {
			public function execute(string $sql, array $params = []): bool {
				throw new \RuntimeException('DB offline');
			}
			public function fetchCell(string $sql, array $params = []): mixed {
				throw new \RuntimeException('DB offline');
			}
			public function fetchRow(string $sql, array $params = []): ?array {
				throw new \RuntimeException('DB offline');
			}
			public function fetchAssoc(string $sql, array $params = []): array {
				throw new \RuntimeException('DB offline');
			}
		};

		wordpress_reset_runtime($failingDb);
		$this->assertSame(ss_wordpress_stats_unknown(), ss_wordpress_stats(1));
	}

	public function testReplicateOutPollerBottomAndSetupHooks(): void {
		$primaryDb = new MemoryDbAdapter();
		$remoteDb  = new MemoryDbAdapter();
		$transport = new class implements HttpTransport {
			public function get(string $url, array $headers, int $connectTimeout, int $readTimeout, int $maxBytes, bool $verifyTls, ?string $pinnedIp = null): HttpResponse {
				return new HttpResponse(200, '{"name":"Rep Site","wp_version":"6.7.2"}', [], 100.0, 110.0, 50);
			}
		};
		wordpress_reset_runtime($primaryDb, $transport);

		wordpress_repository()->upsertSite([
			'slug'      => 'remote-site',
			'name'      => 'Remote Site',
			'base_url'  => 'https://remote.example.com',
			'username'  => 'monitor',
			'poller_id' => 2,
		]);

		$repResult = wordpress_replicate_out([
			'class'            => 'all',
			'remote_poller_id' => 2,
			'remote_adapter'   => $remoteDb,
		]);
		$this->assertSame(1, $repResult['wordpress_replicated']);

		// Poller bottom runs cleanly on poller 1 (0 sites on poller 1 -> fast no-op).
		wordpress_poller_bottom();
		$this->assertNotEmpty($GLOBALS['__wp_log']);

		// Hook wrappers do not echo $context keys.
		$checks = wordpress_doctor_register_checks(['mode' => 'run', 'plugin' => 'wordpress']);
		$this->assertIsArray($checks);
		$this->assertArrayNotHasKey('mode', $checks);
		$this->assertCount(4, $checks);

		$debug = wordpress_doctor_register_debug_info(['plugin' => 'wordpress']);
		$this->assertIsArray($debug);
		$this->assertArrayNotHasKey('plugin', $debug);
		$this->assertSame('wordpress.overview', $debug[0]['id']);

		$api = wordpress_api_register_resources([]);
		$this->assertIsArray($api);
		$this->assertCount(2, $api);

		$cascBag = [];
		$cascReg = new class($cascBag) {
			/** @param list<array<string, mixed>> $bag */
			public function __construct(public array &$bag) {}
			/** @param array<string, mixed> $desc */
			public function register(array $desc): void {
				$this->bag[] = $desc;
			}
		};
		wordpress_casc_register_providers($cascReg);
		$this->assertCount(1, $cascBag);

		$mcpBag = [];
		$mcpReg = new class($mcpBag) {
			/** @param array<string, mixed> $bag */
			public function __construct(public array &$bag) {}
			/** @param array<string, mixed> $def */
			public function register(string $id, array $def): void {
				$this->bag[$id] = $def;
			}
		};
		wordpress_abilities_register($mcpReg);
		$this->assertCount(3, $mcpBag);
	}
}
