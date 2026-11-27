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

namespace Somethingwithproof\WordPress\Tests\Integration;

use PHPUnit\Framework\TestCase;
use Somethingwithproof\WordPress\Metrics\SiteMetrics;
use Somethingwithproof\WordPress\Pages;
use Somethingwithproof\WordPress\Schema;
use Somethingwithproof\WordPress\Settings;

final class MariaDbIntegrationTest extends TestCase {
	public function testSchemaHooksRealmsVaultSnapshotsAndScriptServerOnLiveMariaDb(): void {
		$schema = new Schema(false);
		$this->assertTrue($schema->isCurrent());
		$this->assertTrue($schema->hooksRegistered());

		// Repeated upgrade is idempotent.
		$this->assertTrue(plugin_wordpress_upgrade());

		$realmCount = (int) db_fetch_cell_prepared('SELECT COUNT(*) FROM plugin_realms WHERE plugin = ?', ['wordpress']);
		$this->assertSame(count(Pages::realms()), $realmCount);

		$keyFile = tempnam(sys_get_temp_dir(), 'cacti_wp_ci_key_');
		$this->assertIsString($keyFile);
		file_put_contents($keyFile, bin2hex(random_bytes(32)));
		chmod($keyFile, 0600);

		try {
			$updated = Settings::fromRow([
				'wordpress_vault_key_file'      => $keyFile,
				'wordpress_poll_interval'       => 300,
				'wordpress_default_apdex_t_ms'  => 500,
				'wordpress_autoload_warn_bytes' => 819200,
				'wordpress_autoload_crit_bytes' => 2097152,
			]);
			$this->assertTrue(wordpress_save_settings($updated));
			$this->assertSame($keyFile, wordpress_settings()->vaultKeyFile);

			$repo  = wordpress_repository();
			$vault = wordpress_vault();

			$this->assertTrue($repo->upsertSite([
				'slug'      => 'ci-wp-site',
				'name'      => 'CI WordPress Site',
				'base_url'  => 'https://ci-wp.example.com',
				'username'  => 'cacti-monitor',
				'poller_id' => 1,
				'enabled'   => true,
			]));
			$this->assertTrue($vault->store('ci-wp-site', 'AbCd 1234 EfGh 5678 IjKl 9012'));
			$this->assertSame('AbCd 1234 EfGh 5678 IjKl 9012', $vault->retrieve('ci-wp-site'));

			$snapshot = SiteMetrics::fromObservation([
				'slug'                   => 'ci-wp-site',
				'siteName'               => 'CI WordPress Site',
				'url'                    => 'https://ci-wp.example.com',
				'pollerId'               => 1,
				'wpVersion'              => '6.7.2',
				'ttfbMs'                 => 180.5,
				'ttfbP95Ms'              => 210.0,
				'apdexTMs'               => 500,
				'ttfbSamples'            => [180.5, 195.0, 210.0],
				'siteHealthGood'         => 5,
				'siteHealthRecommended'  => 0,
				'siteHealthCritical'     => 0,
				'pluginsActive'          => 14,
				'pluginsUpdatesPending'  => 0,
				'themesActive'           => 1,
				'themesUpdatesPending'   => 0,
				'cronOverdueCount'       => 0,
				'cronOldestLagSeconds'   => 0,
				'autoloadBytes'          => 245760,
				'autoloadRows'           => 312,
				'objectCacheHitRatio'    => 97.4,
				'opcacheHitRatio'        => 99.1,
				'opcacheMemoryUsedPct'   => 48.2,
				'tlsExpiryDays'          => 64,
				'httpErrorRatePct'       => 0.1,
			], $updated);

			$this->assertTrue($repo->saveSnapshot($snapshot));
			$loaded = $repo->findSnapshot('ci-wp-site');
			$this->assertNotNull($loaded);
			$this->assertSame(SiteMetrics::STATUS_HEALTHY, $loaded->status);
			$this->assertSame(64, $loaded->tlsExpiryDays);

			// Verify script-server output against live MariaDB snapshot.
			$ssOut = ss_wordpress_stats(1);
			$this->assertStringContainsString('sites_total:1', $ssOut);
			$this->assertStringContainsString('sites_healthy:1', $ssOut);
			$this->assertStringContainsString('tls_min_expiry_days:64', $ssOut);

			// Verify canonical ecosystem hooks.
			$checks = wordpress_doctor_register_checks(['mode' => 'run', 'plugin' => 'wordpress']);
			$this->assertIsArray($checks);
			$this->assertCount(4, $checks);

			foreach ($checks as $check) {
				$this->assertSame('wordpress', $check['plugin']);
				$this->assertSame('ok', $check['status']);
			}

			$debug = wordpress_doctor_register_debug_info(['plugin' => 'wordpress']);
			$this->assertIsArray($debug);
			$this->assertCount(1, $debug);
			$this->assertSame('wordpress.overview', $debug[0]['id']);
			$this->assertStringNotContainsString('AbCd 1234', json_encode($debug, JSON_THROW_ON_ERROR));

			$resources = wordpress_api_register_resources([]);
			$this->assertIsArray($resources);
			$this->assertCount(2, $resources);
			$this->assertSame('wordpressSites', $resources[0]['collection']);
			$this->assertSame('wordpressHealth', $resources[1]['collection']);

			// Clean up CI test rows.
			$this->assertTrue($repo->deleteSite('ci-wp-site'));
			$this->assertTrue($vault->delete('ci-wp-site'));
		} finally {
			@unlink($keyFile);
		}
	}
}
