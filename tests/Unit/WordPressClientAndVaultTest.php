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
use Somethingwithproof\WordPress\Client\CurlHttpTransport;
use Somethingwithproof\WordPress\Client\HttpResponse;
use Somethingwithproof\WordPress\Client\HttpTransport;
use Somethingwithproof\WordPress\Client\WordPressClient;
use Somethingwithproof\WordPress\Db\MemoryDbAdapter;
use Somethingwithproof\WordPress\Metrics\SiteMetrics;
use Somethingwithproof\WordPress\Security\OutboundGuard;
use Somethingwithproof\WordPress\Security\SecretVault;
use Somethingwithproof\WordPress\Security\SecurityException;
use Somethingwithproof\WordPress\Settings;

final class WordPressClientAndVaultTest extends TestCase {
	private string $keyFileRaw = '';
	private string $keyFileB64 = '';

	protected function setUp(): void {
		$this->keyFileRaw = tempnam(sys_get_temp_dir(), 'wpraw_');
		file_put_contents($this->keyFileRaw, random_bytes(32));
		chmod($this->keyFileRaw, 0600);

		$this->keyFileB64 = tempnam(sys_get_temp_dir(), 'wpb64_');
		file_put_contents($this->keyFileB64, 'base64:' . base64_encode(random_bytes(32)));
		chmod($this->keyFileB64, 0600);
	}

	protected function tearDown(): void {
		foreach ([$this->keyFileRaw, $this->keyFileB64] as $f) {
			if ($f !== '' && is_file($f)) {
				@unlink($f);
			}
		}
	}

	public function testFullReadOnlySitePollAndParsers(): void {
		$capturedHeaders = [];
		$transport       = new class($capturedHeaders) implements HttpTransport {
			/** @param list<array<string, string>> $log */
			public function __construct(public array &$log) {}

			public function get(
				string $url,
				array $headers,
				int $connectTimeout,
				int $readTimeout,
				int $maxBytes,
				bool $verifyTls,
				?string $pinnedIp = null,
			): HttpResponse {
				$this->log[] = $headers;

				if (str_ends_with($url, '/wp-json/')) {
					return new HttpResponse(
						200,
						(string) json_encode([
							'name'       => 'Acme Marketing',
							'wp_version' => '6.7.2',
							'namespaces' => ['wp/v2', 'wp-site-health/v1', 'cacti-wp/v1'],
							'routes'     => ['/wp/v2/users' => ['namespace' => 'wp/v2']],
						]),
						['x-pingback' => 'https://wp.example.com/xmlrpc.php'],
						142.5,
						160.0,
						45
					);
				}

				if (str_contains($url, '/wp-site-health/v1/tests/background-updates')) {
					return new HttpResponse(200, (string) json_encode(['status' => 'good', 'label' => 'Background updates working']), [], 90.0, 100.0);
				}

				if (str_contains($url, '/wp-site-health/v1/tests/https-status')) {
					return new HttpResponse(200, (string) json_encode(['status' => 'recommended', 'label' => 'HSTS header missing']), [], 110.0, 120.0);
				}

				if (str_contains($url, '/wp-site-health/v1/tests/')) {
					return new HttpResponse(200, (string) json_encode(['status' => 'good', 'label' => 'OK']), [], 95.0, 105.0);
				}

				if (str_ends_with($url, '/directory-sizes')) {
					return new HttpResponse(200, (string) json_encode(['total_size' => ['raw' => 524288000]]), [], 80.0, 85.0);
				}

				if (str_ends_with($url, '/wp/v2/plugins')) {
					return new HttpResponse(
						200,
						(string) json_encode([
							['plugin' => 'akismet/akismet.php', 'status' => 'active', 'version' => '5.3.0', 'update' => ['version' => '5.3.5']],
							['plugin' => 'hello.php', 'status' => 'inactive', 'version' => '1.7.2'],
						]),
						[],
						120.0,
						130.0
					);
				}

				if (str_ends_with($url, '/wp/v2/themes')) {
					return new HttpResponse(
						200,
						(string) json_encode([
							['stylesheet' => 'twentytwentyfive', 'status' => 'active', 'version' => '1.0', 'new_version' => '1.1'],
							['stylesheet' => 'twentytwentyfour', 'status' => 'inactive', 'version' => '1.2'],
						]),
						[],
						105.0,
						115.0
					);
				}

				if (str_ends_with($url, '/cacti-wp/v1/telemetry')) {
					return new HttpResponse(
						200,
						(string) json_encode([
							'wp_cron'      => ['overdue_count' => 2, 'oldest_lag_seconds' => 420],
							'autoload'     => ['bytes' => 921600, 'rows' => 640],
							'object_cache' => ['hit_ratio_pct' => 96.8],
							'opcache'      => ['hit_ratio_pct' => 99.4, 'memory_used_pct' => 61.2],
							'php_fpm'      => ['active' => 6, 'idle' => 14, 'queued' => 0],
							'http'         => ['homepage_ttfb_ms' => 165.4, 'ttfb_p95_ms' => 240.0, 'error_rate_pct' => 0.4],
							'tls_expiry_days' => 24,
						]),
						[],
						88.0,
						92.0
					);
				}

				return new HttpResponse(404, '{}', [], 50.0, 55.0);
			}
		};

		$guard  = new OutboundGuard([], [], 5, 10, 2097152, true, static fn (string $h): array => ['93.184.216.34']);
		$client = new WordPressClient($transport, $guard, 'Cacti-Plugin-WordPress/0.1.0', new Settings());

		$metrics = $client->pollSite([
			'slug'     => 'acme-mkt',
			'name'     => 'Acme',
			'base_url' => 'https://wp.example.com',
			'username' => 'cacti-readonly',
		], 'AbCd 1234 EfGh 5678 IjKl 9012');

		$this->assertSame('acme-mkt', $metrics->slug);
		$this->assertSame('Acme Marketing', $metrics->siteName);
		$this->assertSame('6.7.2', $metrics->wpVersion);
		$this->assertSame(SiteMetrics::STATUS_DEGRADED, $metrics->status);
		$this->assertSame(4, $metrics->siteHealthGood);
		$this->assertSame(1, $metrics->siteHealthRecommended);
		$this->assertSame(0, $metrics->siteHealthCritical);
		$this->assertSame(1, $metrics->pluginsActive);
		$this->assertSame(1, $metrics->pluginsInactive);
		$this->assertSame(1, $metrics->pluginsUpdatesPending);
		$this->assertSame(1, $metrics->themesActive);
		$this->assertSame(1, $metrics->themesUpdatesPending);
		$this->assertSame(2, $metrics->cronOverdueCount);
		$this->assertSame(921600, $metrics->autoloadBytes);
		$this->assertSame('warning', $metrics->autoloadSeverity());
		$this->assertSame('warning', $metrics->cronSeverity());
		$this->assertSame('warning', $metrics->tlsSeverity());
		$this->assertSame(96.8, $metrics->objectCacheHitRatio);
		$this->assertSame(99.4, $metrics->opcacheHitRatio);
		$this->assertSame(6, $metrics->phpFpmActive);
		$this->assertTrue($metrics->xmlrpcExposed);
		$this->assertTrue($metrics->restUsersExposed);

		$this->assertNotEmpty($capturedHeaders);
		$this->assertSame('Cacti-Plugin-WordPress/0.1.0', $capturedHeaders[0]['User-Agent']);
		$this->assertStringStartsWith('Basic ', $capturedHeaders[0]['Authorization']);
	}

	public function testClientHandlesDiscoveryFailureAndSecurityBlockGracefully(): void {
		$transport = new class implements HttpTransport {
			public function get(string $url, array $headers, int $connectTimeout, int $readTimeout, int $maxBytes, bool $verifyTls, ?string $pinnedIp = null): HttpResponse {
				return new HttpResponse(503, 'Service Unavailable', [], 310.0, 320.0, 12);
			}
		};

		$guard  = new OutboundGuard([], [], 5, 10, 2097152, true, static fn (string $h): array => $h === 'down.example.com' ? ['93.184.216.34'] : ['127.0.0.1']);
		$client = new WordPressClient($transport, $guard);

		$down = $client->pollSite(['slug' => 'down-site', 'name' => 'Down', 'base_url' => 'https://down.example.com']);
		$this->assertSame(SiteMetrics::STATUS_UNREACHABLE, $down->status);
		$this->assertStringContainsString('503', $down->lastError);
		$this->assertSame(12, $down->tlsExpiryDays);

		$blocked = $client->pollSite(['slug' => 'ssrf-site', 'name' => 'SSRF', 'base_url' => 'https://local.example.com']);
		$this->assertSame(SiteMetrics::STATUS_UNREACHABLE, $blocked->status);
		$this->assertStringContainsString('blocked', strtolower($blocked->lastError));
	}

	public function testSecretVaultSupportsRawAndBase64KeyfilesAndLifecycle(): void {
		$db = new MemoryDbAdapter();

		foreach ([$this->keyFileRaw, $this->keyFileB64] as $kf) {
			$vault  = new SecretVault($db, $kf);
			$health = $vault->healthStatus();
			$this->assertTrue($health['configured']);
			$this->assertTrue($health['readable']);
			$this->assertTrue($health['permissionsOk']);
			$this->assertSame(16, strlen($health['keyFingerprint']));

			$this->assertTrue($vault->store('site-alpha', 'Pass 1111 2222 3333 4444 5555'));
			$this->assertTrue($vault->hasSecret('site-alpha'));
			$this->assertSame('Pass 1111 2222 3333 4444 5555', $vault->retrieve('site-alpha'));
			$this->assertSame(1, $vault->countStoredSecrets());
			$this->assertTrue($vault->delete('site-alpha'));
			$this->assertFalse($vault->hasSecret('site-alpha'));
			$this->assertNull($vault->retrieve('site-alpha'));
		}

		// Missing keyfile reports unconfigured/unhealthy cleanly.
		$unconfigured = new SecretVault($db, '');
		$this->assertFalse($unconfigured->healthStatus()['configured']);

		$missing = new SecretVault($db, '/nonexistent/path/keyfile.key');
		$this->assertFalse($missing->healthStatus()['readable']);

		// Invalid envelope / empty plaintext throw SecurityException.
		$vault = new SecretVault($db, $this->keyFileRaw);

		try {
			$vault->encrypt('site-alpha', '');
			$this->fail('Expected empty plaintext rejection');
		} catch (SecurityException) {
			$this->addToAssertionCount(1);
		}

		$this->expectException(SecurityException::class);
		$vault->decrypt('site-alpha', 'v1:bad:envelope');
	}

	public function testParserHelpersAndCertExpiryExtraction(): void {
		$resp = new HttpResponse(200, 'abc', ['content-type' => 'application/json']);
		$this->assertSame(3, $resp->bytes());
		$this->assertSame('application/json', $resp->header('Content-Type'));
		$this->assertNull($resp->header('X-Missing'));

		$disc = WordPressClient::parseDiscoveryPayload(
			(string) json_encode(['name' => 'Blog', 'generator' => 'WordPress 6.6.1', 'authentication' => ['xmlrpc' => true]]),
			[]
		);
		$this->assertSame('6.6.1', $disc['wpVersion']);
		$this->assertTrue($disc['xmlrpcExposed']);

		$discHeader = WordPressClient::parseDiscoveryPayload('{}', ['x-wp-version' => '6.5.4']);
		$this->assertSame('6.5.4', $discHeader['wpVersion']);

		$critHealth = WordPressClient::parseSiteHealthTestPayload((string) json_encode(['status' => 'critical', 'label' => 'PHP outdated']));
		$this->assertSame(1, $critHealth['critical']);
		$unkHealth  = WordPressClient::parseSiteHealthTestPayload('not-json');
		$this->assertSame('unknown', $unkHealth['status']);

		$dirSum = WordPressClient::parseDirectorySizesPayload((string) json_encode([
			'wordpress_size' => ['raw' => 1000],
			'uploads_size'   => ['raw' => 2500],
		]));
		$this->assertSame(3500, $dirSum);

		$future = gmdate('M d H:i:s Y', time() + (20 * 86400)) . ' GMT';
		$days   = CurlHttpTransport::extractTlsExpiryDays([['Expire date' => $future]]);
		$this->assertNotNull($days);
		$this->assertGreaterThanOrEqual(19, $days);
		$this->assertNull(CurlHttpTransport::extractTlsExpiryDays([]));
	}
}
