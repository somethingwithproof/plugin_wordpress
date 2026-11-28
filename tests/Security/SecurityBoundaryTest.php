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

namespace Somethingwithproof\WordPress\Tests\Security;

use PHPUnit\Framework\TestCase;
use Somethingwithproof\WordPress\Config\ConfigSchema;
use Somethingwithproof\WordPress\Config\YamlXmlCodec;
use Somethingwithproof\WordPress\Db\MemoryDbAdapter;
use Somethingwithproof\WordPress\Integration\ApiResources;
use Somethingwithproof\WordPress\Integration\CascProvider;
use Somethingwithproof\WordPress\Integration\DoctorChecks;
use Somethingwithproof\WordPress\Integration\McpAbilities;
use Somethingwithproof\WordPress\Log;
use Somethingwithproof\WordPress\Repository\SiteRepository;
use Somethingwithproof\WordPress\Security\OutboundGuard;
use Somethingwithproof\WordPress\Security\SecretVault;
use Somethingwithproof\WordPress\Security\SecurityException;
use Somethingwithproof\WordPress\Settings;
use Somethingwithproof\WordPress\Ui\CsrfGuard;

final class SecurityBoundaryTest extends TestCase {
	private string $keyFile = '';

	protected function setUp(): void {
		$this->keyFile = tempnam(sys_get_temp_dir(), 'wpvault_');
		file_put_contents($this->keyFile, bin2hex(random_bytes(32)));
		chmod($this->keyFile, 0600);
	}

	protected function tearDown(): void {
		if ($this->keyFile !== '' && is_file($this->keyFile)) {
			@unlink($this->keyFile);
		}
	}

	public function testOutboundGuardBlocksNonHttpsEmbeddedCredsRedirectsAndSsrfIps(): void {
		$guard = new OutboundGuard(
			[],
			[],
			5,
			10,
			OutboundGuard::HARD_MAX_RESPONSE_BYTES,
			true,
			static function (string $host): array {
				return match ($host) {
					'public.example.com'   => ['93.184.216.34'],
					'rebind.example.com'   => ['93.184.216.34', '127.0.0.1'],
					'metadata.example.com' => ['169.254.169.254'],
					'mapped.example.com'   => ['::ffff:10.0.0.12'],
					'ipv6meta.example.com' => ['fd00:ec2::254'],
					'internal.corp.local'  => ['10.20.30.40'],
					default                => [],
				};
			}
		);

		$valid = $guard->validateUrl('https://public.example.com/wp-json/');
		$this->assertSame('93.184.216.34', $valid['pinnedIp']);

		foreach ([
			'http://public.example.com/wp-json/',
			'file:///etc/passwd',
			'https://user:pass@public.example.com/wp-json/',
			'https://public.example.com/wp-json/#frag',
			"https://public.example.com/wp-json/\r\nX-Injected: 1",
			'https://127.0.0.1/wp-json/',
			'https://[::1]/wp-json/',
			'https://169.254.169.254/latest/meta-data/',
			'https://rebind.example.com/wp-json/',
			'https://metadata.example.com/wp-json/',
			'https://mapped.example.com/wp-json/',
			'https://ipv6meta.example.com/wp-json/',
			'https://internal.corp.local/wp-json/',
			'https://unresolvable.invalid/wp-json/',
		] as $badUrl) {
			try {
				$guard->validateUrl($badUrl);
				$this->fail('Expected SecurityException for ' . $badUrl);
			} catch (SecurityException) {
				$this->addToAssertionCount(1);
			}
		}

		// Explicit enterprise host & CIDR allowlist permits internal WP host, never cloud metadata.
		$corpGuard = new OutboundGuard(
			['*.corp.local'],
			['10.20.0.0/16'],
			5,
			10,
			OutboundGuard::HARD_MAX_RESPONSE_BYTES,
			true,
			static fn (string $h): array => $h === 'blog.corp.local' ? ['10.20.30.40'] : ['169.254.169.254']
		);
		$corpOk = $corpGuard->validateUrl('https://blog.corp.local/wp-json/');
		$this->assertSame('10.20.30.40', $corpOk['pinnedIp']);

		$this->expectException(SecurityException::class);
		$corpGuard->validateUrl('https://meta.corp.local/wp-json/', true);
	}

	public function testOutboundGuardEnforcesZeroRedirectsAndTwoMiBCap(): void {
		$guard = new OutboundGuard();
		$guard->assertResponseAllowed(200, 1024);
		$guard->assertResponseAllowed(200, OutboundGuard::HARD_MAX_RESPONSE_BYTES);

		try {
			$guard->assertResponseAllowed(302, 128);
			$this->fail('Expected redirect to be rejected');
		} catch (SecurityException $e) {
			$this->assertStringContainsString('redirects', strtolower($e->getMessage()));
		}

		$this->expectException(SecurityException::class);
		$guard->assertResponseAllowed(200, OutboundGuard::HARD_MAX_RESPONSE_BYTES + 1);
	}

	public function testSecretVaultAes256GcmTamperAadAndPermissionBoundaries(): void {
		$db     = new MemoryDbAdapter();
		$vault  = new SecretVault($db, $this->keyFile);
		$secret = 'abcd 1234 efgh 5678 ijkl 9012';

		$envelope = $vault->encrypt('prod-blog', $secret);
		$this->assertStringStartsWith('v1:', $envelope);
		$this->assertStringNotContainsString($secret, $envelope);
		$this->assertSame($secret, $vault->decrypt('prod-blog', $envelope));

		// AAD site binding prevents cross-site ciphertext transplant.
		try {
			$vault->decrypt('other-site', $envelope);
			$this->fail('Expected AAD mismatch failure');
		} catch (SecurityException $e) {
			$this->assertStringContainsString('authentication tag', strtolower($e->getMessage()));
		}

		// Tampered ciphertext is rejected.
		$parts    = explode(':', $envelope);
		$rawCt    = base64_decode($parts[3], true);
		$this->assertIsString($rawCt);
		$tampered = $parts[0] . ':' . $parts[1] . ':' . $parts[2] . ':' . base64_encode($rawCt ^ str_repeat("\x01", strlen($rawCt)));

		try {
			$vault->decrypt('prod-blog', $tampered);
			$this->fail('Expected tampered ciphertext rejection');
		} catch (SecurityException) {
			$this->addToAssertionCount(1);
		}

		// World-readable keyfile is rejected when strict permissions are enabled.
		chmod($this->keyFile, 0644);
		$strictVault = new SecretVault($db, $this->keyFile, true);
		$health      = $strictVault->healthStatus();
		$this->assertFalse($health['permissionsOk']);
		chmod($this->keyFile, 0600);
	}

	public function testZeroSecretLeakageAcrossCascDoctorMcpApiLogsAndReplication(): void {
		$primaryDb = new MemoryDbAdapter();
		$remoteDb  = new MemoryDbAdapter();
		$repo      = new SiteRepository($primaryDb);
		$vault     = new SecretVault($primaryDb, $this->keyFile);
		$settings  = new Settings(vaultKeyFile: $this->keyFile);

		$appPass = 'Zx9Q Lm2P Rr4T Ww8K Vv1N Bb6M';
		$repo->upsertSite([
			'slug'      => 'flagship-wp',
			'name'      => 'Flagship Site',
			'base_url'  => 'https://flagship.example.com',
			'username'  => 'cacti-readonly',
			'poller_id' => 2,
		]);
		$this->assertTrue($vault->store('flagship-wp', $appPass));

		// Remote collector replication copies site rows only, NEVER secrets.
		$replicated = $repo->replicateSitesToRemote($remoteDb, 2);
		$this->assertSame(1, $replicated);
		$this->assertSame(1, (int) $remoteDb->fetchCell('SELECT COUNT(*) FROM plugin_wordpress_sites'));
		$this->assertSame(0, (int) $remoteDb->fetchCell('SELECT COUNT(*) FROM plugin_wordpress_secrets'));

		// CasC export, Doctor debug info, MCP abilities, and API resources must never expose secret or keyfile path.
		$cascDesc   = CascProvider::descriptor(static fn (): Settings => $settings, static fn (Settings $s): bool => true, static fn (): SiteRepository => $repo);
		$cascExport = ($cascDesc['export'])([]);
		$doctorInfo = DoctorChecks::buildDebugInfo(static fn (): SecretVault => $vault, static fn (): SiteRepository => $repo, static fn (): Settings => $settings);

		$mcpCaptured = [];
		$mcpReg      = new class($mcpCaptured) {
			/** @param array<string, mixed> $bag */
			public function __construct(public array &$bag) {}
			/** @param array<string, mixed> $spec */
			public function register(string $id, array $spec): void {
				$this->bag[$id] = $spec;
			}
		};
		McpAbilities::register($mcpReg, static fn (): SiteRepository => $repo, static fn (): Settings => $settings, static fn (int $u): bool => true);
		$mcpList = ($mcpCaptured['wordpress-list-sites']['execute'])(1, new \stdClass());

		$apiRes   = ApiResources::build(static fn (): SiteRepository => $repo, static fn (): Settings => $settings);
		$apiSites = ($apiRes[0]['handlers']['list'])();

		$serialized = json_encode([$cascExport, $doctorInfo, $mcpList, $apiSites], JSON_THROW_ON_ERROR);
		$this->assertStringNotContainsString($appPass, $serialized);
		$this->assertStringContainsString('vault:wordpress:flagship-wp', $serialized);
		$this->assertStringNotContainsString($this->keyFile, json_encode($doctorInfo, JSON_THROW_ON_ERROR));

		// Log sanitizer scrubs Basic Auth headers and Application Passwords.
		$sanitized = Log::sanitize("Authorization: Basic dXNlcjpwYXNz\nFailed with token {$appPass}");
		$this->assertStringNotContainsString('dXNlcjpwYXNz', $sanitized);
		$this->assertStringNotContainsString($appPass, $sanitized);
		$this->assertStringContainsString('[REDACTED]', $sanitized);
		$this->assertStringContainsString('[REDACTED_APP_PASSWORD]', $sanitized);

		// ConfigSchema rejects raw password fields and XML DOCTYPE XXE payloads.
		$schemaErrors = ConfigSchema::validateSite([
			'slug'         => 'bad-site',
			'name'         => 'Bad',
			'base_url'     => 'https://bad.example.com',
			'username'     => 'wp',
			'app_password' => $appPass,
		]);
		$this->assertNotEmpty($schemaErrors);

		$this->expectException(\InvalidArgumentException::class);
		YamlXmlCodec::decode('<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><wordpressFleetConfig/>');
	}

	public function testCsrfGuardVerification(): void {
		$session = [];
		$field   = CsrfGuard::hiddenField($session);
		$token   = CsrfGuard::token($session);

		$this->assertStringContainsString(CsrfGuard::FIELD_NAME, $field);
		$this->assertTrue(CsrfGuard::verify($session, $token));
		$this->assertFalse(CsrfGuard::verify($session, ''));
		$this->assertFalse(CsrfGuard::verify($session, str_repeat('a', 64)));
		$this->assertFalse(CsrfGuard::verify([], $token));
	}
}
