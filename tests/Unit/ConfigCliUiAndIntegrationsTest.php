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
use Somethingwithproof\WordPress\Schema;
use Somethingwithproof\WordPress\Security\OutboundGuard;
use Somethingwithproof\WordPress\Security\SecretVault;
use Somethingwithproof\WordPress\Settings;
use Somethingwithproof\WordPress\Ui\CsrfGuard;
use Somethingwithproof\WordPress\Ui\PagesRenderer;

final class ConfigCliUiAndIntegrationsTest extends TestCase {
	public function testYamlXmlRoundTripValidationAndCliPlanApplyFlow(): void {
		$db       = new MemoryDbAdapter();
		$repo     = new SiteRepository($db);
		$settings = new Settings(pollInterval: 300, defaultApdexTMs: 500);
		$saved    = $settings;

		$repo->upsertSite([
			'slug'     => 'docs-wp',
			'name'     => 'Docs Portal',
			'base_url' => 'https://docs.example.com',
			'username' => 'cacti-ro',
		]);

		$transport = new class implements HttpTransport {
			public function get(string $url, array $headers, int $connectTimeout, int $readTimeout, int $maxBytes, bool $verifyTls, ?string $pinnedIp = null): HttpResponse {
				return new HttpResponse(200, '{"name":"Docs Portal","wp_version":"6.7.2","namespaces":["wp/v2"]}', [], 95.0, 105.0, 60);
			}
		};

		$guard  = new OutboundGuard([], [], 5, 10, 2097152, true, static fn (string $h): array => ['93.184.216.34']);
		$poller = new FleetPoller($repo, new SecretVault($db, ''), new WordPressClient($transport, $guard), new AdaptivePollerSizer(), $settings);

		$runner = new CliRunner(
			static function () use (&$saved): Settings {
				return $saved;
			},
			static function (Settings $next) use (&$saved): bool {
				$saved = $next;

				return true;
			},
			$repo,
			$poller
		);

		$yamlOut = $runner->run(['export', '--format=yaml']);
		$this->assertSame(0, $yamlOut['exitCode']);
		$this->assertStringContainsString('vault:wordpress:docs-wp', $yamlOut['stdout']);

		$xmlOut = $runner->run(['export', '--format=xml']);
		$this->assertSame(0, $xmlOut['exitCode']);
		$this->assertStringContainsString('<wordpressFleetConfig', $xmlOut['stdout']);
		$this->assertSame(0, $runner->run(['validate'], $xmlOut['stdout'])['exitCode']);

		// Modify exported YAML to change poll interval and add a second site.
		$desiredYaml = str_replace('wordpress_poll_interval: 300', 'wordpress_poll_interval: 600', $yamlOut['stdout']);
		$planRes     = $runner->run(['plan', '--format=json'], $desiredYaml);
		$this->assertSame(0, $planRes['exitCode']);
		$planData = json_decode($planRes['stdout'], true, 512, JSON_THROW_ON_ERROR);
		$this->assertSame(1, $planData['changes']);
		$planHash = (string) $planData['planHash'];

		// Refuses apply without --confirm or with wrong hash.
		$this->assertSame(2, $runner->run(['apply'], $desiredYaml)['exitCode']);
		$this->assertSame(1, $runner->run(['apply', '--confirm=deadbeef'], $desiredYaml)['exitCode']);

		// Succeeds with exact PLAN_HASH.
		$applyRes = $runner->run(['apply', '--confirm=' . $planHash], $desiredYaml);
		$this->assertSame(0, $applyRes['exitCode']);
		$this->assertSame(600, $saved->pollInterval);

		// Health and probe CLI subcommands.
		$probeRes = $runner->run(['probe', '--site=docs-wp', '--persist=1', '--format=text']);
		$this->assertSame(0, $probeRes['exitCode']);
		$this->assertStringContainsString('site=docs-wp', $probeRes['stdout']);

		$healthText = $runner->run(['health', '--format=text']);
		$this->assertSame(0, $healthText['exitCode']);
		$this->assertStringContainsString('sites_total=1', $healthText['stdout']);

		$healthJson = $runner->run(['health', '--format=json']);
		$this->assertSame(0, $healthJson['exitCode']);
		$this->assertSame(0, $runner->run(['help'])['exitCode']);
		$this->assertSame(2, $runner->run(['unknown-cmd'])['exitCode']);
		$this->assertSame(2, $runner->run(['export', '--format=csv'])['exitCode']);
	}

	public function testConfigSchemaValidationBoundaries(): void {
		$errors = ConfigSchema::validate([
			'wordpress_poll_interval'       => 5,
			'wordpress_vault_key_file'      => '/etc/../passwd',
			'wordpress_autoload_warn_bytes' => 2097152,
			'wordpress_autoload_crit_bytes' => 819200,
			'wordpress_min_concurrency'     => 16,
			'wordpress_max_concurrency'     => 4,
			'password'                      => 'leaked',
			'unknown_field'                 => 'x',
		]);

		$this->assertCount(6, $errors);
	}

	public function testIntegrationsContractsAndPagesRendererEscaping(): void {
		$db       = new MemoryDbAdapter();
		$repo     = new SiteRepository($db);
		$settings = new Settings();
		$vault    = new SecretVault($db, '');

		$repo->upsertSite([
			'slug'     => 'xss-site',
			'name'     => '<script>alert(1)</script>',
			'base_url' => 'https://xss.example.com',
			'username' => 'reader',
		]);
		$snap = SiteMetrics::fromObservation([
			'slug'                  => 'xss-site',
			'siteName'              => '<img src=x onerror=alert(1)>',
			'url'                   => 'https://xss.example.com',
			'wpVersion'             => '6.6.0',
			'ttfbMs'                => 210.0,
			'pluginsUpdatesPending' => 2,
			'tlsExpiryDays'         => 50,
			'details'               => ['pluginDrift' => [['slug' => 'foo/foo.php', 'version' => '1.0', 'newVersion' => '1.1']]],
		], $settings);
		$repo->saveSnapshot($snap);

		$analysis = (new FleetAnalyzer($settings))->analyze([$snap]);
		$session  = [];
		$csrf     = CsrfGuard::hiddenField($session);

		$viewHtml = PagesRenderer::renderViewConsole($analysis, [$snap], FleetAnalyzer::tholdTemplates($settings));
		$opHtml   = PagesRenderer::renderOperatorConsole($csrf, $repo->listSites(), $analysis, $snap, ['OK'], ['Warn']);
		$admHtml  = PagesRenderer::renderAdminConsole($csrf, $repo->listSites(), ['xss-site' => false], $vault->healthStatus(), $settings, [], []);

		$this->assertStringNotContainsString('<script>', $admHtml);
		$this->assertStringContainsString('&lt;script&gt;', $admHtml);
		$this->assertStringContainsString('WordPress Fleet TTFB p95 Latency', $viewHtml);
		$this->assertStringContainsString('dry_run_probe', $opHtml);

		// Canonical Doctor list & run contracts.
		$listChecks = DoctorChecks::buildChecks(static fn (): SecretVault => $vault, static fn (): SiteRepository => $repo, static fn (): Settings => $settings, 'list');
		$this->assertCount(4, $listChecks);
		$this->assertSame('wordpress.vault_keyfile', $listChecks[0]['id']);
		$this->assertSame('info', $listChecks[0]['status']);

		$runChecks = DoctorChecks::buildChecks(static fn (): SecretVault => $vault, static fn (): SiteRepository => $repo, static fn (): Settings => $settings, 'run');
		$this->assertSame('warn', $runChecks[0]['status']);

		$debug = DoctorChecks::buildDebugInfo(static fn (): SecretVault => $vault, static fn (): SiteRepository => $repo, static fn (): Settings => $settings);
		$this->assertSame('wordpress.overview', $debug[0]['id']);
		$this->assertArrayHasKey('vault_keyfile', $debug[0]['fields']);

		// Canonical Schema safety check: Cacti 1.2.31 interpolates table/column comments unescaped.
		foreach (Schema::tables() as $tableName => $def) {
			if (isset($def['comment']) && is_string($def['comment'])) {
				$this->assertStringNotContainsString("'", $def['comment'], $tableName . ' comment must not contain single quotes');
			}

			foreach ((array) ($def['columns'] ?? []) as $col) {
				if (is_array($col) && isset($col['comment']) && is_string($col['comment'])) {
					$this->assertStringNotContainsString("'", $col['comment'], $tableName . ' column comment must not contain single quotes');
				}
			}
		}

		// Canonical MCP schema check: registerCategory precedes register, all objects are closed, all arrays are bounded.
		$abilities = [];
		$events    = [];
		$reg       = new class($abilities, $events) {
			/**
			 * @param array<string, mixed> $bag
			 * @param list<string> $events
			 */
			public function __construct(public array &$bag, public array &$events) {}
			public function registerCategory(string $id, string $label): void {
				$this->events[] = 'category:' . $id . ':' . $label;
			}
			/** @param array<string, mixed> $def */
			public function register(string $id, array $def): void {
				$this->events[] = 'ability:' . $id;
				$this->bag[$id] = $def;
			}
		};
		McpAbilities::register($reg, static fn (): SiteRepository => $repo, static fn (): Settings => $settings, static fn (int $u): bool => true);
		$this->assertSame(['wordpress-list-sites', 'wordpress-get-health', 'wordpress-get-drift'], array_keys($abilities));
		$this->assertSame('category:monitoring:Monitoring', $events[0] ?? null);
		$this->assertSame('ability:wordpress-list-sites', $events[1] ?? null);

		// Duplicate category LogicException must not abort ability registration.
		$dupBag = [];
		$dupReg = new class($dupBag) {
			/** @param array<string, mixed> $bag */
			public function __construct(public array &$bag) {}
			public function registerCategory(string $id, string $label): void {
				throw new \LogicException('Duplicate category');
			}
			/** @param array<string, mixed> $def */
			public function register(string $id, array $def): void {
				$this->bag[$id] = $def;
			}
		};
		McpAbilities::register($dupReg, static fn (): SiteRepository => $repo, static fn (): Settings => $settings, static fn (int $u): bool => true);
		$this->assertCount(3, $dupBag);

		foreach ($abilities as $id => $def) {
			$this->assertSchemaClosedAndBounded($def['input_schema'], $id . '.input_schema');
			$this->assertSchemaClosedAndBounded($def['output_schema'], $id . '.output_schema');
		}

		$healthOut = ($abilities['wordpress-get-health']['execute'])(1, new \stdClass());
		$this->assertSame(1, $healthOut['counts']['sites_total']);
		$driftOut = ($abilities['wordpress-get-drift']['execute'])(1, new \stdClass());
		$this->assertCount(1, $driftOut['sites']);
		$this->assertSame([['version' => '6.6.0', 'count' => 1]], $driftOut['summary']['wpVersionCounts']);

		// Canonical API resource contract.
		$resources = ApiResources::build(static fn (): SiteRepository => $repo, static fn (): Settings => $settings);
		$this->assertSame('wordpressSites', $resources[0]['collection']);
		$this->assertSame('wordpress_view.php', $resources[0]['realm_read']);
		$this->assertNotNull(($resources[0]['handlers']['get'])('xss-site'));
		$this->assertNull(($resources[0]['handlers']['get'])('missing'));
		$this->assertArrayHasKey('counts', ($resources[1]['handlers']['get'])('fleet'));
		$this->assertSame('xss-site', ($resources[1]['handlers']['get'])('xss-site')['slug']);

		// Canonical CasC 1-arg registration.
		$cascBag = [];
		$cascReg = new class($cascBag) {
			/** @param list<array<string, mixed>> $bag */
			public function __construct(public array &$bag) {}
			/** @param array<string, mixed> $desc */
			public function register(array $desc): void {
				$this->bag[] = $desc;
			}
		};
		$this->assertTrue(CascProvider::register($cascReg, static fn (): Settings => $settings, static fn (Settings $s): bool => true, static fn (): SiteRepository => $repo));
		$this->assertCount(1, $cascBag);
		$this->assertSame('wordpress', $cascBag[0]['slug']);
	}

	/**
	 * Recursively verify every JSON schema object is closed and every array declares items and maxItems.
	 *
	 * @param array<string, mixed> $schema Schema node.
	 * @param string $path Context path for failure messages.
	 * @return void
	 */
	private function assertSchemaClosedAndBounded(array $schema, string $path): void {
		$type = is_array($schema['type'] ?? null) ? ($schema['type'][0] ?? null) : ($schema['type'] ?? null);

		if ($type === 'object') {
			$this->assertArrayHasKey('properties', $schema, $path . ' missing properties');
			$this->assertFalse($schema['additionalProperties'] ?? null, $path . ' must set additionalProperties=false');
			$props = is_array($schema['properties']) ? $schema['properties'] : (array) $schema['properties'];

			foreach ((array) ($schema['required'] ?? []) as $req) {
				$this->assertArrayHasKey((string) $req, $props, $path . ' required field missing from properties: ' . (string) $req);
			}

			foreach ($props as $k => $prop) {
				if (is_array($prop)) {
					$this->assertSchemaClosedAndBounded($prop, $path . '.' . $k);
				}
			}
		}

		if ($type === 'array') {
			$this->assertArrayHasKey('items', $schema, $path . ' missing items');
			$this->assertArrayHasKey('maxItems', $schema, $path . ' missing maxItems');
			$this->assertIsInt($schema['maxItems'], $path . ' maxItems must be int');

			if (is_array($schema['items'])) {
				$this->assertSchemaClosedAndBounded($schema['items'], $path . '[]');
			}
		}
	}
}
