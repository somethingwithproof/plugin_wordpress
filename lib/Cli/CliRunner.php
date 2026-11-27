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

namespace Somethingwithproof\WordPress\Cli;

use Somethingwithproof\WordPress\Config\ConfigSchema;
use Somethingwithproof\WordPress\Config\YamlXmlCodec;
use Somethingwithproof\WordPress\Integration\CascProvider;
use Somethingwithproof\WordPress\Metrics\FleetAnalyzer;
use Somethingwithproof\WordPress\Poller\FleetPoller;
use Somethingwithproof\WordPress\Repository\SiteRepository;
use Somethingwithproof\WordPress\Settings;

/**
 * Command-line runner for cli/wordpress.php implementing declarative Config export,
 * validate, plan, apply (--confirm=<PLAN_HASH>), health, and single-site probe commands.
 */
final class CliRunner {
	/**
	 * Construct a CliRunner with injected settings, repository, and poller dependencies.
	 *
	 * @param callable(): Settings $settingsProvider Live settings supplier.
	 * @param callable(Settings): bool $settingsWriter Settings persistence writer.
	 * @param SiteRepository $repository Site and snapshot repository.
	 * @param FleetPoller $poller Fleet poller for live probes.
	 */
	public function __construct(
		private readonly mixed $settingsProvider,
		private readonly mixed $settingsWriter,
		private readonly SiteRepository $repository,
		private readonly FleetPoller $poller,
	) {
	}

	/**
	 * Execute a CLI command from argv tokens (excluding script filename).
	 *
	 * @param list<string> $args Command-line arguments.
	 * @param string|null $stdinContent Optional pre-supplied document content for tests.
	 * @return array{exitCode: int, stdout: string, stderr: string}
	 */
	public function run(array $args, ?string $stdinContent = null): array {
		$command = $args[0] ?? 'help';
		$opts    = self::parseOptions(array_slice($args, 1));

		return match ($command) {
			'export'   => $this->cmdExport($opts),
			'validate' => $this->cmdValidate($opts, $stdinContent),
			'plan'     => $this->cmdPlan($opts, $stdinContent),
			'apply'    => $this->cmdApply($opts, $stdinContent),
			'health'   => $this->cmdHealth($opts),
			'probe'    => $this->cmdProbe($opts),
			'help', '--help', '-h' => [
				'exitCode' => 0,
				'stdout'   => self::usage(),
				'stderr'   => '',
			],
			default => [
				'exitCode' => 2,
				'stdout'   => '',
				'stderr'   => sprintf("Unknown subcommand \"%s\".\n%s", $command, self::usage()),
			],
		};
	}

	/**
	 * Export Config-only WordPress settings and site inventory in YAML or XML.
	 *
	 * @param array<string, string> $opts Parsed CLI flags.
	 * @return array{exitCode: int, stdout: string, stderr: string}
	 */
	private function cmdExport(array $opts): array {
		$format   = strtolower($opts['format'] ?? 'yaml');
		$settings = $this->currentSettings();
		$doc      = [
			'settings' => $settings->toConfigArray(),
			'sites'    => $this->repository->exportSitesConfig(),
		];

		if ($format === 'yaml') {
			return ['exitCode' => 0, 'stdout' => YamlXmlCodec::encodeYaml($doc), 'stderr' => ''];
		}

		if ($format === 'xml') {
			return ['exitCode' => 0, 'stdout' => YamlXmlCodec::encodeXml($doc), 'stderr' => ''];
		}

		return ['exitCode' => 2, 'stdout' => '', 'stderr' => "Unsupported --format value (expected yaml or xml).\n"];
	}

	/**
	 * Validate a YAML or XML Config file against ConfigSchema.
	 *
	 * @param array<string, string> $opts Parsed CLI flags.
	 * @param string|null $stdinContent Optional document override.
	 * @return array{exitCode: int, stdout: string, stderr: string}
	 */
	private function cmdValidate(array $opts, ?string $stdinContent): array {
		try {
			$desired = $this->loadConfigDocument($opts, $stdinContent);
		} catch (\RuntimeException $error) {
			return ['exitCode' => 1, 'stdout' => '', 'stderr' => $error->getMessage() . "\n"];
		}

		$errors = ConfigSchema::validate($desired);

		if ($errors !== []) {
			return [
				'exitCode' => 1,
				'stdout'   => '',
				'stderr'   => "Validation failed:\n- " . implode("\n- ", $errors) . "\n",
			];
		}

		return ['exitCode' => 0, 'stdout' => "Configuration is valid.\n", 'stderr' => ''];
	}

	/**
	 * Compute a deterministic plan diff and SHA-256 confirmation hash without mutating state.
	 *
	 * @param array<string, string> $opts Parsed CLI flags.
	 * @param string|null $stdinContent Optional document override.
	 * @return array{exitCode: int, stdout: string, stderr: string}
	 */
	private function cmdPlan(array $opts, ?string $stdinContent): array {
		try {
			$desired = $this->loadConfigDocument($opts, $stdinContent);
		} catch (\RuntimeException $error) {
			return ['exitCode' => 1, 'stdout' => '', 'stderr' => $error->getMessage() . "\n"];
		}

		$errors = ConfigSchema::validate($desired);

		if ($errors !== []) {
			return ['exitCode' => 1, 'stdout' => '', 'stderr' => "Validation failed:\n- " . implode("\n- ", $errors) . "\n"];
		}

		$actions  = CascProvider::computePlan($desired, $this->currentSettings(), $this->repository);
		$planHash = YamlXmlCodec::planHash($desired, $actions);
		$payload  = [
			'planHash' => $planHash,
			'changes'  => count($actions),
			'actions'  => $actions,
		];

		if (($opts['format'] ?? 'text') === 'json') {
			return [
				'exitCode' => 0,
				'stdout'   => (string) json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n",
				'stderr'   => '',
			];
		}

		$lines   = [sprintf('PLAN_HASH: %s', $planHash), sprintf('PLANNED_CHANGES: %d', count($actions))];

		foreach ($actions as $action) {
			$op      = is_string($action['operation'] ?? null) ? $action['operation'] : 'update';
			$key     = is_string($action['key'] ?? null) ? $action['key'] : '';
			$lines[] = sprintf('- [%s] %s', $op, $key);
		}

		return ['exitCode' => 0, 'stdout' => implode("\n", $lines) . "\n", 'stderr' => ''];
	}

	/**
	 * Apply a validated Config document when --confirm=<PLAN_HASH> matches the computed plan.
	 *
	 * @param array<string, string> $opts Parsed CLI flags.
	 * @param string|null $stdinContent Optional document override.
	 * @return array{exitCode: int, stdout: string, stderr: string}
	 */
	private function cmdApply(array $opts, ?string $stdinContent): array {
		$confirm = $opts['confirm'] ?? '';

		if ($confirm === '') {
			return ['exitCode' => 2, 'stdout' => '', 'stderr' => "Refusing to apply without --confirm=<PLAN_HASH>. Run 'plan' first.\n"];
		}

		try {
			$desired = $this->loadConfigDocument($opts, $stdinContent);
		} catch (\RuntimeException $error) {
			return ['exitCode' => 1, 'stdout' => '', 'stderr' => $error->getMessage() . "\n"];
		}

		$writer = $this->settingsWriter;

		if (!is_callable($writer)) {
			return ['exitCode' => 1, 'stdout' => '', 'stderr' => "Settings writer is not configured.\n"];
		}

		$result = CascProvider::applyPlan(
			$desired,
			$confirm,
			$this->currentSettings(),
			static fn (Settings $next): bool => (bool) $writer($next),
			$this->repository
		);

		if (empty($result['ok'])) {
			$errList = [];

			if (is_array($result['errors'] ?? null)) {
				foreach ($result['errors'] as $errItem) {
					if (is_scalar($errItem)) {
						$errList[] = (string) $errItem;
					}
				}
			}

			$errs = $errList !== [] ? implode('; ', $errList) : 'Apply failed.';

			return ['exitCode' => 1, 'stdout' => '', 'stderr' => $errs . "\n"];
		}

		$appliedHash  = is_string($result['planHash'] ?? null) ? $result['planHash'] : '';
		$appliedActs  = is_numeric($result['actions'] ?? null) ? (int) $result['actions'] : 0;
		$appliedSites = is_numeric($result['sitesApplied'] ?? null) ? (int) $result['sitesApplied'] : 0;

		return [
			'exitCode' => 0,
			'stdout'   => sprintf(
				"Applied plan %s (%d action(s), %d site(s) synchronized).\n",
				$appliedHash,
				$appliedActs,
				$appliedSites
			),
			'stderr' => '',
		];
	}

	/**
	 * Output fleet health metrics in text or JSON format.
	 *
	 * @param array<string, string> $opts Parsed CLI flags.
	 * @return array{exitCode: int, stdout: string, stderr: string}
	 */
	private function cmdHealth(array $opts): array {
		$format   = strtolower($opts['format'] ?? 'text');
		$pollerId = isset($opts['poller']) && is_numeric($opts['poller']) ? max(1, (int) $opts['poller']) : null;
		$analysis = (new FleetAnalyzer($this->currentSettings()))->analyze($this->repository->loadSnapshots($pollerId));

		if ($format === 'json') {
			return [
				'exitCode' => 0,
				'stdout'   => (string) json_encode($analysis, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n",
				'stderr'   => '',
			];
		}

		if ($format !== 'text') {
			return ['exitCode' => 2, 'stdout' => '', 'stderr' => "Unsupported --format value (expected text or json).\n"];
		}

		$c    = $analysis['counts'];
		$text = sprintf(
			"sites_total=%d sites_healthy=%d sites_degraded=%d sites_critical=%d apdex=%.2f ttfb_p95_ms=%.2f updates_pending=%d cron_overdue_total=%d autoload_bloat_sites=%d tls_min_expiry_days=%s\n",
			$c['sites_total'],
			$c['sites_healthy'],
			$c['sites_degraded'],
			$c['sites_critical'],
			$analysis['apdex']['score'],
			$c['ttfb_p95_ms'],
			$c['updates_pending'],
			$c['cron_overdue_total'],
			$c['autoload_bloat_sites'],
			$c['tls_min_expiry_days'] !== null ? (string) $c['tls_min_expiry_days'] : 'n/a'
		);

		return ['exitCode' => 0, 'stdout' => $text, 'stderr' => ''];
	}

	/**
	 * Probe a single configured WordPress site by slug in read-only mode.
	 *
	 * @param array<string, string> $opts Parsed CLI flags.
	 * @return array{exitCode: int, stdout: string, stderr: string}
	 */
	private function cmdProbe(array $opts): array {
		$slug = trim($opts['site'] ?? '');

		if ($slug === '') {
			return ['exitCode' => 2, 'stdout' => '', 'stderr' => "Missing required --site=<slug> option.\n"];
		}

		$persist = isset($opts['persist']) && in_array(strtolower($opts['persist']), ['1', 'true', 'yes', 'on'], true);
		$metrics = $this->poller->probeSite($slug, $persist);

		if ($metrics === null) {
			return ['exitCode' => 1, 'stdout' => '', 'stderr' => sprintf("Unknown site slug \"%s\".\n", $slug)];
		}

		if (strtolower($opts['format'] ?? 'json') === 'text') {
			return [
				'exitCode' => 0,
				'stdout'   => sprintf(
					"site=%s status=%s wp=%s ttfb_ms=%.2f apdex=%.2f updates=%d cron_overdue=%d autoload_bytes=%d\n",
					$metrics->slug,
					$metrics->status,
					$metrics->wpVersion,
					$metrics->ttfbMs,
					$metrics->apdexScore,
					$metrics->totalUpdatesPending(),
					$metrics->cronOverdueCount,
					$metrics->autoloadBytes
				),
				'stderr' => '',
			];
		}

		return [
			'exitCode' => 0,
			'stdout'   => (string) json_encode($metrics->toArray(), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n",
			'stderr'   => '',
		];
	}

	/**
	 * Load and decode a Config document from --file=<path> or injected content.
	 *
	 * @param array<string, string> $opts Parsed CLI flags.
	 * @param string|null $stdinContent Optional preloaded content.
	 * @return array<string, mixed>
	 * @throws \RuntimeException When the input file is missing or unreadable.
	 */
	private function loadConfigDocument(array $opts, ?string $stdinContent): array {
		$raw = $stdinContent;

		if (isset($opts['file']) && $opts['file'] !== '') {
			if (!is_file($opts['file']) || !is_readable($opts['file'])) {
				throw new \RuntimeException(sprintf('Unable to read config file "%s".', $opts['file']));
			}

			$loaded = file_get_contents($opts['file']);

			if (!is_string($loaded)) {
				throw new \RuntimeException(sprintf('Failed to read config file "%s".', $opts['file']));
			}

			$raw = $loaded;
		}

		if ($raw === null) {
			$current = $this->currentSettings()->toConfigArray();
			$current['sites'] = $this->repository->exportSitesConfig();

			return $current;
		}

		try {
			$decoded = YamlXmlCodec::decode($raw);
		} catch (\InvalidArgumentException $error) {
			throw new \RuntimeException($error->getMessage(), 0, $error);
		}

		$flat          = $decoded['settings'];
		$flat['sites'] = $decoded['sites'];

		return $flat;
	}

	/**
	 * Retrieve live Settings via the injected callable.
	 *
	 * @return Settings
	 */
	private function currentSettings(): Settings {
		$provider = $this->settingsProvider;

		if (is_callable($provider)) {
			$result = $provider();

			if ($result instanceof Settings) {
				return $result;
			}
		}

		return new Settings();
	}

	/**
	 * Parse --key=value and --key value CLI options into an associative map.
	 *
	 * @param list<string> $tokens Raw argument tokens after subcommand.
	 * @return array<string, string>
	 */
	private static function parseOptions(array $tokens): array {
		$opts  = [];
		$count = count($tokens);

		for ($i = 0; $i < $count; $i++) {
			$token = $tokens[$i];

			if (!str_starts_with($token, '--')) {
				continue;
			}

			$body = substr($token, 2);

			if (str_contains($body, '=')) {
				[$k, $v]  = explode('=', $body, 2);
				$opts[$k] = $v;
			} elseif (($i + 1) < $count && !str_starts_with($tokens[$i + 1], '--')) {
				$opts[$body] = $tokens[++$i];
			} else {
				$opts[$body] = '1';
			}
		}

		return $opts;
	}

	/**
	 * Return CLI usage text.
	 *
	 * @return string
	 */
	private static function usage(): string {
		return "Usage: php plugins/wordpress/cli/wordpress.php <command> [options]\n"
			. "Commands:\n"
			. "  export   --format=yaml|xml\n"
			. "  validate [--file=<path>]\n"
			. "  plan     [--file=<path>] [--format=text|json]\n"
			. "  apply    --confirm=<PLAN_HASH> [--file=<path>]\n"
			. "  health   [--poller=N] [--format=text|json]\n"
			. "  probe    --site=<slug> [--format=json|text] [--persist=1]\n";
	}
}
