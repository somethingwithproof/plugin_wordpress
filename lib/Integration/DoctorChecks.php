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

namespace Somethingwithproof\WordPress\Integration;

use Somethingwithproof\WordPress\Metrics\FleetAnalyzer;
use Somethingwithproof\WordPress\Repository\SiteRepository;
use Somethingwithproof\WordPress\Security\SecretVault;
use Somethingwithproof\WordPress\Settings;

/**
 * Decoupled diagnostic checks and redacted debug info exposed via
 * doctor_register_checks and doctor_register_debug_info hooks.
 */
final class DoctorChecks {
	/**
	 * Build pre-evaluated plain-array diagnostic check descriptors for doctor_register_checks.
	 *
	 * @param callable(): SecretVault $vaultFactory Lazy SecretVault supplier.
	 * @param callable(): SiteRepository $repoFactory Lazy SiteRepository supplier.
	 * @param callable(): Settings $settingsFactory Lazy Settings supplier.
	 * @param string $mode Execution mode ('run' or 'list').
	 * @return list<array{
	 *   id: string,
	 *   plugin: string,
	 *   category: string,
	 *   title: string,
	 *   status: string,
	 *   message: string,
	 *   details: array<string, mixed>,
	 *   remediation: string
	 * }>
	 */
	public static function buildChecks(
		callable $vaultFactory,
		callable $repoFactory,
		callable $settingsFactory,
		string $mode = 'run',
	): array {
		if ($mode === 'list') {
			return [
				[
					'id'          => 'wordpress.vault_keyfile',
					'plugin'      => 'wordpress',
					'category'    => 'security',
					'title'       => 'WordPress AES-256-GCM Vault Keyfile',
					'status'      => 'info',
					'message'     => 'Checks external 256-bit vault keyfile availability and POSIX permissions.',
					'details'     => [],
					'remediation' => 'Configure wordpress_vault_key_file pointing to a chmod 0600 256-bit keyfile.',
				],
				[
					'id'          => 'wordpress.fleet_health',
					'plugin'      => 'wordpress',
					'category'    => 'monitoring',
					'title'       => 'WordPress Fleet Availability and Site Health',
					'status'      => 'info',
					'message'     => 'Evaluates critical, unreachable, and degraded WordPress sites across the fleet.',
					'details'     => [],
					'remediation' => 'Run cli/wordpress.php probe --site=<slug> to diagnose unhealthy sites.',
				],
				[
					'id'          => 'wordpress.cron_and_autoload',
					'plugin'      => 'wordpress',
					'category'    => 'performance',
					'title'       => 'WordPress WP-Cron Stalls and Autoload Bloat',
					'status'      => 'info',
					'message'     => 'Checks overdue WP-Cron queues and wp_options autoloaded payload budgets.',
					'details'     => [],
					'remediation' => 'Run system cron for wp-cron.php and trim oversized autoloaded options.',
				],
				[
					'id'          => 'wordpress.tls_expiry',
					'plugin'      => 'wordpress',
					'category'    => 'security',
					'title'       => 'WordPress Fleet TLS Certificate Expiry',
					'status'      => 'info',
					'message'     => 'Tracks minimum days remaining before TLS certificate expiration across monitored sites.',
					'details'     => [],
					'remediation' => 'Renew expiring TLS certificates before reaching the warning window.',
				],
			];
		}

		$settings    = $settingsFactory();
		$vaultStatus = $vaultFactory()->healthStatus();
		$analysis    = (new FleetAnalyzer($settings))->analyze($repoFactory()->loadSnapshots());
		$counts      = $analysis['counts'];

		if (!$vaultStatus['configured']) {
			$vaultCheck = [
				'id'          => 'wordpress.vault_keyfile',
				'plugin'      => 'wordpress',
				'category'    => 'security',
				'title'       => 'WordPress AES-256-GCM Vault Keyfile',
				'status'      => 'warn',
				'message'     => 'WordPress vault keyfile is not configured; authenticated REST probes are disabled.',
				'details'     => [
					'configured'    => false,
					'storedSecrets' => $vaultStatus['storedSecrets'],
				],
				'remediation' => 'Create a chmod 0600 256-bit keyfile and set wordpress_vault_key_file in Settings.',
			];
		} elseif (!$vaultStatus['readable'] || !$vaultStatus['permissionsOk']) {
			$vaultCheck = [
				'id'          => 'wordpress.vault_keyfile',
				'plugin'      => 'wordpress',
				'category'    => 'security',
				'title'       => 'WordPress AES-256-GCM Vault Keyfile',
				'status'      => 'fail',
				'message'     => 'WordPress vault keyfile check failed: ' . $vaultStatus['error'],
				'details'     => [
					'configured'    => true,
					'readable'      => $vaultStatus['readable'],
					'permissionsOk' => $vaultStatus['permissionsOk'],
					'storedSecrets' => $vaultStatus['storedSecrets'],
				],
				'remediation' => 'Verify keyfile ownership, chmod 0600 permissions, and 256-bit key length.',
			];
		} else {
			$vaultCheck = [
				'id'          => 'wordpress.vault_keyfile',
				'plugin'      => 'wordpress',
				'category'    => 'security',
				'title'       => 'WordPress AES-256-GCM Vault Keyfile',
				'status'      => 'ok',
				'message'     => sprintf('Vault keyfile loaded (%s); %d encrypted credential(s) stored locally.', $vaultStatus['keyFingerprint'], $vaultStatus['storedSecrets']),
				'details'     => [
					'configured'     => true,
					'readable'       => true,
					'permissionsOk'  => true,
					'keyFingerprint' => $vaultStatus['keyFingerprint'],
					'storedSecrets'  => $vaultStatus['storedSecrets'],
				],
				'remediation' => '',
			];
		}

		if ($counts['sites_critical'] > 0) {
			$fleetCheck = [
				'id'          => 'wordpress.fleet_health',
				'plugin'      => 'wordpress',
				'category'    => 'monitoring',
				'title'       => 'WordPress Fleet Availability and Site Health',
				'status'      => 'fail',
				'message'     => sprintf('%d of %d WordPress site(s) are critical or unreachable.', $counts['sites_critical'], $counts['sites_total']),
				'details'     => $counts,
				'remediation' => 'Inspect critical sites in WordPress Operator Console or run cli/wordpress.php probe.',
			];
		} elseif ($counts['sites_degraded'] > 0) {
			$fleetCheck = [
				'id'          => 'wordpress.fleet_health',
				'plugin'      => 'wordpress',
				'category'    => 'monitoring',
				'title'       => 'WordPress Fleet Availability and Site Health',
				'status'      => 'warn',
				'message'     => sprintf('%d of %d WordPress site(s) are degraded.', $counts['sites_degraded'], $counts['sites_total']),
				'details'     => $counts,
				'remediation' => 'Review pending updates, Site Health warnings, and TTFB anomalies in WordPress View.',
			];
		} else {
			$fleetCheck = [
				'id'          => 'wordpress.fleet_health',
				'plugin'      => 'wordpress',
				'category'    => 'monitoring',
				'title'       => 'WordPress Fleet Availability and Site Health',
				'status'      => 'ok',
				'message'     => sprintf('All %d monitored WordPress site(s) are healthy (Apdex %.2f).', $counts['sites_total'], $analysis['apdex']['score']),
				'details'     => $counts,
				'remediation' => '',
			];
		}

		if ($counts['autoload_crit_sites'] > 0 || $counts['cron_overdue_total'] >= 25) {
			$cronCheck = [
				'id'          => 'wordpress.cron_and_autoload',
				'plugin'      => 'wordpress',
				'category'    => 'performance',
				'title'       => 'WordPress WP-Cron Stalls and Autoload Bloat',
				'status'      => 'fail',
				'message'     => sprintf('%d site(s) have critical autoload bloat (> 2 MiB) and %d overdue WP-Cron job(s).', $counts['autoload_crit_sites'], $counts['cron_overdue_total']),
				'details'     => [
					'autoloadBloatSites' => $counts['autoload_bloat_sites'],
					'autoloadCritSites'  => $counts['autoload_crit_sites'],
					'cronOverdueTotal'   => $counts['cron_overdue_total'],
				],
				'remediation' => 'Audit wp_options where autoload=yes and restore system cron execution for wp-cron.php.',
			];
		} elseif ($counts['autoload_bloat_sites'] > 0 || $counts['cron_overdue_total'] > 0) {
			$cronCheck = [
				'id'          => 'wordpress.cron_and_autoload',
				'plugin'      => 'wordpress',
				'category'    => 'performance',
				'title'       => 'WordPress WP-Cron Stalls and Autoload Bloat',
				'status'      => 'warn',
				'message'     => sprintf('%d site(s) exceed autoload bloat thresholds; %d overdue WP-Cron job(s).', $counts['autoload_bloat_sites'], $counts['cron_overdue_total']),
				'details'     => [
					'autoloadBloatSites' => $counts['autoload_bloat_sites'],
					'autoloadWarnSites'  => $counts['autoload_warn_sites'],
					'cronOverdueTotal'   => $counts['cron_overdue_total'],
				],
				'remediation' => 'Prune stale transients from wp_options and verify WP-Cron scheduling cadence.',
			];
		} else {
			$cronCheck = [
				'id'          => 'wordpress.cron_and_autoload',
				'plugin'      => 'wordpress',
				'category'    => 'performance',
				'title'       => 'WordPress WP-Cron Stalls and Autoload Bloat',
				'status'      => 'ok',
				'message'     => 'No WP-Cron stalls or wp_options autoload bloat detected across the fleet.',
				'details'     => [
					'autoloadBloatSites' => 0,
					'cronOverdueTotal'   => 0,
				],
				'remediation' => '',
			];
		}

		$minDays = $counts['tls_min_expiry_days'];

		if ($minDays !== null && $minDays <= $settings->tlsCritDays) {
			$tlsCheck = [
				'id'          => 'wordpress.tls_expiry',
				'plugin'      => 'wordpress',
				'category'    => 'security',
				'title'       => 'WordPress Fleet TLS Certificate Expiry',
				'status'      => 'fail',
				'message'     => sprintf('Minimum WordPress TLS certificate expiry is %d day(s) (critical <= %d).', $minDays, $settings->tlsCritDays),
				'details'     => ['minExpiryDays' => $minDays, 'expiringCount' => count($analysis['tlsExpiring'])],
				'remediation' => 'Renew the expiring TLS certificate immediately and verify ACME automation.',
			];
		} elseif ($minDays !== null && $minDays <= $settings->tlsWarnDays) {
			$tlsCheck = [
				'id'          => 'wordpress.tls_expiry',
				'plugin'      => 'wordpress',
				'category'    => 'security',
				'title'       => 'WordPress Fleet TLS Certificate Expiry',
				'status'      => 'warn',
				'message'     => sprintf('Minimum WordPress TLS certificate expiry is %d day(s) (warning <= %d).', $minDays, $settings->tlsWarnDays),
				'details'     => ['minExpiryDays' => $minDays, 'expiringCount' => count($analysis['tlsExpiring'])],
				'remediation' => 'Schedule TLS certificate renewal before entering the critical window.',
			];
		} else {
			$tlsCheck = [
				'id'          => 'wordpress.tls_expiry',
				'plugin'      => 'wordpress',
				'category'    => 'security',
				'title'       => 'WordPress Fleet TLS Certificate Expiry',
				'status'      => 'ok',
				'message'     => $minDays === null
					? 'No TLS certificate expiration issues reported.'
					: sprintf('Minimum WordPress TLS certificate expiry is %d day(s).', $minDays),
				'details'     => ['minExpiryDays' => $minDays, 'expiringCount' => 0],
				'remediation' => '',
			];
		}

		return [$vaultCheck, $fleetCheck, $cronCheck, $tlsCheck];
	}

	/**
	 * Build a strictly redacted list of debug info sections for doctor_register_debug_info.
	 *
	 * Never exposes Application Passwords, raw keyfile bytes, keyfile filesystem path,
	 * or HTTP Authorization headers.
	 *
	 * @param callable(): SecretVault $vaultFactory Lazy SecretVault supplier.
	 * @param callable(): SiteRepository $repoFactory Lazy SiteRepository supplier.
	 * @param callable(): Settings $settingsFactory Lazy Settings supplier.
	 * @return list<array{
	 *   id: string,
	 *   plugin: string,
	 *   label: string,
	 *   fields: array<string, array{label: string, value: bool|float|int|string|null}>
	 * }>
	 */
	public static function buildDebugInfo(
		callable $vaultFactory,
		callable $repoFactory,
		callable $settingsFactory,
	): array {
		$settings    = $settingsFactory();
		$vaultStatus = $vaultFactory()->healthStatus();
		$repo        = $repoFactory();
		$sites       = $repo->listSites();
		$analysis    = (new FleetAnalyzer($settings))->analyze($repo->loadSnapshots());

		return [
			[
				'id'     => 'wordpress.overview',
				'plugin' => 'wordpress',
				'label'  => 'WordPress Fleet Monitor (plugin_wordpress)',
				'fields' => [
					'vault_keyfile'        => ['label' => 'Vault Keyfile', 'value' => $vaultStatus['configured'] ? '[CONFIGURED]' : 'unconfigured'],
					'vault_readable'       => ['label' => 'Vault Readable', 'value' => $vaultStatus['readable']],
					'vault_key_fp'         => ['label' => 'Vault Key Fingerprint', 'value' => $vaultStatus['keyFingerprint'] !== '' ? $vaultStatus['keyFingerprint'] : 'none'],
					'vault_stored_secrets' => ['label' => 'Stored Local Secrets', 'value' => $vaultStatus['storedSecrets']],
					'sites_configured'     => ['label' => 'Sites Configured', 'value' => count($sites)],
					'sites_polled'         => ['label' => 'Sites Polled', 'value' => $analysis['counts']['sites_total']],
					'sites_healthy'        => ['label' => 'Sites Healthy', 'value' => $analysis['counts']['sites_healthy']],
					'sites_degraded'       => ['label' => 'Sites Degraded', 'value' => $analysis['counts']['sites_degraded']],
					'sites_critical'       => ['label' => 'Sites Critical', 'value' => $analysis['counts']['sites_critical']],
					'fleet_apdex'          => ['label' => 'Fleet Apdex', 'value' => $analysis['apdex']['score']],
					'ttfb_p95_ms'          => ['label' => 'Fleet TTFB p95 (ms)', 'value' => $analysis['counts']['ttfb_p95_ms']],
					'updates_pending'      => ['label' => 'Pending Updates', 'value' => $analysis['counts']['updates_pending']],
					'cron_overdue_total'   => ['label' => 'Overdue WP-Cron Jobs', 'value' => $analysis['counts']['cron_overdue_total']],
					'autoload_bloat_sites' => ['label' => 'Autoload Bloat Sites', 'value' => $analysis['counts']['autoload_bloat_sites']],
					'tls_min_expiry_days'  => ['label' => 'Min TLS Expiry (days)', 'value' => $analysis['counts']['tls_min_expiry_days']],
					'poll_interval_sec'    => ['label' => 'Poll Interval (s)', 'value' => $settings->pollInterval],
					'max_response_bytes'   => ['label' => 'Max Response Bytes', 'value' => $settings->maxResponseBytes],
					'allowlist_host_count' => ['label' => 'Allowlisted Host Patterns', 'value' => count($settings->parsedAllowlistHosts())],
					'allowlist_cidr_count' => ['label' => 'Allowlisted CIDRs', 'value' => count($settings->parsedAllowlistCidrs())],
				],
			],
		];
	}
}
