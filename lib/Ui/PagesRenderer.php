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

namespace Somethingwithproof\WordPress\Ui;

use Somethingwithproof\WordPress\Metrics\SiteMetrics;
use Somethingwithproof\WordPress\Security\SecretVault;
use Somethingwithproof\WordPress\Settings;

/**
 * HTML renderer for the three RBAC-separated plugin_wordpress Console views
 * (View, Operator, Admin). Escapes all dynamic text via html_escape() and
 * never outputs Application Passwords or vault ciphertexts.
 */
final class PagesRenderer {
	/**
	 * Render the WordPress View Console dashboard (read-only fleet overview).
	 *
	 * @param array<string, mixed> $analysis Output of FleetAnalyzer::analyze().
	 * @param list<SiteMetrics> $snapshots Latest site snapshots.
	 * @param list<array<string, mixed>> $tholdTemplates Baseline Thold definitions.
	 * @return string Safe HTML markup.
	 */
	public static function renderViewConsole(array $analysis, array $snapshots, array $tholdTemplates): string {
		$counts  = is_array($analysis['counts'] ?? null) ? $analysis['counts'] : [];
		$apdex   = is_array($analysis['apdex'] ?? null) ? $analysis['apdex'] : [];
		$latency = is_array($analysis['latency'] ?? null) ? $analysis['latency'] : [];

		$html  = '<div class="wordpress-fleet-view">';
		$html .= '<h3>' . html_escape(__('Fleet Health Summary', 'wordpress')) . '</h3>';
		$html .= '<table class="cactiTable"><thead><tr>'
			. '<th>Sites</th><th>Healthy</th><th>Degraded</th><th>Critical</th>'
			. '<th>Apdex</th><th>p95 TTFB (ms)</th><th>Pending Updates</th>'
			. '<th>Overdue Cron</th><th>Autoload Bloat</th><th>Min TLS Days</th>'
			. '</tr></thead><tbody><tr>'
			. '<td>' . html_escape(self::str($counts['sites_total'] ?? 0)) . '</td>'
			. '<td>' . html_escape(self::str($counts['sites_healthy'] ?? 0)) . '</td>'
			. '<td>' . html_escape(self::str($counts['sites_degraded'] ?? 0)) . '</td>'
			. '<td>' . html_escape(self::str($counts['sites_critical'] ?? 0)) . '</td>'
			. '<td>' . html_escape(sprintf('%.2f (%s)', self::flt($apdex['score'] ?? 0.0), self::str($apdex['rating'] ?? 'n/a'))) . '</td>'
			. '<td>' . html_escape(sprintf('%.2f', self::flt($counts['ttfb_p95_ms'] ?? 0.0))) . '</td>'
			. '<td>' . html_escape(self::str($counts['updates_pending'] ?? 0)) . '</td>'
			. '<td>' . html_escape(self::str($counts['cron_overdue_total'] ?? 0)) . '</td>'
			. '<td>' . html_escape(self::str($counts['autoload_bloat_sites'] ?? 0)) . '</td>'
			. '<td>' . html_escape(isset($counts['tls_min_expiry_days']) ? self::str($counts['tls_min_expiry_days']) : 'n/a') . '</td>'
			. '</tr></tbody></table>';

		$anomalies = is_array($latency['anomalies'] ?? null) ? $latency['anomalies'] : [];

		if ($anomalies !== []) {
			$html .= '<h4>' . html_escape(__('MAD Latency Anomalies', 'wordpress')) . '</h4><ul>';

			foreach ($anomalies as $item) {
				if (is_array($item)) {
					$html .= '<li>' . html_escape(sprintf(
						'%s: %.2f ms (modified z=%.2f)',
						self::str($item['slug'] ?? ''),
						self::flt($item['ttfbMs'] ?? 0.0),
						self::flt($item['modifiedZ'] ?? 0.0)
					)) . '</li>';
				}
			}

			$html .= '</ul>';
		}

		$html .= '<h3>' . html_escape(__('Site Snapshots', 'wordpress')) . '</h3>';
		$html .= '<table class="cactiTable"><thead><tr>'
			. '<th>Slug</th><th>Status</th><th>WP</th><th>TTFB (ms)</th><th>Apdex</th>'
			. '<th>Health (G/R/C)</th><th>Updates</th><th>Cron Overdue</th><th>Autoload (KiB)</th><th>TLS Days</th>'
			. '</tr></thead><tbody>';

		foreach ($snapshots as $snap) {
			$html .= '<tr>'
				. '<td>' . html_escape($snap->slug) . '</td>'
				. '<td>' . html_escape($snap->status) . '</td>'
				. '<td>' . html_escape($snap->wpVersion !== '' ? $snap->wpVersion : '-') . '</td>'
				. '<td>' . html_escape(sprintf('%.2f', $snap->ttfbMs)) . '</td>'
				. '<td>' . html_escape(sprintf('%.2f', $snap->apdexScore)) . '</td>'
				. '<td>' . html_escape(sprintf('%d/%d/%d', $snap->siteHealthGood, $snap->siteHealthRecommended, $snap->siteHealthCritical)) . '</td>'
				. '<td>' . html_escape((string) $snap->totalUpdatesPending()) . '</td>'
				. '<td>' . html_escape((string) $snap->cronOverdueCount) . '</td>'
				. '<td>' . html_escape(sprintf('%.1f', $snap->autoloadBytes / 1024.0)) . '</td>'
				. '<td>' . html_escape($snap->tlsExpiryDays !== null ? (string) $snap->tlsExpiryDays : '-') . '</td>'
				. '</tr>';
		}

		$html .= '</tbody></table>';

		$html .= '<h3>' . html_escape(__('Cacti Thold Baseline Templates', 'wordpress')) . '</h3><ul>';

		foreach ($tholdTemplates as $tpl) {
			$html .= '<li><strong>' . html_escape(self::str($tpl['name'] ?? '')) . '</strong> ('
				. html_escape(self::str($tpl['metricField'] ?? '')) . '): '
				. html_escape(self::str($tpl['rationale'] ?? '')) . '</li>';
		}

		$html .= '</ul></div>';

		return $html;
	}

	/**
	 * Render the WordPress Operator Console (drift, Site Health, cron, autoload inspection, and CSRF dry-run probe).
	 *
	 * @param string $csrfHiddenField Hidden CSRF input markup.
	 * @param list<array<string, mixed>> $sites Configured site inventory.
	 * @param array<string, mixed> $analysis Fleet analysis map.
	 * @param SiteMetrics|null $probeResult Optional result from an operator dry-run probe.
	 * @param list<string> $messages Informational notices.
	 * @param list<string> $errors Validation or runtime errors.
	 * @return string Safe HTML markup.
	 */
	public static function renderOperatorConsole(
		string $csrfHiddenField,
		array $sites,
		array $analysis,
		?SiteMetrics $probeResult,
		array $messages,
		array $errors,
	): string {
		$html  = self::renderNotices($messages, $errors);
		$html .= '<form method="post" action="wordpress_operator.php">';
		$html .= $csrfHiddenField;
		$html .= '<input type="hidden" name="action" value="dry_run_probe">';
		$html .= '<label for="wp_probe_slug">' . html_escape(__('Dry-Run Probe Site:', 'wordpress')) . '</label> ';
		$html .= '<select id="wp_probe_slug" name="site_slug">';

		foreach ($sites as $site) {
			$slug  = self::str($site['slug'] ?? '');
			$name  = self::str($site['name'] ?? $slug);
			$html .= '<option value="' . html_escape($slug) . '">' . html_escape($slug . ' (' . $name . ')') . '</option>';
		}

		$html .= '</select> <button type="submit">' . html_escape(__('Run Read-Only Probe', 'wordpress')) . '</button></form>';

		if ($probeResult !== null) {
			$html .= '<h3>' . html_escape(__('Latest Dry-Run Probe Result', 'wordpress')) . '</h3>';
			$html .= '<pre>' . html_escape((string) json_encode($probeResult->toArray(), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)) . '</pre>';
		}

		$drift = is_array($analysis['updateDrift'] ?? null) ? $analysis['updateDrift'] : [];
		$html .= '<h3>' . html_escape(__('Update Drift, Cron Stalls & Autoload Bloat', 'wordpress')) . '</h3>';
		$html .= '<p>' . html_escape(sprintf(
			'Latest WP Core: %s | Sites behind core: %d | Total pending updates: %d',
			self::str($drift['latestWpVersion'] ?? 'n/a'),
			self::intVal($drift['sitesBehindCore'] ?? 0),
			self::intVal($drift['totalPending'] ?? 0)
		)) . '</p>';

		return $html;
	}

	/**
	 * Render the WordPress Admin Console (site inventory CRUD, write-only vault secret form, poller assignment).
	 *
	 * @param string $csrfHiddenField Hidden CSRF input markup.
	 * @param list<array<string, mixed>> $sites Configured sites.
	 * @param array<string, bool> $secretPresence Map of site slug => whether encrypted secret is stored.
	 * @param array<string, mixed> $vaultHealth Non-secret vault diagnostic status.
	 * @param Settings $settings Active plugin settings.
	 * @param list<string> $messages Informational notices.
	 * @param list<string> $errors Validation or runtime errors.
	 * @return string Safe HTML markup.
	 */
	public static function renderAdminConsole(
		string $csrfHiddenField,
		array $sites,
		array $secretPresence,
		array $vaultHealth,
		Settings $settings,
		array $messages,
		array $errors,
	): string {
		$html  = self::renderNotices($messages, $errors);
		$html .= '<p><strong>' . html_escape(__('Vault Status:', 'wordpress')) . '</strong> '
			. html_escape(!empty($vaultHealth['readable'])
				? sprintf('Active (fingerprint %s, %d secret(s) stored locally)', self::str($vaultHealth['keyFingerprint'] ?? ''), self::intVal($vaultHealth['storedSecrets'] ?? 0))
				: self::str($vaultHealth['error'] ?? 'Unconfigured'))
			. '</p>';

		$html .= '<h3>' . html_escape(__('Add or Update WordPress Site', 'wordpress')) . '</h3>';
		$html .= '<form method="post" action="wordpress_admin.php">'
			. $csrfHiddenField
			. '<input type="hidden" name="action" value="save_site">'
			. 'Slug: <input type="text" name="slug" required pattern="[a-z0-9][a-z0-9_-]{1,63}"> '
			. 'Name: <input type="text" name="name" required maxlength="128"> '
			. 'HTTPS URL: <input type="url" name="base_url" required placeholder="https://wp.example.com"> '
			. 'Username: <input type="text" name="username" required maxlength="128"> '
			. 'Poller ID: <input type="number" name="poller_id" min="1" value="1"> '
			. 'Application Password (write-only): <input type="password" name="app_password" autocomplete="new-password"> '
			. '<button type="submit">' . html_escape(__('Save Site', 'wordpress')) . '</button>'
			. '</form>';

		$html .= '<h3>' . html_escape(__('Configured Fleet Inventory', 'wordpress')) . '</h3>';
		$html .= '<table class="cactiTable"><thead><tr>'
			. '<th>Slug</th><th>Name</th><th>URL</th><th>Poller</th><th>Secret Ref</th><th>Vault Stored</th><th>Action</th>'
			. '</tr></thead><tbody>';

		foreach ($sites as $site) {
			$slug   = self::str($site['slug'] ?? '');
			$stored = !empty($secretPresence[$slug]);
			$html  .= '<tr>'
				. '<td>' . html_escape($slug) . '</td>'
				. '<td>' . html_escape(self::str($site['name'] ?? '')) . '</td>'
				. '<td>' . html_escape(self::str($site['base_url'] ?? '')) . '</td>'
				. '<td>' . html_escape(self::str($site['poller_id'] ?? 1)) . '</td>'
				. '<td>' . html_escape(SecretVault::referenceFor($slug)) . '</td>'
				. '<td>' . html_escape($stored ? 'yes' : 'no') . '</td>'
				. '<td><form method="post" action="wordpress_admin.php">'
				. $csrfHiddenField
				. '<input type="hidden" name="action" value="delete_site">'
				. '<input type="hidden" name="slug" value="' . html_escape($slug) . '">'
				. '<button type="submit">' . html_escape(__('Delete', 'wordpress')) . '</button></form></td>'
				. '</tr>';
		}

		$html .= '</tbody></table>';
		$html .= '<p>' . html_escape(sprintf(
			'Active policy: poll_interval=%ds, connect_timeout=%ds, read_timeout=%ds, max_response_bytes=%d',
			$settings->pollInterval,
			$settings->connectTimeout,
			$settings->readTimeout,
			$settings->maxResponseBytes
		)) . '</p>';

		return $html;
	}

	/**
	 * Render escaped informational and error message banners.
	 *
	 * @param list<string> $messages Informational notices.
	 * @param list<string> $errors Error messages.
	 * @return string
	 */
	private static function renderNotices(array $messages, array $errors): string {
		$html = '';

		foreach ($messages as $msg) {
			$html .= '<div class="messageBox">' . html_escape($msg) . '</div>';
		}

		foreach ($errors as $err) {
			$html .= '<div class="messageBox error">' . html_escape($err) . '</div>';
		}

		return $html;
	}

	/**
	 * Safely coerce a mixed scalar value to string.
	 *
	 * @param mixed $val Raw value.
	 * @return string
	 */
	private static function str(mixed $val): string {
		return is_scalar($val) ? (string) $val : '';
	}

	/**
	 * Safely coerce a mixed numeric value to float.
	 *
	 * @param mixed $val Raw value.
	 * @return float
	 */
	private static function flt(mixed $val): float {
		return is_numeric($val) ? (float) $val : 0.0;
	}

	/**
	 * Safely coerce a mixed numeric value to int.
	 *
	 * @param mixed $val Raw value.
	 * @return int
	 */
	private static function intVal(mixed $val): int {
		return is_numeric($val) ? (int) $val : 0;
	}
}
