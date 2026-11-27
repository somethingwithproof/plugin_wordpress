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

namespace Somethingwithproof\WordPress\Client;

use Somethingwithproof\WordPress\Log;
use Somethingwithproof\WordPress\Metrics\SiteMetrics;
use Somethingwithproof\WordPress\Security\OutboundGuard;
use Somethingwithproof\WordPress\Security\SecurityException;
use Somethingwithproof\WordPress\Settings;

/**
 * Strictly read-only WordPress REST, Site Health, and runtime telemetry client.
 *
 * Authenticates via HTTP Basic Auth using WordPress Application Passwords retrieved
 * from SecretVault, sends an explicit User-Agent, enforces OutboundGuard SSRF/TLS/byte
 * limits on every GET request, and never executes write HTTP verbs.
 */
final class WordPressClient {
	/**
	 * Core WordPress Site Health test endpoints polled in read-only mode.
	 *
	 * @var list<string>
	 */
	public const SITE_HEALTH_TESTS = [
		'background-updates',
		'loopback-requests',
		'https-status',
		'dotorg-communication',
		'authorization-header',
	];

	/**
	 * Construct a WordPressClient bound to a read-only HttpTransport and OutboundGuard.
	 *
	 * @param HttpTransport $transport Read-only HTTP GET transport.
	 * @param OutboundGuard $guard SSRF, HTTPS, timeout, and byte-cap policy guard.
	 * @param string $userAgent Outbound User-Agent header.
	 * @param Settings|null $settings Threshold settings used when classifying SiteMetrics.
	 */
	public function __construct(
		private readonly HttpTransport $transport,
		private readonly OutboundGuard $guard,
		private readonly string $userAgent = 'Cacti-Plugin-WordPress/0.1.0',
		private readonly ?Settings $settings = null,
	) {
	}

	/**
	 * Poll a WordPress site across /wp-json/, Site Health, plugins/themes, and optional telemetry.
	 *
	 * @param array<string, mixed> $site Site configuration record from plugin_wordpress_sites.
	 * @param string|null $applicationPassword Decrypted WordPress Application Password (null for unauthenticated discovery).
	 * @return SiteMetrics
	 */
	public function pollSite(array $site, ?string $applicationPassword = null): SiteMetrics {
		$slug           = is_string($site['slug'] ?? null) ? $site['slug'] : 'unknown';
		$name           = is_string($site['name'] ?? null) ? $site['name'] : $slug;
		$baseUrl        = rtrim(is_string($site['base_url'] ?? null) ? $site['base_url'] : '', '/');
		$username       = is_string($site['username'] ?? null) ? $site['username'] : '';
		$telemetryPath  = is_string($site['telemetry_path'] ?? null) ? trim($site['telemetry_path']) : '/wp-json/cacti-wp/v1/telemetry';
		$pollerId       = is_numeric($site['poller_id'] ?? null) ? max(1, (int) $site['poller_id']) : 1;
		$verifyTls      = isset($site['verify_tls']) ? (bool) $site['verify_tls'] : $this->guard->verifyTls;
		$allowPrivateIp = isset($site['allow_private_ip']) && (bool) $site['allow_private_ip'];
		$connectTimeout = is_numeric($site['timeout_connect'] ?? null)
			? max(1, min(OutboundGuard::HARD_MAX_CONNECT_TIMEOUT, (int) $site['timeout_connect']))
			: $this->guard->connectTimeout;
		$readTimeout    = is_numeric($site['timeout_read'] ?? null)
			? max(1, min(OutboundGuard::HARD_MAX_READ_TIMEOUT, (int) $site['timeout_read']))
			: $this->guard->readTimeout;
		$apdexTMs       = is_numeric($site['apdex_t_ms'] ?? null) ? max(50, (int) $site['apdex_t_ms']) : ($this->settings !== null ? $this->settings->defaultApdexTMs : 500);

		$headers = [
			'Accept'     => 'application/json',
			'User-Agent' => $this->userAgent,
		];

		if ($username !== '' && is_string($applicationPassword) && $applicationPassword !== '') {
			$headers['Authorization'] = 'Basic ' . base64_encode($username . ':' . $applicationPassword);
		}

		$polledAt      = time();
		$ttfbSamples   = [];
		$tlsExpiryDays = null;

		try {
			$discoveryResp = $this->getChecked($baseUrl . '/wp-json/', $headers, $connectTimeout, $readTimeout, $verifyTls, $allowPrivateIp);
			$ttfbSamples[] = $discoveryResp->ttfbMs;
			$tlsExpiryDays = $discoveryResp->tlsExpiryDays;

			if ($discoveryResp->statusCode < 200 || $discoveryResp->statusCode >= 300) {
				return SiteMetrics::unreachable(
					$slug,
					$name,
					$baseUrl,
					$pollerId,
					sprintf('Discovery endpoint returned HTTP %d.', $discoveryResp->statusCode),
					$polledAt,
					$apdexTMs,
					$discoveryResp->ttfbMs,
					$tlsExpiryDays
				);
			}

			$discovery = self::parseDiscoveryPayload($discoveryResp->body, $discoveryResp->headers);
		} catch (SecurityException $error) {
			return SiteMetrics::unreachable(
				$slug,
				$name,
				$baseUrl,
				$pollerId,
				Log::sanitize($error->getMessage()),
				$polledAt,
				$apdexTMs
			);
		}

		$healthGood        = 0;
		$healthRecommended = 0;
		$healthCritical    = 0;
		$directoryBytes    = 0;
		$healthFindings    = [];

		foreach (self::SITE_HEALTH_TESTS as $testSlug) {
			try {
				$resp = $this->getChecked(
					$baseUrl . '/wp-json/wp-site-health/v1/tests/' . $testSlug,
					$headers,
					$connectTimeout,
					$readTimeout,
					$verifyTls,
					$allowPrivateIp
				);

				if ($resp->statusCode >= 200 && $resp->statusCode < 300) {
					$ttfbSamples[] = $resp->ttfbMs;
					$parsed        = self::parseSiteHealthTestPayload($resp->body);
					$healthGood        += $parsed['good'];
					$healthRecommended += $parsed['recommended'];
					$healthCritical    += $parsed['critical'];

					if ($parsed['status'] !== 'good' && $parsed['label'] !== '') {
						$healthFindings[] = [
							'test'   => $testSlug,
							'status' => $parsed['status'],
							'label'  => $parsed['label'],
						];
					}
				}
			} catch (SecurityException $error) {
				Log::warning(sprintf('Site Health test %s skipped for %s: %s', $testSlug, $slug, $error->getMessage()));
			}
		}

		try {
			$dirResp = $this->getChecked(
				$baseUrl . '/wp-json/wp-site-health/v1/directory-sizes',
				$headers,
				$connectTimeout,
				$readTimeout,
				$verifyTls,
				$allowPrivateIp
			);

			if ($dirResp->statusCode >= 200 && $dirResp->statusCode < 300) {
				$directoryBytes = self::parseDirectorySizesPayload($dirResp->body);
			}
		} catch (SecurityException) {
			// Directory sizes are optional when Site Health permissions are restricted.
		}

		$plugins = ['active' => 0, 'inactive' => 0, 'updatesPending' => 0, 'drift' => []];

		try {
			$pluginResp = $this->getChecked(
				$baseUrl . '/wp-json/wp/v2/plugins',
				$headers,
				$connectTimeout,
				$readTimeout,
				$verifyTls,
				$allowPrivateIp
			);

			if ($pluginResp->statusCode >= 200 && $pluginResp->statusCode < 300) {
				$ttfbSamples[] = $pluginResp->ttfbMs;
				$plugins       = self::parsePluginsPayload($pluginResp->body);
			}
		} catch (SecurityException) {
			// Authenticated plugin inventory is optional when read scope excludes plugins.
		}

		$themes = ['active' => 0, 'inactive' => 0, 'updatesPending' => 0, 'drift' => []];

		try {
			$themeResp = $this->getChecked(
				$baseUrl . '/wp-json/wp/v2/themes',
				$headers,
				$connectTimeout,
				$readTimeout,
				$verifyTls,
				$allowPrivateIp
			);

			if ($themeResp->statusCode >= 200 && $themeResp->statusCode < 300) {
				$ttfbSamples[] = $themeResp->ttfbMs;
				$themes        = self::parseThemesPayload($themeResp->body);
			}
		} catch (SecurityException) {
			// Authenticated theme inventory is optional when read scope excludes themes.
		}

		$telemetry = self::emptyTelemetry();

		if ($telemetryPath !== '' && str_starts_with($telemetryPath, '/')) {
			try {
				$telResp = $this->getChecked(
					$baseUrl . $telemetryPath,
					$headers,
					$connectTimeout,
					$readTimeout,
					$verifyTls,
					$allowPrivateIp
				);

				if ($telResp->statusCode >= 200 && $telResp->statusCode < 300) {
					$ttfbSamples[] = $telResp->ttfbMs;
					$telemetry     = self::parseTelemetryPayload($telResp->body);
				}
			} catch (SecurityException) {
				// Runtime telemetry endpoint is optional.
			}
		}

		if ($telemetry['ttfb_p95_ms'] !== null) {
			$ttfbP95Ms = $telemetry['ttfb_p95_ms'];
		} else {
			$ttfbP95Ms = self::computeP95($ttfbSamples);
		}

		$primaryTtfbMs = $telemetry['homepage_ttfb_ms'] ?? $ttfbSamples[0];

		if ($telemetry['tls_expiry_days'] !== null) {
			$tlsExpiryDays = $telemetry['tls_expiry_days'];
		}

		$settings = $this->settings ?? new Settings();
		$wpVer    = $telemetry['wp_version'] !== '' ? $telemetry['wp_version'] : $discovery['wpVersion'];

		return SiteMetrics::fromObservation([
			'slug'                   => $slug,
			'siteName'               => $discovery['siteName'] !== '' ? $discovery['siteName'] : $name,
			'url'                    => $baseUrl,
			'pollerId'               => $pollerId,
			'wpVersion'              => $wpVer,
			'ttfbMs'                 => $primaryTtfbMs,
			'ttfbP95Ms'              => $ttfbP95Ms,
			'apdexTMs'               => $apdexTMs,
			'ttfbSamples'            => $ttfbSamples,
			'siteHealthGood'         => $healthGood,
			'siteHealthRecommended'  => $healthRecommended,
			'siteHealthCritical'     => $healthCritical,
			'pluginsActive'          => $plugins['active'],
			'pluginsInactive'        => $plugins['inactive'],
			'pluginsUpdatesPending'  => $plugins['updatesPending'],
			'themesActive'           => $themes['active'],
			'themesInactive'         => $themes['inactive'],
			'themesUpdatesPending'   => $themes['updatesPending'],
			'cronOverdueCount'       => $telemetry['cron_overdue_count'],
			'cronOldestLagSeconds'   => $telemetry['cron_oldest_lag_seconds'],
			'autoloadBytes'          => $telemetry['autoload_bytes'],
			'autoloadRows'           => $telemetry['autoload_rows'],
			'objectCacheHitRatio'    => $telemetry['object_cache_hit_ratio'],
			'opcacheHitRatio'        => $telemetry['opcache_hit_ratio'],
			'opcacheMemoryUsedPct'   => $telemetry['opcache_memory_used_pct'],
			'phpFpmActive'           => $telemetry['php_fpm_active'],
			'phpFpmIdle'             => $telemetry['php_fpm_idle'],
			'phpFpmQueued'           => $telemetry['php_fpm_queued'],
			'tlsExpiryDays'          => $tlsExpiryDays,
			'httpErrorRatePct'       => $telemetry['http_error_rate_pct'],
			'xmlrpcExposed'          => $discovery['xmlrpcExposed'],
			'restUsersExposed'       => $discovery['restUsersExposed'],
			'details'                => [
				'namespaces'     => $discovery['namespaces'],
				'directoryBytes' => $directoryBytes,
				'healthFindings' => $healthFindings,
				'pluginDrift'    => $plugins['drift'],
				'themeDrift'     => $themes['drift'],
			],
			'polledAt'               => $polledAt,
		], $settings);
	}

	/**
	 * Parse the /wp-json/ root discovery payload and security exposure signals.
	 *
	 * @param string $json Raw /wp-json/ response body.
	 * @param array<string, string> $headers Lowercase-keyed HTTP response headers.
	 * @return array{siteName: string, wpVersion: string, namespaces: list<string>, xmlrpcExposed: bool, restUsersExposed: bool}
	 */
	public static function parseDiscoveryPayload(string $json, array $headers = []): array {
		$data = self::decodeJsonObject($json);

		$siteName   = isset($data['name']) && is_string($data['name']) ? trim($data['name']) : '';
		$namespaces = [];

		if (isset($data['namespaces']) && is_array($data['namespaces'])) {
			foreach ($data['namespaces'] as $ns) {
				if (is_string($ns) && $ns !== '') {
					$namespaces[] = $ns;
				}
			}
		}

		$wpVersion = '';

		if (isset($data['wp_version']) && is_string($data['wp_version'])) {
			$wpVersion = trim($data['wp_version']);
		} elseif (isset($data['generator']) && is_string($data['generator']) && preg_match('/WordPress\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)/i', $data['generator'], $m) === 1) {
			$wpVersion = $m[1];
		} elseif (isset($headers['x-wp-version']) && is_string($headers['x-wp-version'])) {
			$wpVersion = trim($headers['x-wp-version']);
		}

		$xmlrpcExposed = isset($headers['x-pingback']) && $headers['x-pingback'] !== '';

		if (!$xmlrpcExposed && isset($data['authentication']) && is_array($data['authentication']) && isset($data['authentication']['xmlrpc'])) {
			$xmlrpcExposed = true;
		}

		$restUsersExposed = false;

		if (isset($data['routes']) && is_array($data['routes']) && isset($data['routes']['/wp/v2/users'])) {
			$restUsersExposed = true;
		}

		return [
			'siteName'         => $siteName,
			'wpVersion'        => $wpVersion,
			'namespaces'       => $namespaces,
			'xmlrpcExposed'    => $xmlrpcExposed,
			'restUsersExposed' => $restUsersExposed,
		];
	}

	/**
	 * Parse a single /wp-json/wp-site-health/v1/tests/* JSON payload.
	 *
	 * @param string $json Raw Site Health test JSON body.
	 * @return array{status: string, label: string, good: int, recommended: int, critical: int}
	 */
	public static function parseSiteHealthTestPayload(string $json): array {
		$data   = self::decodeJsonObject($json);
		$status = isset($data['status']) && is_string($data['status']) ? strtolower(trim($data['status'])) : '';
		$label  = isset($data['label']) && is_string($data['label']) ? trim($data['label']) : '';

		if ($status === 'good') {
			return ['status' => 'good', 'label' => $label, 'good' => 1, 'recommended' => 0, 'critical' => 0];
		}

		if ($status === 'recommended') {
			return ['status' => 'recommended', 'label' => $label, 'good' => 0, 'recommended' => 1, 'critical' => 0];
		}

		if ($status === 'critical') {
			return ['status' => 'critical', 'label' => $label, 'good' => 0, 'recommended' => 0, 'critical' => 1];
		}

		return ['status' => 'unknown', 'label' => $label, 'good' => 0, 'recommended' => 0, 'critical' => 0];
	}

	/**
	 * Parse /wp-json/wp-site-health/v1/directory-sizes and return total installation bytes.
	 *
	 * @param string $json Raw directory-sizes JSON body.
	 * @return int Total bytes reported across WordPress directories.
	 */
	public static function parseDirectorySizesPayload(string $json): int {
		$data = self::decodeJsonObject($json);

		if (isset($data['total_size']) && is_array($data['total_size']) && is_numeric($data['total_size']['raw'] ?? null)) {
			return max(0, (int) $data['total_size']['raw']);
		}

		$total = 0;

		foreach ($data as $section => $entry) {
			if ($section === 'total_size' || !is_array($entry)) {
				continue;
			}

			if (is_numeric($entry['raw'] ?? null)) {
				$total += max(0, (int) $entry['raw']);
			}
		}

		return $total;
	}

	/**
	 * Parse /wp-json/wp/v2/plugins into active/inactive counts and pending update drift.
	 *
	 * @param string $json Raw plugins JSON list.
	 * @return array{active: int, inactive: int, updatesPending: int, drift: list<array{slug: string, version: string, newVersion: string}>}
	 */
	public static function parsePluginsPayload(string $json): array {
		$items    = self::decodeJsonList($json);
		$active   = 0;
		$inactive = 0;
		$updates  = 0;
		$drift    = [];

		foreach ($items as $item) {
			$status = isset($item['status']) && is_string($item['status']) ? strtolower($item['status']) : '';

			if ($status === 'active' || $status === 'network-active') {
				$active++;
			} else {
				$inactive++;
			}

			$newVersion = self::extractPendingVersion($item);

			if ($newVersion !== '') {
				$updates++;
				$drift[] = [
					'slug'       => is_string($item['plugin'] ?? null) ? $item['plugin'] : (is_string($item['name'] ?? null) ? $item['name'] : 'unknown'),
					'version'    => is_string($item['version'] ?? null) ? $item['version'] : '',
					'newVersion' => $newVersion,
				];
			}
		}

		return [
			'active'         => $active,
			'inactive'       => $inactive,
			'updatesPending' => $updates,
			'drift'          => $drift,
		];
	}

	/**
	 * Parse /wp-json/wp/v2/themes into active/inactive counts and pending update drift.
	 *
	 * @param string $json Raw themes JSON list.
	 * @return array{active: int, inactive: int, updatesPending: int, drift: list<array{slug: string, version: string, newVersion: string}>}
	 */
	public static function parseThemesPayload(string $json): array {
		$items    = self::decodeJsonList($json);
		$active   = 0;
		$inactive = 0;
		$updates  = 0;
		$drift    = [];

		foreach ($items as $item) {
			$status = isset($item['status']) && is_string($item['status']) ? strtolower($item['status']) : '';

			if ($status === 'active') {
				$active++;
			} else {
				$inactive++;
			}

			$newVersion = self::extractPendingVersion($item);

			if ($newVersion !== '') {
				$updates++;
				$drift[] = [
					'slug'       => is_string($item['stylesheet'] ?? null) ? $item['stylesheet'] : 'unknown',
					'version'    => is_string($item['version'] ?? null) ? $item['version'] : '',
					'newVersion' => $newVersion,
				];
			}
		}

		return [
			'active'         => $active,
			'inactive'       => $inactive,
			'updatesPending' => $updates,
			'drift'          => $drift,
		];
	}

	/**
	 * Parse the optional read-only runtime telemetry JSON payload.
	 *
	 * @param string $json Raw runtime telemetry JSON body.
	 * @return array{
	 *   wp_version: string,
	 *   cron_overdue_count: int,
	 *   cron_oldest_lag_seconds: int,
	 *   autoload_bytes: int,
	 *   autoload_rows: int,
	 *   object_cache_hit_ratio: float|null,
	 *   opcache_hit_ratio: float|null,
	 *   opcache_memory_used_pct: float|null,
	 *   php_fpm_active: int|null,
	 *   php_fpm_idle: int|null,
	 *   php_fpm_queued: int|null,
	 *   tls_expiry_days: int|null,
	 *   homepage_ttfb_ms: float|null,
	 *   ttfb_p95_ms: float|null,
	 *   http_error_rate_pct: float
	 * }
	 */
	public static function parseTelemetryPayload(string $json): array {
		$data = self::decodeJsonObject($json);
		$cron = is_array($data['wp_cron'] ?? null) ? $data['wp_cron'] : [];
		$auto = is_array($data['autoload'] ?? null) ? $data['autoload'] : [];
		$oc   = is_array($data['object_cache'] ?? null) ? $data['object_cache'] : [];
		$opc  = is_array($data['opcache'] ?? null) ? $data['opcache'] : [];
		$fpm  = is_array($data['php_fpm'] ?? null) ? $data['php_fpm'] : [];
		$http = is_array($data['http'] ?? null) ? $data['http'] : [];

		return [
			'wp_version'              => is_string($data['wp_version'] ?? null) ? trim($data['wp_version']) : '',
			'cron_overdue_count'      => self::nonNegInt($cron['overdue_count'] ?? ($data['cron_overdue_count'] ?? 0)),
			'cron_oldest_lag_seconds' => self::nonNegInt($cron['oldest_lag_seconds'] ?? ($data['cron_oldest_lag_seconds'] ?? 0)),
			'autoload_bytes'          => self::nonNegInt($auto['bytes'] ?? ($data['autoload_bytes'] ?? 0)),
			'autoload_rows'           => self::nonNegInt($auto['rows'] ?? ($data['autoload_rows'] ?? 0)),
			'object_cache_hit_ratio'  => self::nullablePercent($oc['hit_ratio_pct'] ?? ($data['object_cache_hit_ratio'] ?? null)),
			'opcache_hit_ratio'       => self::nullablePercent($opc['hit_ratio_pct'] ?? ($data['opcache_hit_ratio'] ?? null)),
			'opcache_memory_used_pct' => self::nullablePercent($opc['memory_used_pct'] ?? ($data['opcache_memory_used_pct'] ?? null)),
			'php_fpm_active'          => self::nullableNonNegInt($fpm['active'] ?? ($data['php_fpm_active'] ?? null)),
			'php_fpm_idle'            => self::nullableNonNegInt($fpm['idle'] ?? ($data['php_fpm_idle'] ?? null)),
			'php_fpm_queued'          => self::nullableNonNegInt($fpm['queued'] ?? ($data['php_fpm_queued'] ?? null)),
			'tls_expiry_days'         => is_numeric($data['tls_expiry_days'] ?? null) ? (int) $data['tls_expiry_days'] : null,
			'homepage_ttfb_ms'        => self::nullableNonNegFloat($http['homepage_ttfb_ms'] ?? ($data['homepage_ttfb_ms'] ?? null)),
			'ttfb_p95_ms'             => self::nullableNonNegFloat($http['ttfb_p95_ms'] ?? ($data['ttfb_p95_ms'] ?? null)),
			'http_error_rate_pct'     => self::clampPercent($http['error_rate_pct'] ?? ($data['http_error_rate_pct'] ?? 0.0)),
		];
	}

	/**
	 * Validate URL via OutboundGuard, execute read-only GET, and assert response compliance.
	 *
	 * @param string $url Target endpoint URL.
	 * @param array<string, string> $headers Request headers.
	 * @param int $connectTimeout Bounded connect timeout in seconds.
	 * @param int $readTimeout Bounded read timeout in seconds.
	 * @param bool $verifyTls Enforce TLS certificate verification.
	 * @param bool $allowPrivateIp Site-level internal allowlist opt-in.
	 * @return HttpResponse
	 * @throws SecurityException On SSRF, redirect, TLS, or payload-cap violation.
	 */
	private function getChecked(
		string $url,
		array $headers,
		int $connectTimeout,
		int $readTimeout,
		bool $verifyTls,
		bool $allowPrivateIp,
	): HttpResponse {
		$validated = $this->guard->validateUrl($url, $allowPrivateIp);
		$response  = $this->transport->get(
			$validated['url'],
			$headers,
			$connectTimeout,
			$readTimeout,
			$this->guard->maxResponseBytes,
			$verifyTls,
			$validated['pinnedIp']
		);
		$this->guard->assertResponseAllowed($response->statusCode, $response->bytes());

		return $response;
	}

	/**
	 * Return default empty telemetry structure when optional telemetry endpoint is unavailable.
	 *
	 * @return array{
	 *   wp_version: string,
	 *   cron_overdue_count: int,
	 *   cron_oldest_lag_seconds: int,
	 *   autoload_bytes: int,
	 *   autoload_rows: int,
	 *   object_cache_hit_ratio: float|null,
	 *   opcache_hit_ratio: float|null,
	 *   opcache_memory_used_pct: float|null,
	 *   php_fpm_active: int|null,
	 *   php_fpm_idle: int|null,
	 *   php_fpm_queued: int|null,
	 *   tls_expiry_days: int|null,
	 *   homepage_ttfb_ms: float|null,
	 *   ttfb_p95_ms: float|null,
	 *   http_error_rate_pct: float
	 * }
	 */
	private static function emptyTelemetry(): array {
		return [
			'wp_version'              => '',
			'cron_overdue_count'      => 0,
			'cron_oldest_lag_seconds' => 0,
			'autoload_bytes'          => 0,
			'autoload_rows'           => 0,
			'object_cache_hit_ratio'  => null,
			'opcache_hit_ratio'       => null,
			'opcache_memory_used_pct' => null,
			'php_fpm_active'          => null,
			'php_fpm_idle'            => null,
			'php_fpm_queued'          => null,
			'tls_expiry_days'         => null,
			'homepage_ttfb_ms'        => null,
			'ttfb_p95_ms'             => null,
			'http_error_rate_pct'     => 0.0,
		];
	}

	/**
	 * Decode a JSON string into an associative object array, returning empty array on invalid JSON.
	 *
	 * @param string $json Raw JSON text.
	 * @return array<string, mixed>
	 */
	private static function decodeJsonObject(string $json): array {
		if ($json === '') {
			return [];
		}

		$decoded = json_decode($json, true);

		if (!is_array($decoded) || array_is_list($decoded)) {
			return [];
		}

		/** @var array<string, mixed> $typed */
		$typed = $decoded;

		return $typed;
	}

	/**
	 * Decode a JSON string into a list of associative object arrays.
	 *
	 * @param string $json Raw JSON array text.
	 * @return list<array<string, mixed>>
	 */
	private static function decodeJsonList(string $json): array {
		if ($json === '') {
			return [];
		}

		$decoded = json_decode($json, true);

		if (!is_array($decoded)) {
			return [];
		}

		$items = [];

		foreach ($decoded as $entry) {
			if (is_array($entry)) {
				/** @var array<string, mixed> $typed */
				$typed   = $entry;
				$items[] = $typed;
			}
		}

		return $items;
	}

	/**
	 * Extract a pending update version string from a WordPress plugin or theme item.
	 *
	 * @param array<string, mixed> $item Decoded plugin or theme JSON record.
	 * @return string Pending version string, or empty string when up to date.
	 */
	private static function extractPendingVersion(array $item): string {
		if (isset($item['update']) && is_array($item['update']) && isset($item['update']['version']) && is_string($item['update']['version'])) {
			return trim($item['update']['version']);
		}

		if (isset($item['new_version']) && is_string($item['new_version']) && trim($item['new_version']) !== '') {
			return trim($item['new_version']);
		}

		if (isset($item['update_available']) && $item['update_available'] === true) {
			return 'available';
		}

		return '';
	}

	/**
	 * Compute the 95th percentile of a non-empty latency sample list.
	 *
	 * @param list<float> $samples Latency samples in milliseconds.
	 * @return float
	 */
	private static function computeP95(array $samples): float {
		$count = count($samples);

		if ($count === 0) {
			return 0.0;
		}

		sort($samples, SORT_NUMERIC);
		$idx = (int) ceil(0.95 * $count) - 1;
		$idx = max(0, min($count - 1, $idx));

		return round($samples[$idx], 2);
	}

	/**
	 * Coerce a numeric value to a non-negative integer.
	 *
	 * @param mixed $val Raw input.
	 * @return int
	 */
	private static function nonNegInt(mixed $val): int {
		return is_numeric($val) ? max(0, (int) $val) : 0;
	}

	/**
	 * Coerce a nullable numeric value to a non-negative integer or null.
	 *
	 * @param mixed $val Raw input.
	 * @return int|null
	 */
	private static function nullableNonNegInt(mixed $val): ?int {
		return is_numeric($val) ? max(0, (int) $val) : null;
	}

	/**
	 * Coerce a nullable numeric value to a non-negative float or null.
	 *
	 * @param mixed $val Raw input.
	 * @return float|null
	 */
	private static function nullableNonNegFloat(mixed $val): ?float {
		return is_numeric($val) ? round(max(0.0, (float) $val), 2) : null;
	}

	/**
	 * Coerce a nullable numeric percentage to 0..100 float or null.
	 *
	 * @param mixed $val Raw input.
	 * @return float|null
	 */
	private static function nullablePercent(mixed $val): ?float {
		if (!is_numeric($val)) {
			return null;
		}

		return round(max(0.0, min(100.0, (float) $val)), 2);
	}

	/**
	 * Coerce a numeric percentage to 0..100 float with 0.0 fallback.
	 *
	 * @param mixed $val Raw input.
	 * @return float
	 */
	private static function clampPercent(mixed $val): float {
		if (!is_numeric($val)) {
			return 0.0;
		}

		return round(max(0.0, min(100.0, (float) $val)), 2);
	}
}
