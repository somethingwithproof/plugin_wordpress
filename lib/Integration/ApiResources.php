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
use Somethingwithproof\WordPress\Pages;
use Somethingwithproof\WordPress\Repository\SiteRepository;
use Somethingwithproof\WordPress\Security\SecretVault;
use Somethingwithproof\WordPress\Settings;

/**
 * Plain-array resource descriptors for the api_register_resources hook exposing
 * read-only wordpressSites and wordpressHealth collections without importing
 * any external API plugin classes at boot.
 */
final class ApiResources {
	/**
	 * Build plain-array API resource descriptors for wordpressSites and wordpressHealth.
	 *
	 * @param callable(): SiteRepository $repoFactory Lazy SiteRepository supplier.
	 * @param callable(): Settings $settingsFactory Lazy Settings supplier.
	 * @return list<array<string, mixed>>
	 */
	public static function build(callable $repoFactory, callable $settingsFactory): array {
		return [
			[
				'plugin'      => 'wordpress',
				'collection'  => 'wordpressSites',
				'version'     => 'v1',
				'readOnly'    => true,
				'realm_read'  => Pages::VIEW,
				'description' => 'Monitored WordPress site inventory (non-secret; credentials represented as vault references).',
				'fields'      => [
					'slug'      => ['type' => 'string'],
					'name'      => ['type' => 'string'],
					'base_url'  => ['type' => 'string'],
					'poller_id' => ['type' => 'integer'],
					'enabled'   => ['type' => 'boolean'],
					'secretRef' => ['type' => 'string'],
				],
				'handlers' => [
					'list' => static function () use ($repoFactory): array {
						$rows = [];

						foreach ($repoFactory()->listSites() as $site) {
							$slug   = (string) $site['slug'];
							$rows[] = [
								'slug'       => $slug,
								'name'       => (string) $site['name'],
								'base_url'   => (string) $site['base_url'],
								'poller_id'  => (int) $site['poller_id'],
								'enabled'    => (bool) $site['enabled'],
								'verify_tls' => (bool) $site['verify_tls'],
								'apdex_t_ms' => (int) $site['apdex_t_ms'],
								'secretRef'  => SecretVault::referenceFor($slug),
							];
						}

						return $rows;
					},
					'get' => static function (string $id) use ($repoFactory): ?array {
						$site = $repoFactory()->findSite($id);

						if ($site === null) {
							return null;
						}

						$slug = (string) $site['slug'];

						return [
							'slug'       => $slug,
							'name'       => (string) $site['name'],
							'base_url'   => (string) $site['base_url'],
							'poller_id'  => (int) $site['poller_id'],
							'enabled'    => (bool) $site['enabled'],
							'verify_tls' => (bool) $site['verify_tls'],
							'apdex_t_ms' => (int) $site['apdex_t_ms'],
							'secretRef'  => SecretVault::referenceFor($slug),
						];
					},
				],
			],
			[
				'plugin'      => 'wordpress',
				'collection'  => 'wordpressHealth',
				'version'     => 'v1',
				'readOnly'    => true,
				'realm_read'  => Pages::VIEW,
				'description' => 'WordPress fleet and per-site health telemetry snapshots, Apdex scores, and anomaly flags.',
				'fields'      => [
					'slug'             => ['type' => 'string'],
					'status'           => ['type' => 'string'],
					'wpVersion'        => ['type' => 'string'],
					'ttfbMs'           => ['type' => 'number'],
					'ttfbP95Ms'        => ['type' => 'number'],
					'apdexScore'       => ['type' => 'number'],
					'updatesPending'   => ['type' => 'integer'],
					'cronOverdueCount' => ['type' => 'integer'],
					'autoloadBytes'    => ['type' => 'integer'],
					'tlsExpiryDays'    => ['type' => 'integer'],
				],
				'handlers' => [
					'list' => static function () use ($repoFactory): array {
						$rows = [];

						foreach ($repoFactory()->loadSnapshots() as $snap) {
							$rows[] = $snap->toArray();
						}

						return $rows;
					},
					'get' => static function (string $id) use ($repoFactory, $settingsFactory): ?array {
						if ($id === 'fleet') {
							return (new FleetAnalyzer($settingsFactory()))->analyze($repoFactory()->loadSnapshots());
						}

						$snap = $repoFactory()->findSnapshot($id);

						return $snap?->toArray();
					},
				],
			],
		];
	}
}
