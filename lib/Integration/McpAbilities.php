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
 * Registers strictly read-only WordPress fleet observability abilities via the
 * abilities_register hook without importing any external MCP plugin classes.
 */
final class McpAbilities {
	/**
	 * Read-only safety annotations attached to all WordPress abilities.
	 */
	private const ANNOTATIONS = [
		'readOnly'    => true,
		'destructive' => false,
		'idempotent'  => true,
	];

	/**
	 * Maximum list elements permitted in ability output array schemas.
	 */
	private const MAX_ARRAY_ITEMS = 500;

	/**
	 * Register wordpress-list-sites, wordpress-get-health, and wordpress-get-drift.
	 *
	 * Every array schema explicitly declares both items and maxItems.
	 *
	 * @param object $registrar Duck-typed registrar exposing register(string $id, array $spec).
	 * @param callable(): SiteRepository $repoFactory Lazy SiteRepository supplier.
	 * @param callable(): Settings $settingsFactory Lazy Settings supplier.
	 * @param callable(int): bool $permissionCheck Cacti user ID DB realm permission callback.
	 * @return void
	 */
	public static function register(
		object $registrar,
		callable $repoFactory,
		callable $settingsFactory,
		callable $permissionCheck,
	): void {
		if (!method_exists($registrar, 'register')) {
			return;
		}

		$registrar->register('wordpress-list-sites', [
			'label'        => 'List WordPress sites',
			'description'  => 'List monitored WordPress site inventory records and latest health statuses without exposing Application Passwords.',
			'category'     => 'monitoring',
			'input_schema' => [
				'type'       => 'object',
				'properties' => [
					'poller_id' => ['type' => 'integer', 'minimum' => 1],
				],
				'additionalProperties' => false,
			],
			'output_schema' => [
				'type'       => 'object',
				'properties' => [
					'sites' => [
						'type'     => 'array',
						'maxItems' => self::MAX_ARRAY_ITEMS,
						'items'    => [
							'type'       => 'object',
							'properties' => [
								'slug'       => ['type' => 'string', 'maxLength' => 64],
								'name'       => ['type' => 'string', 'maxLength' => 128],
								'baseUrl'    => ['type' => 'string', 'maxLength' => 255],
								'pollerId'   => ['type' => 'integer', 'minimum' => 1],
								'enabled'    => ['type' => 'boolean'],
								'secretRef'  => ['type' => 'string', 'maxLength' => 96],
								'status'     => ['type' => 'string', 'maxLength' => 32],
								'wpVersion'  => ['type' => 'string', 'maxLength' => 32],
								'ttfbMs'     => ['type' => 'number', 'minimum' => 0],
								'apdexScore' => ['type' => 'number', 'minimum' => 0, 'maximum' => 1],
							],
							'required'             => ['slug', 'name', 'baseUrl', 'pollerId', 'enabled', 'secretRef', 'status', 'wpVersion', 'ttfbMs', 'apdexScore'],
							'additionalProperties' => false,
						],
					],
				],
				'required'             => ['sites'],
				'additionalProperties' => false,
			],
			'annotations' => self::ANNOTATIONS,
			'permission'  => $permissionCheck,
			'execute'     => static function (int $userId, \stdClass $args) use ($repoFactory): array {
				$pollerId  = isset($args->poller_id) && is_numeric($args->poller_id) ? max(1, (int) $args->poller_id) : null;
				$repo      = $repoFactory();
				$snapshots = [];

				foreach ($repo->loadSnapshots($pollerId) as $snap) {
					$snapshots[$snap->slug] = $snap;
				}

				$items = [];

				foreach ($repo->listSites($pollerId) as $site) {
					if (count($items) >= self::MAX_ARRAY_ITEMS) {
						break;
					}

					$slug    = (string) $site['slug'];
					$snap    = $snapshots[$slug] ?? null;
					$items[] = [
						'slug'       => $slug,
						'name'       => (string) $site['name'],
						'baseUrl'    => (string) $site['base_url'],
						'pollerId'   => (int) $site['poller_id'],
						'enabled'    => (bool) $site['enabled'],
						'secretRef'  => SecretVault::referenceFor($slug),
						'status'     => $snap !== null ? $snap->status : 'unpolled',
						'wpVersion'  => $snap !== null ? $snap->wpVersion : '',
						'ttfbMs'     => $snap !== null ? $snap->ttfbMs : 0.0,
						'apdexScore' => $snap !== null ? $snap->apdexScore : 0.0,
					];
				}

				return ['sites' => $items];
			},
		]);

		$registrar->register('wordpress-get-health', [
			'label'        => 'Get WordPress fleet health',
			'description'  => 'Return aggregate fleet health counts, Apdex score, MAD latency anomalies, autoload bloat, WP-Cron stalls, and TLS expiry summary.',
			'category'     => 'monitoring',
			'input_schema' => [
				'type'       => 'object',
				'properties' => [
					'poller_id' => ['type' => 'integer', 'minimum' => 1],
				],
				'additionalProperties' => false,
			],
			'output_schema' => [
				'type'       => 'object',
				'properties' => [
					'counts'  => ['type' => 'object'],
					'apdex'   => ['type' => 'object'],
					'latency' => [
						'type'       => 'object',
						'properties' => [
							'medianMs'     => ['type' => 'number'],
							'madMs'        => ['type' => 'number'],
							'p95Ms'        => ['type' => 'number'],
							'anomalyCount' => ['type' => 'integer', 'minimum' => 0],
							'anomalies'    => [
								'type'     => 'array',
								'maxItems' => 50,
								'items'    => [
									'type'       => 'object',
									'properties' => [
										'slug'      => ['type' => 'string', 'maxLength' => 64],
										'ttfbMs'    => ['type' => 'number'],
										'modifiedZ' => ['type' => 'number'],
									],
									'required'             => ['slug', 'ttfbMs', 'modifiedZ'],
									'additionalProperties' => false,
								],
							],
						],
						'required'             => ['medianMs', 'madMs', 'p95Ms', 'anomalyCount', 'anomalies'],
						'additionalProperties' => false,
					],
					'cronStalls' => [
						'type'     => 'array',
						'maxItems' => 50,
						'items'    => [
							'type'       => 'object',
							'properties' => [
								'slug'         => ['type' => 'string', 'maxLength' => 64],
								'overdue'      => ['type' => 'integer', 'minimum' => 0],
								'oldestLagSec' => ['type' => 'integer', 'minimum' => 0],
								'severity'     => ['type' => 'string', 'maxLength' => 16],
							],
							'required'             => ['slug', 'overdue', 'oldestLagSec', 'severity'],
							'additionalProperties' => false,
						],
					],
					'autoloadBloat' => [
						'type'     => 'array',
						'maxItems' => 50,
						'items'    => [
							'type'       => 'object',
							'properties' => [
								'slug'     => ['type' => 'string', 'maxLength' => 64],
								'bytes'    => ['type' => 'integer', 'minimum' => 0],
								'rows'     => ['type' => 'integer', 'minimum' => 0],
								'severity' => ['type' => 'string', 'maxLength' => 16],
							],
							'required'             => ['slug', 'bytes', 'rows', 'severity'],
							'additionalProperties' => false,
						],
					],
					'tlsExpiring' => [
						'type'     => 'array',
						'maxItems' => 50,
						'items'    => [
							'type'       => 'object',
							'properties' => [
								'slug'          => ['type' => 'string', 'maxLength' => 64],
								'daysRemaining' => ['type' => 'integer'],
								'severity'      => ['type' => 'string', 'maxLength' => 16],
							],
							'required'             => ['slug', 'daysRemaining', 'severity'],
							'additionalProperties' => false,
						],
					],
				],
				'required'             => ['counts', 'apdex', 'latency', 'cronStalls', 'autoloadBloat', 'tlsExpiring'],
				'additionalProperties' => false,
			],
			'annotations' => self::ANNOTATIONS,
			'permission'  => $permissionCheck,
			'execute'     => static function (int $userId, \stdClass $args) use ($repoFactory, $settingsFactory): array {
				$pollerId = isset($args->poller_id) && is_numeric($args->poller_id) ? max(1, (int) $args->poller_id) : null;
				$analysis = (new FleetAnalyzer($settingsFactory()))->analyze($repoFactory()->loadSnapshots($pollerId));

				return [
					'counts'        => $analysis['counts'],
					'apdex'         => $analysis['apdex'],
					'latency'       => $analysis['latency'],
					'cronStalls'    => $analysis['cronStalls'],
					'autoloadBloat' => $analysis['autoloadBloat'],
					'tlsExpiring'   => $analysis['tlsExpiring'],
				];
			},
		]);

		$driftEntrySchema = [
			'type'       => 'object',
			'properties' => [
				'slug'       => ['type' => 'string', 'maxLength' => 128],
				'version'    => ['type' => 'string', 'maxLength' => 32],
				'newVersion' => ['type' => 'string', 'maxLength' => 32],
			],
			'required'             => ['slug', 'version', 'newVersion'],
			'additionalProperties' => false,
		];

		$registrar->register('wordpress-get-drift', [
			'label'        => 'Get WordPress update and version drift',
			'description'  => 'Return WordPress core version distribution and per-site pending plugin/theme update counts without exposing secrets.',
			'category'     => 'monitoring',
			'input_schema' => [
				'type'       => 'object',
				'properties' => [
					'site' => ['type' => 'string', 'maxLength' => 64],
				],
				'additionalProperties' => false,
			],
			'output_schema' => [
				'type'       => 'object',
				'properties' => [
					'summary' => ['type' => 'object'],
					'sites'   => [
						'type'     => 'array',
						'maxItems' => self::MAX_ARRAY_ITEMS,
						'items'    => [
							'type'       => 'object',
							'properties' => [
								'slug'                  => ['type' => 'string', 'maxLength' => 64],
								'wpVersion'             => ['type' => 'string', 'maxLength' => 32],
								'pluginsUpdatesPending' => ['type' => 'integer', 'minimum' => 0],
								'themesUpdatesPending'  => ['type' => 'integer', 'minimum' => 0],
								'pluginDrift'           => [
									'type'     => 'array',
									'maxItems' => 100,
									'items'    => $driftEntrySchema,
								],
								'themeDrift' => [
									'type'     => 'array',
									'maxItems' => 100,
									'items'    => $driftEntrySchema,
								],
							],
							'required'             => ['slug', 'wpVersion', 'pluginsUpdatesPending', 'themesUpdatesPending', 'pluginDrift', 'themeDrift'],
							'additionalProperties' => false,
						],
					],
				],
				'required'             => ['summary', 'sites'],
				'additionalProperties' => false,
			],
			'annotations' => self::ANNOTATIONS,
			'permission'  => $permissionCheck,
			'execute'     => static function (int $userId, \stdClass $args) use ($repoFactory, $settingsFactory): array {
				$filterSite = isset($args->site) && is_string($args->site) && trim($args->site) !== ''
					? trim($args->site)
					: null;
				$snapshots  = $repoFactory()->loadSnapshots();
				$analysis   = (new FleetAnalyzer($settingsFactory()))->analyze($snapshots);
				$driftSites = [];

				foreach ($snapshots as $snap) {
					if (count($driftSites) >= self::MAX_ARRAY_ITEMS) {
						break;
					}

					if ($filterSite !== null && $snap->slug !== $filterSite) {
						continue;
					}

					if ($filterSite !== null || $snap->totalUpdatesPending() > 0 || ($analysis['updateDrift']['latestWpVersion'] !== '' && $snap->wpVersion !== '' && version_compare($snap->wpVersion, $analysis['updateDrift']['latestWpVersion'], '<'))) {
						$driftSites[] = [
							'slug'                  => $snap->slug,
							'wpVersion'             => $snap->wpVersion,
							'pluginsUpdatesPending' => $snap->pluginsUpdatesPending,
							'themesUpdatesPending'  => $snap->themesUpdatesPending,
							'pluginDrift'           => is_array($snap->details['pluginDrift'] ?? null) ? array_slice($snap->details['pluginDrift'], 0, 100) : [],
							'themeDrift'            => is_array($snap->details['themeDrift'] ?? null) ? array_slice($snap->details['themeDrift'], 0, 100) : [],
						];
					}
				}

				return [
					'summary' => $analysis['updateDrift'],
					'sites'   => $driftSites,
				];
			},
		]);
	}

	/**
	 * Verify Cacti realm authorization for a specific user ID directly against
	 * user_auth_realm and user_auth_group_realm (never relying on $_SESSION).
	 *
	 * @param int $userId Cacti user_auth.id.
	 * @return bool
	 */
	public static function userHasViewRealm(int $userId): bool {
		if ($userId <= 0 || !function_exists('db_fetch_cell_prepared')) {
			return false;
		}

		$files        = [Pages::VIEW, Pages::OPERATOR, Pages::ADMIN];
		$placeholders = implode(', ', array_fill(0, count($files), '?'));

		/** @var mixed $direct */
		$direct = db_fetch_cell_prepared(
			"SELECT COUNT(*)
			 FROM user_auth_realm AS uar
			 INNER JOIN plugin_realms AS pr ON uar.realm_id = (pr.id + 100)
			 WHERE uar.user_id = ? AND pr.plugin = 'wordpress' AND pr.file IN ($placeholders)",
			array_merge([$userId], $files)
		);

		if (is_numeric($direct) && (int) $direct > 0) {
			return true;
		}

		/** @var mixed $viaGroup */
		$viaGroup = db_fetch_cell_prepared(
			"SELECT COUNT(*)
			 FROM user_auth_group_realm AS uagr
			 INNER JOIN user_auth_group_members AS uagm ON uagm.group_id = uagr.group_id
			 INNER JOIN user_auth_group AS uag ON uag.id = uagr.group_id AND uag.enabled = 'on'
			 INNER JOIN plugin_realms AS pr ON uagr.realm_id = (pr.id + 100)
			 WHERE uagm.user_id = ? AND pr.plugin = 'wordpress' AND pr.file IN ($placeholders)",
			array_merge([$userId], $files)
		);

		return is_numeric($viaGroup) && (int) $viaGroup > 0;
	}
}
