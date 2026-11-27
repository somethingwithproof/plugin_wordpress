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

use Somethingwithproof\WordPress\Config\ConfigSchema;
use Somethingwithproof\WordPress\Config\YamlXmlCodec;
use Somethingwithproof\WordPress\Repository\SiteRepository;
use Somethingwithproof\WordPress\Settings;

/**
 * Decoupled Config-as-Code provider for casc_register_providers (slug: wordpress).
 *
 * Exports declarative Settings and site inventory with symbolic vault:wordpress:<slug>
 * secret references only. Never exports Application Passwords, vault ciphertexts,
 * telemetry snapshots, or poller CoDel state, and imports zero sibling plugin classes.
 */
final class CascProvider {
	/**
	 * Plugin slug registered with Config-as-Code hooks.
	 */
	public const SLUG = 'wordpress';

	/**
	 * Register the plain-array WordPress CasC provider descriptor on a registrar object.
	 *
	 * @param object $registrar Duck-typed registrar exposing register(array $descriptor).
	 * @param callable(): Settings $settingsProvider Live settings supplier.
	 * @param callable(Settings): bool $settingsWriter Settings persistence writer.
	 * @param callable(): SiteRepository $repoProvider Live SiteRepository supplier.
	 * @return bool True when registration succeeded.
	 */
	public static function register(
		object $registrar,
		callable $settingsProvider,
		callable $settingsWriter,
		callable $repoProvider,
	): bool {
		if (!method_exists($registrar, 'register')) {
			return false;
		}

		$registrar->register(self::descriptor($settingsProvider, $settingsWriter, $repoProvider));

		return true;
	}

	/**
	 * Build the plain-array CasC provider descriptor for plugin_wordpress.
	 *
	 * @param callable(): Settings $settingsProvider Live settings supplier.
	 * @param callable(Settings): bool $settingsWriter Settings persistence writer.
	 * @param callable(): SiteRepository $repoProvider Live SiteRepository supplier.
	 * @return array{
	 *   slug: string,
	 *   schemaVersion: string,
	 *   export: callable(array<string, mixed>): array<string, mixed>,
	 *   validate: callable(array<string, mixed>): list<string>,
	 *   plan: callable(array<string, mixed>, array<string, mixed>): list<array<string, mixed>>,
	 *   apply: callable(array<string, mixed>, string, array<string, mixed>): array<string, mixed>
	 * }
	 */
	public static function descriptor(
		callable $settingsProvider,
		callable $settingsWriter,
		callable $repoProvider,
	): array {
		return [
			'slug'          => self::SLUG,
			'schemaVersion' => ConfigSchema::SCHEMA_VERSION,
			'export'        => static function (array $options = []) use ($settingsProvider, $repoProvider): array {
				$out          = $settingsProvider()->toConfigArray();
				$out['sites'] = $repoProvider()->exportSitesConfig();

				return $out;
			},
			'validate' => static function (array $desired): array {
				return ConfigSchema::validate($desired);
			},
			'plan' => static function (array $desired, array $options = []) use ($settingsProvider, $repoProvider): array {
				return self::computePlan($desired, $settingsProvider(), $repoProvider());
			},
			'apply' => static function (array $desired, string $planHash, array $options = []) use ($settingsProvider, $settingsWriter, $repoProvider): array {
				return self::applyPlan($desired, $planHash, $settingsProvider(), $settingsWriter, $repoProvider());
			},
		];
	}

	/**
	 * Compute deterministic diff actions between live Config and a desired Config map.
	 *
	 * @param array<string, mixed> $desired Desired flat settings plus optional sites list.
	 * @param Settings $currentSettings Active settings snapshot.
	 * @param SiteRepository $repository Live site repository.
	 * @return list<array<string, mixed>>
	 */
	public static function computePlan(array $desired, Settings $currentSettings, SiteRepository $repository): array {
		$errors = ConfigSchema::validate($desired);

		if ($errors !== []) {
			return array_map(
				static fn (string $msg): array => [
					'operation' => 'error',
					'key'       => self::SLUG,
					'message'   => $msg,
				],
				$errors
			);
		}

		$current = $currentSettings->toConfigArray();
		$actions = [];

		foreach ($desired as $field => $targetValue) {
			if ($field === 'sites') {
				continue;
			}

			$liveValue = $current[$field] ?? null;

			if ($liveValue !== $targetValue) {
				$actions[] = [
					'operation' => 'update',
					'key'       => self::SLUG . '.' . $field,
					'before'    => $liveValue,
					'after'     => $targetValue,
				];
			}
		}

		if (isset($desired['sites']) && is_array($desired['sites'])) {
			$existingBySlug = [];

			foreach ($repository->exportSitesConfig() as $existing) {
				$existingBySlug[(string) $existing['slug']] = $existing;
			}

			foreach ($desired['sites'] as $candidate) {
				if (!is_array($candidate) || !isset($candidate['slug']) || !is_string($candidate['slug'])) {
					continue;
				}

				$slug = $candidate['slug'];

				if (!isset($existingBySlug[$slug])) {
					$actions[] = [
						'operation' => 'create',
						'key'       => self::SLUG . '.sites.' . $slug,
						'after'     => $candidate,
					];
				} else {
					$currentSite = $existingBySlug[$slug];
					$changed     = [];

					foreach ($candidate as $k => $v) {
						if (($currentSite[$k] ?? null) !== $v) {
							$changed[$k] = ['before' => $currentSite[$k] ?? null, 'after' => $v];
						}
					}

					if ($changed !== []) {
						$actions[] = [
							'operation' => 'update',
							'key'       => self::SLUG . '.sites.' . $slug,
							'changes'   => $changed,
						];
					}
				}
			}
		}

		return $actions;
	}

	/**
	 * Validate confirmation plan hash and apply settings and non-secret site inventory changes.
	 *
	 * @param array<string, mixed> $desired Desired Config map.
	 * @param string $planHash Caller-supplied SHA-256 confirmation hash.
	 * @param Settings $currentSettings Active settings snapshot.
	 * @param callable(Settings): bool $settingsWriter Settings writer callback.
	 * @param SiteRepository $repository Live site repository.
	 * @return array<string, mixed>
	 */
	public static function applyPlan(
		array $desired,
		string $planHash,
		Settings $currentSettings,
		callable $settingsWriter,
		SiteRepository $repository,
	): array {
		$errors = ConfigSchema::validate($desired);

		if ($errors !== []) {
			return [
				'ok'       => false,
				'planHash' => $planHash,
				'errors'   => $errors,
			];
		}

		$actions      = self::computePlan($desired, $currentSettings, $repository);
		$expectedHash = YamlXmlCodec::planHash($desired, $actions);

		if ($planHash === '' || !hash_equals($expectedHash, $planHash)) {
			return [
				'ok'           => false,
				'planHash'     => $planHash,
				'expectedHash' => $expectedHash,
				'errors'       => ['Confirmation plan hash does not match the computed plan.'],
			];
		}

		$settingUpdates = $desired;
		unset($settingUpdates['sites']);

		$ok = true;

		if ($settingUpdates !== []) {
			$merged = array_merge($currentSettings->toConfigArray(), $settingUpdates);
			$ok     = $settingsWriter(Settings::fromRow($merged));
		}

		$sitesApplied = 0;

		if ($ok && isset($desired['sites']) && is_array($desired['sites'])) {
			foreach ($desired['sites'] as $site) {
				if (is_array($site)) {
					/** @var array<string, mixed> $typedSite */
					$typedSite = $site;

					if ($repository->upsertSite($typedSite)) {
						$sitesApplied++;
					} else {
						$ok = false;
					}
				}
			}
		}

		return [
			'ok'           => $ok,
			'planHash'     => $expectedHash,
			'actions'      => count($actions),
			'sitesApplied' => $sitesApplied,
		];
	}
}
