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

namespace Somethingwithproof\WordPress\Poller;

use Somethingwithproof\WordPress\Client\WordPressClient;
use Somethingwithproof\WordPress\Log;
use Somethingwithproof\WordPress\Metrics\AdaptivePollerSizer;
use Somethingwithproof\WordPress\Metrics\SiteMetrics;
use Somethingwithproof\WordPress\Repository\SiteRepository;
use Somethingwithproof\WordPress\Security\SecretVault;
use Somethingwithproof\WordPress\Security\SecurityException;
use Somethingwithproof\WordPress\Settings;

/**
 * Fleet polling orchestrator supporting poller_bottom, remote collectors (--poller=N),
 * deterministic collector sharding (--shard=K/N), dry-run probes, and Little's Law + CoDel sizing.
 */
final class FleetPoller {
	/**
	 * Construct a FleetPoller with injected client, vault, repository, sizer, and settings.
	 *
	 * @param SiteRepository $repository Site and snapshot storage repository.
	 * @param SecretVault $vault Local AES-256-GCM Application Password vault.
	 * @param WordPressClient $client Hardened read-only WordPress client.
	 * @param AdaptivePollerSizer $sizer Little's Law and CoDel concurrency sizer.
	 * @param Settings $settings Active plugin settings.
	 */
	public function __construct(
		private readonly SiteRepository $repository,
		private readonly SecretVault $vault,
		private readonly WordPressClient $client,
		private readonly AdaptivePollerSizer $sizer,
		private readonly Settings $settings,
	) {
	}

	/**
	 * Poll all enabled sites assigned to a poller (optionally sharded) and persist snapshots.
	 *
	 * @param int $pollerId Cacti poller ID (>= 1).
	 * @param int $shardIndex 1-based shard index.
	 * @param int $shardCount Total shard count.
	 * @param bool $dryRun When true, do not persist snapshots or poller state.
	 * @return array{
	 *   pollerId: int,
	 *   shard: string,
	 *   polled: int,
	 *   healthy: int,
	 *   degraded: int,
	 *   critical: int,
	 *   durationMs: float,
	 *   sizing: array{
	 *     recommendedConcurrency: int,
	 *     littlesLawTarget: float,
	 *     arrivalRatePerSec: float,
	 *     ewmaLatencyMs: float,
	 *     standingDelayMs: float,
	 *     codelDropCount: int,
	 *     codelState: string
	 *   },
	 *   snapshots: list<SiteMetrics>
	 * }
	 */
	public function pollFleet(int $pollerId = 1, int $shardIndex = 1, int $shardCount = 1, bool $dryRun = false): array {
		$start    = microtime(true);
		$allSites = $this->repository->listSites($pollerId, true);
		$sites    = AdaptivePollerSizer::shardSites($allSites, $shardIndex, $shardCount);

		$snapshots  = [];
		$healthy    = 0;
		$degraded   = 0;
		$critical   = 0;
		$latencySum = 0.0;
		$maxSojourn = 0.0;

		foreach ($sites as $site) {
			$siteStart = microtime(true);
			$metrics   = $this->probeSiteRecord($site);
			$elapsedMs = (microtime(true) - $siteStart) * 1000.0;

			$latencySum += max($metrics->ttfbMs, $elapsedMs);

			if ($metrics->ttfbMs > 0.0 && $elapsedMs > $metrics->ttfbMs) {
				$sojourn = $elapsedMs - $metrics->ttfbMs;

				if ($sojourn > $maxSojourn) {
					$maxSojourn = $sojourn;
				}
			}

			if (!$dryRun) {
				$this->repository->saveSnapshot($metrics);
			}

			if ($metrics->status === SiteMetrics::STATUS_HEALTHY) {
				$healthy++;
			} elseif ($metrics->status === SiteMetrics::STATUS_DEGRADED) {
				$degraded++;
			} else {
				$critical++;
			}

			$snapshots[] = $metrics;
		}

		$count       = count($snapshots);
		$durationMs  = round((microtime(true) - $start) * 1000.0, 2);
		$meanLatency = $count > 0 ? ($latencySum / $count) : 100.0;
		$prevState   = $this->repository->loadPollerState($pollerId);
		$sizing      = $this->sizer->size(
			$count,
			$this->settings->pollInterval,
			$meanLatency,
			$maxSojourn,
			$prevState,
			$this->settings->codelTargetMs,
			$this->settings->minConcurrency,
			$this->settings->maxConcurrency
		);

		if (!$dryRun) {
			$this->repository->savePollerState(
				$pollerId,
				$sizing['recommendedConcurrency'],
				$sizing['ewmaLatencyMs'],
				$sizing['standingDelayMs'],
				$sizing['codelDropCount'],
				$count,
				$durationMs
			);
		}

		return [
			'pollerId'   => $pollerId,
			'shard'      => sprintf('%d/%d', $shardIndex, $shardCount),
			'polled'     => $count,
			'healthy'    => $healthy,
			'degraded'   => $degraded,
			'critical'   => $critical,
			'durationMs' => $durationMs,
			'sizing'     => $sizing,
			'snapshots'  => $snapshots,
		];
	}

	/**
	 * Execute a single-site probe by slug (used by Operator UI dry-run and CLI probe).
	 *
	 * @param string $slug Unique site slug.
	 * @param bool $persist Persist the resulting snapshot when true.
	 * @return SiteMetrics|null Null when the site slug does not exist.
	 */
	public function probeSite(string $slug, bool $persist = false): ?SiteMetrics {
		$site = $this->repository->findSite($slug);

		if ($site === null) {
			return null;
		}

		$metrics = $this->probeSiteRecord($site);

		if ($persist) {
			$this->repository->saveSnapshot($metrics);
		}

		return $metrics;
	}

	/**
	 * Retrieve the site's decrypted Application Password (if available) and invoke WordPressClient.
	 *
	 * @param array<string, mixed> $site Site configuration record.
	 * @return SiteMetrics
	 */
	private function probeSiteRecord(array $site): SiteMetrics {
		$slug     = is_string($site['slug'] ?? null) ? $site['slug'] : 'unknown';
		$password = null;

		try {
			$password = $this->vault->retrieve($slug);
		} catch (SecurityException $error) {
			Log::warning(sprintf('Vault lookup failed for site "%s": %s', $slug, $error->getMessage()));
		}

		return $this->client->pollSite($site, $password);
	}
}
