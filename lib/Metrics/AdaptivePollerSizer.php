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

namespace Somethingwithproof\WordPress\Metrics;

/**
 * Adaptive fleet poller concurrency sizer combining Little's Law (L = lambda * W)
 * with CoDel standing-delay congestion control and deterministic shard partitioning.
 */
final class AdaptivePollerSizer {
	/**
	 * EWMA smoothing factor for probe service-time tracking.
	 */
	private const EWMA_ALPHA = 0.25;

	/**
	 * Headroom multiplier applied to Little's Law target concurrency to absorb jitter.
	 */
	private const HEADROOM_FACTOR = 1.25;

	/**
	 * Compute recommended poller concurrency using Little's Law (L = lambda * W)
	 * modulated by CoDel standing-delay control.
	 *
	 * @param int $siteCount Number of enabled sites assigned to this poller shard.
	 * @param int $pollIntervalSec Target polling interval in seconds.
	 * @param float $observedLatencyMs Observed mean or p95 per-site probe service time in ms.
	 * @param float $standingDelayMs Observed queue sojourn / standing delay in ms during the run.
	 * @param array{
	 *   recommendedConcurrency?: int,
	 *   ewmaLatencyMs?: float,
	 *   codelDropCount?: int
	 * } $previousState Previous persisted poller sizing state.
	 * @param int $codelTargetMs CoDel target standing delay in milliseconds.
	 * @param int $minConcurrency Configured lower concurrency bound.
	 * @param int $maxConcurrency Configured upper concurrency bound.
	 * @return array{
	 *   recommendedConcurrency: int,
	 *   littlesLawTarget: float,
	 *   arrivalRatePerSec: float,
	 *   ewmaLatencyMs: float,
	 *   standingDelayMs: float,
	 *   codelDropCount: int,
	 *   codelState: string
	 * }
	 */
	public function size(
		int $siteCount,
		int $pollIntervalSec,
		float $observedLatencyMs,
		float $standingDelayMs,
		array $previousState = [],
		int $codelTargetMs = 500,
		int $minConcurrency = 2,
		int $maxConcurrency = 32,
	): array {
		$minC        = max(1, $minConcurrency);
		$maxC        = max($minC, $maxConcurrency);
		$intervalSec = max(1, $pollIntervalSec);
		$sites       = max(0, $siteCount);
		$latencyMs   = max(1.0, $observedLatencyMs);
		$sojournMs   = max(0.0, $standingDelayMs);
		$targetMs    = max(10, $codelTargetMs);

		$prevEwma = isset($previousState['ewmaLatencyMs']) && $previousState['ewmaLatencyMs'] > 0.0
			? (float) $previousState['ewmaLatencyMs']
			: $latencyMs;
		$ewmaMs   = ($prevEwma * (1.0 - self::EWMA_ALPHA)) + ($latencyMs * self::EWMA_ALPHA);

		// Little's Law: L = lambda * W, where lambda = sites / intervalSec and W = ewmaMs / 1000.
		$lambda           = $sites / (float) $intervalSec;
		$serviceSec       = $ewmaMs / 1000.0;
		$littlesLawRaw    = $lambda * $serviceSec * self::HEADROOM_FACTOR;
		$littlesLawTarget = max((float) $minC, min((float) $maxC, $littlesLawRaw));

		$prevConcurrency = isset($previousState['recommendedConcurrency']) && $previousState['recommendedConcurrency'] >= $minC
			? (int) $previousState['recommendedConcurrency']
			: (int) ceil($littlesLawTarget);
		$dropCount       = isset($previousState['codelDropCount']) ? max(0, (int) $previousState['codelDropCount']) : 0;

		if ($sojournMs > (float) $targetMs) {
			// CoDel active backoff: scale concurrency down by 1 / sqrt(dropCount).
			$dropCount++;
			$scaled      = (int) floor($prevConcurrency / sqrt((float) $dropCount));
			$nextConc    = max($minC, min($maxC, $scaled));
			$codelState  = 'backoff';
		} else {
			// Standing delay is within target: decay drop counter and converge smoothly toward Little's Law target.
			$dropCount = max(0, $dropCount - 1);
			$targetInt = max($minC, min($maxC, (int) ceil($littlesLawTarget)));

			if ($prevConcurrency < $targetInt) {
				$step     = max(1, (int) ceil(($targetInt - $prevConcurrency) * 0.5));
				$nextConc = min($targetInt, $prevConcurrency + $step);
			} elseif ($prevConcurrency > $targetInt) {
				$nextConc = max($targetInt, $prevConcurrency - 1);
			} else {
				$nextConc = $targetInt;
			}

			$codelState = 'steady';
		}

		return [
			'recommendedConcurrency' => max($minC, min($maxC, $nextConc)),
			'littlesLawTarget'       => round($littlesLawRaw, 3),
			'arrivalRatePerSec'      => round($lambda, 4),
			'ewmaLatencyMs'          => round($ewmaMs, 2),
			'standingDelayMs'        => round($sojournMs, 2),
			'codelDropCount'         => $dropCount,
			'codelState'             => $codelState,
		];
	}

	/**
	 * Partition a list of site records deterministically for --shard=K/N remote collector execution.
	 *
	 * Uses CRC32 over the site slug (1-based shardIndex in 1..shardCount) so sites remain
	 * evenly balanced across collectors without reshuffling when sites are added.
	 *
	 * @param list<array<string, mixed>> $sites Enabled site records.
	 * @param int $shardIndex 1-based shard index (1 <= K <= N).
	 * @param int $shardCount Total shard count (N >= 1).
	 * @return list<array<string, mixed>>
	 */
	public static function shardSites(array $sites, int $shardIndex, int $shardCount): array {
		if ($shardCount <= 1) {
			return $sites;
		}

		if ($shardIndex < 1 || $shardIndex > $shardCount) {
			throw new \InvalidArgumentException(sprintf('Shard index %d must be between 1 and %d.', $shardIndex, $shardCount));
		}

		$targetBucket = $shardIndex - 1;
		$selected     = [];

		foreach ($sites as $site) {
			$slug   = is_string($site['slug'] ?? null) ? $site['slug'] : '';
			$bucket = (int) (sprintf('%u', crc32($slug)) % $shardCount);

			if ($bucket === $targetBucket) {
				$selected[] = $site;
			}
		}

		return $selected;
	}

	/**
	 * Parse a "--shard=K/N" CLI argument into validated [shardIndex, shardCount].
	 *
	 * @param string $spec Shard specification string (e.g. "2/4").
	 * @return array{index: int, count: int}
	 * @throws \InvalidArgumentException When the format or bounds are invalid.
	 */
	public static function parseShardSpec(string $spec): array {
		if (preg_match('/^(\d+)\/(\d+)$/', trim($spec), $m) !== 1) {
			throw new \InvalidArgumentException('Shard specification must match K/N (for example 1/4).');
		}

		$index = (int) $m[1];
		$count = (int) $m[2];

		if ($count < 1 || $index < 1 || $index > $count) {
			throw new \InvalidArgumentException(sprintf('Invalid shard %d/%d: require 1 <= K <= N.', $index, $count));
		}

		return ['index' => $index, 'count' => $count];
	}
}
