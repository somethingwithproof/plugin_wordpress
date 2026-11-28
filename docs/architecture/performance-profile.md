# Performance Profile and Algorithmic Review

This document records the algorithmic complexity review and measured PHP 8.4 performance profile for `plugin_wordpress` at **5,000** and **10,000** monitored WordPress sites.

## Algorithmic Review

### `FleetAnalyzer::analyze()` (`lib/Metrics/FleetAnalyzer.php`)
- **Complexity**: $O(N \log N)$ time, $O(N)$ memory.
- **Pass structure**:
  1. Single linear pass over $N$ `SiteMetrics` objects accumulating status counts, Apdex satisfied/tolerating tallies, WP-Cron overdue totals, `wp_options` autoload bloat classifications, TLS expiry minimums, core version frequency counts, and a flat numeric list of positive TTFB samples (`$ttfbs`).
  2. One numeric sort (`sort($sorted, SORT_NUMERIC)`) for median and p95 TTFB.
  3. One linear pass to compute absolute deviations `abs($sorted[$i] - $median)` and one numeric sort to compute the Median Absolute Deviation (MAD).
  4. One linear pass to flag latency outliers where modified z-score $M_i = 0.6745 \cdot (x_i - \tilde{x}) / \text{MAD} > 3.5$.
- **Hotspot prevention**:
  - Avoids nested $O(N^2)$ lookups and avoids `array_merge()` inside loops.
  - Bounds summary offender lists (`anomalies`, `cronStalls`, `autoloadBloat`, `tlsExpiring`) to 50 items after sorting so JSON, Console HTML, and MCP responses stay constant-size even on 10,000-site fleets.

### `WordPressClient` Payload Parsers (`lib/Client/WordPressClient.php`)
- **Complexity**: $O(M)$ per JSON payload where $M$ is payload byte length / item count, linear across $N$ sites ($O(N \cdot M)$).
- **Hotspot prevention**:
  - Single-pass `json_decode(..., true)` with no regex backtracking on large payloads.
  - Enforces a hard 2 MiB (`2097152` bytes) response cap inside `CurlHttpTransport` during streaming (`CURLOPT_WRITEFUNCTION`) before the payload ever reaches `json_decode()`, preventing memory exhaustion from oversized or hostile responses.

### `AdaptivePollerSizer` (`lib/Metrics/AdaptivePollerSizer.php`)
- **Complexity**: $O(1)$ per concurrency sizing step; $O(N)$ deterministic sharding via `crc32($slug) % $shardCount`.
- **Control law**:
  - Computes Little's Law target concurrency $L = \lambda \cdot W$ with arrival rate $\lambda = N / T_{\text{interval}}$, EWMA service time $W$, and 1.25x jitter headroom.
  - Applies CoDel standing-delay congestion control: when observed sojourn delay exceeds `wordpress_codel_target_ms`, increments drop count and scales concurrency by $1 / \sqrt{\text{count}}$, clamped to `[wordpress_min_concurrency, wordpress_max_concurrency]`.

### `SecretVault` (`lib/Security/SecretVault.php`)
- **Complexity**: $O(1)$ per site encrypt/decrypt using OpenSSL native AES-256-GCM hardware acceleration (AES-NI / ARMv8 Crypto).
- **Hotspot prevention**:
  - Caches the validated 32-byte key in-process per poller invocation after checking file permissions (`chmod 0600`) once, avoiding repeated `stat()` and `file_get_contents()` syscalls across thousands of sites.

## Measured Benchmark Results

Reproduce locally with:

```bash
php scripts/benchmark.php
```

Measured on PHP `8.4.25` (Darwin, arm64, zero Composer runtime dependencies):

| Component / Workload | 5,000 Sites | 10,000 Sites | Scaling Factor (10k / 5k) |
| --- | ---: | ---: | ---: |
| `FleetAnalyzer::analyze()` (Apdex + MAD + Drift + Bloat + TLS) | 2.65 ms (1,886,318 sites/s) | 5.43 ms (1,840,237 sites/s) | 2.05x (linear) |
| `WordPressClient` parsers (discovery + plugins + telemetry) | 36.64 ms (136,459 sites/s) | 72.91 ms (137,156 sites/s) | 1.99x (linear) |
| `AdaptivePollerSizer` (4-way CRC32 shard + sizing step) | 1.31 ms | 3.63 ms | 2.77x |
| `SecretVault` AES-256-GCM encrypt + decrypt round-trip | 14.28 ms (700,180 ops/s) | 26.30 ms (760,325 ops/s) | 1.84x (linear) |
| Peak Process RSS (`memory_get_peak_usage(true)`) | 10.00 MiB | 20.00 MiB | 2.00x (linear) |

## Operational Takeaway

At 10,000 WordPress sites, CPU and memory overhead inside Cacti's PHP analytics, parser, sharding, and AES-256-GCM decryption layers remains under 110 ms combined and 20 MiB peak RSS. Fleet polling duration is therefore strictly network-bound on remote WordPress HTTP response times, which `AdaptivePollerSizer` and `--shard=K/N` remote collector sharding regulate safely.
