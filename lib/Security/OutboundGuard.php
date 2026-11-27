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

namespace Somethingwithproof\WordPress\Security;

/**
 * Outbound HTTPS and SSRF guard for read-only WordPress REST and Site Health probes.
 *
 * Enforces mandatory HTTPS, private/link-local/metadata IP blocking (with an explicit
 * enterprise host/CIDR allowlist), zero HTTP redirects, bounded connect/read timeouts,
 * TLS peer/host verification by default, and a hard 2 MiB response byte cap.
 */
final class OutboundGuard {
	/**
	 * Hard upper ceiling on HTTP response size (2 MiB).
	 */
	public const HARD_MAX_RESPONSE_BYTES = 2097152;

	/**
	 * Hard upper ceiling on TCP/TLS connect timeout in seconds.
	 */
	public const HARD_MAX_CONNECT_TIMEOUT = 15;

	/**
	 * Hard upper ceiling on HTTP read timeout in seconds.
	 */
	public const HARD_MAX_READ_TIMEOUT = 60;

	/**
	 * Always-blocked IPv4 CIDRs (unspecified, RFC1918, CGNAT, loopback, link-local/metadata, multicast, reserved).
	 *
	 * @var list<string>
	 */
	private const BLOCKED_IPV4_CIDRS = [
		'0.0.0.0/8',
		'10.0.0.0/8',
		'100.64.0.0/10',
		'127.0.0.0/8',
		'169.254.0.0/16',
		'172.16.0.0/12',
		'192.0.0.0/24',
		'192.0.2.0/24',
		'192.168.0.0/16',
		'198.18.0.0/15',
		'198.51.100.0/24',
		'203.0.113.0/24',
		'224.0.0.0/4',
		'240.0.0.0/4',
	];

	/**
	 * Always-blocked IPv6 CIDRs (unspecified, loopback, ULA, link-local, AWS IMDSv2 IPv6, multicast).
	 *
	 * @var list<string>
	 */
	private const BLOCKED_IPV6_CIDRS = [
		'::/128',
		'::1/128',
		'fc00::/7',
		'fe80::/10',
		'ff00::/8',
		'2001:db8::/32',
		'fd00:ec2::/32',
	];

	/**
	 * Normalized lowercase internal host allowlist entries (exact or *.suffix).
	 *
	 * @var list<string>
	 */
	private readonly array $allowlistHosts;

	/**
	 * Normalized internal CIDR allowlist entries.
	 *
	 * @var list<string>
	 */
	private readonly array $allowlistCidrs;

	/**
	 * Bounded connect timeout in seconds.
	 */
	public readonly int $connectTimeout;

	/**
	 * Bounded read timeout in seconds.
	 */
	public readonly int $readTimeout;

	/**
	 * Hard response payload ceiling in bytes.
	 */
	public readonly int $maxResponseBytes;

	/**
	 * Default TLS peer and host verification flag.
	 */
	public readonly bool $verifyTls;

	/**
	 * Optional DNS resolver callback returning resolved IP strings for a hostname.
	 *
	 * @var (callable(string): list<string>)|null
	 */
	private $dnsResolver;

	/**
	 * Construct an OutboundGuard with explicit SSRF, timeout, TLS, and payload boundaries.
	 *
	 * @param list<string> $allowlistHosts Enterprise internal hostnames or *.domain patterns.
	 * @param list<string> $allowlistCidrs Enterprise internal IPv4/IPv6 CIDR ranges.
	 * @param int $connectTimeout Connect timeout in seconds (clamped 1..15).
	 * @param int $readTimeout Read timeout in seconds (clamped 1..60).
	 * @param int $maxResponseBytes Maximum response payload size in bytes (clamped 64 KiB..2 MiB).
	 * @param bool $verifyTls Require valid TLS certificate and hostname match by default.
	 * @param (callable(string): list<string>)|null $dnsResolver Injectable DNS resolver for deterministic testing.
	 */
	public function __construct(
		array $allowlistHosts = [],
		array $allowlistCidrs = [],
		int $connectTimeout = 5,
		int $readTimeout = 10,
		int $maxResponseBytes = self::HARD_MAX_RESPONSE_BYTES,
		bool $verifyTls = true,
		?callable $dnsResolver = null,
	) {
		$this->allowlistHosts   = array_values(array_filter(array_map(static fn (string $h): string => strtolower(trim($h)), $allowlistHosts), static fn (string $h): bool => $h !== ''));
		$this->allowlistCidrs   = array_values(array_filter(array_map('trim', $allowlistCidrs), static fn (string $c): bool => $c !== ''));
		$this->connectTimeout   = max(1, min(self::HARD_MAX_CONNECT_TIMEOUT, $connectTimeout));
		$this->readTimeout      = max(1, min(self::HARD_MAX_READ_TIMEOUT, $readTimeout));
		$this->maxResponseBytes = max(65536, min(self::HARD_MAX_RESPONSE_BYTES, $maxResponseBytes));
		$this->verifyTls        = $verifyTls;
		$this->dnsResolver      = $dnsResolver;
	}

	/**
	 * Validate a target HTTPS URL and all resolved destination IPs before opening a connection.
	 *
	 * @param string $url Target WordPress endpoint URL.
	 * @param bool $allowSitePrivateIp True when the site record explicitly opts into allowlisted internal addressing.
	 * @return array{url: string, host: string, port: int, pinnedIp: string, ips: list<string>}
	 * @throws SecurityException When scheme, host, port, or resolved IP violates security policy.
	 */
	public function validateUrl(string $url, bool $allowSitePrivateIp = false): array {
		if ($url === '' || preg_match('/[\x00-\x1F\x7F]/', $url) === 1) {
			throw new SecurityException('Outbound URL contains control characters or is empty.');
		}

		$parts = parse_url($url);

		if (!is_array($parts)) {
			throw new SecurityException('Outbound URL could not be parsed.');
		}

		$scheme = strtolower((string) ($parts['scheme'] ?? ''));

		if ($scheme !== 'https') {
			throw new SecurityException('Outbound WordPress probes require mandatory https:// transport.');
		}

		if (isset($parts['user']) || isset($parts['pass'])) {
			throw new SecurityException('Embedded credentials in outbound URLs are forbidden; use SecretVault.');
		}

		if (isset($parts['fragment'])) {
			throw new SecurityException('URL fragments are not permitted in outbound WordPress probes.');
		}

		$rawHost = strtolower(trim((string) ($parts['host'] ?? '')));
		$host    = trim($rawHost, '[]');

		if ($host === '' || strlen($host) > 253) {
			throw new SecurityException('Outbound URL has a missing or oversized hostname.');
		}

		$port = isset($parts['port']) ? (int) $parts['port'] : 443;

		if ($port < 1 || $port > 65535) {
			throw new SecurityException('Outbound URL specifies an invalid TCP port.');
		}

		$ips = $this->resolveHost($host);

		if ($ips === []) {
			throw new SecurityException(sprintf('Unable to resolve hostname "%s".', $host));
		}

		$hostAllowlisted = $this->isHostAllowlisted($host);

		foreach ($ips as $ip) {
			if ($this->isBlockedIp($ip)) {
				$cidrAllowlisted = $this->isIpAllowlisted($ip);

				if (!$cidrAllowlisted && !($hostAllowlisted || $allowSitePrivateIp)) {
					throw new SecurityException(sprintf('Outbound target "%s" resolved to blocked private/metadata IP "%s".', $host, $ip));
				}

				if ($this->isAlwaysBlockedMetadataIp($ip)) {
					throw new SecurityException(sprintf('Cloud metadata IP "%s" is unconditionally blocked.', $ip));
				}
			}
		}

		return [
			'url'      => $url,
			'host'     => $host,
			'port'     => $port,
			'pinnedIp' => $ips[0],
			'ips'      => $ips,
		];
	}

	/**
	 * Enforce zero HTTP redirects and verify response size does not exceed the 2 MiB ceiling.
	 *
	 * @param int $statusCode HTTP response status code.
	 * @param int $bytes Response payload size in bytes.
	 * @return void
	 * @throws SecurityException When the response is a redirect or exceeds the configured byte limit.
	 */
	public function assertResponseAllowed(int $statusCode, int $bytes): void {
		if ($statusCode >= 300 && $statusCode < 400) {
			throw new SecurityException(sprintf('HTTP redirects (%d) are disabled for outbound WordPress probes.', $statusCode));
		}

		if ($bytes > $this->maxResponseBytes) {
			throw new SecurityException(sprintf('Response size (%d bytes) exceeds maximum allowed limit (%d bytes).', $bytes, $this->maxResponseBytes));
		}
	}

	/**
	 * Determine whether an IP address belongs to a private, loopback, link-local, metadata, or reserved range.
	 *
	 * @param string $ip IPv4 or IPv6 address literal.
	 * @return bool
	 */
	public function isBlockedIp(string $ip): bool {
		$normalized = $this->unwrapMappedIpv4($ip);

		if (filter_var($normalized, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
			foreach (self::BLOCKED_IPV4_CIDRS as $cidr) {
				if (self::ipInCidr($normalized, $cidr)) {
					return true;
				}
			}

			return false;
		}

		if (filter_var($normalized, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false) {
			foreach (self::BLOCKED_IPV6_CIDRS as $cidr) {
				if (self::ipInCidr($normalized, $cidr)) {
					return true;
				}
			}

			return false;
		}

		return true;
	}

	/**
	 * Check whether an IP address is a cloud instance metadata endpoint (never allowlisted).
	 *
	 * @param string $ip IPv4 or IPv6 address literal.
	 * @return bool
	 */
	public function isAlwaysBlockedMetadataIp(string $ip): bool {
		$normalized = $this->unwrapMappedIpv4($ip);

		return $normalized === '169.254.169.254'
			|| $normalized === '169.254.170.2'
			|| self::ipInCidr($normalized, 'fd00:ec2::/32');
	}

	/**
	 * Check whether a hostname matches the configured enterprise internal host allowlist.
	 *
	 * @param string $host Lowercase hostname without brackets.
	 * @return bool
	 */
	public function isHostAllowlisted(string $host): bool {
		$host = strtolower($host);

		foreach ($this->allowlistHosts as $pattern) {
			if ($pattern === $host) {
				return true;
			}

			if (str_starts_with($pattern, '*.')) {
				$suffix = substr($pattern, 1);

				if (strlen($host) > strlen($suffix) && str_ends_with($host, $suffix)) {
					return true;
				}
			}
		}

		return false;
	}

	/**
	 * Check whether an IP address falls inside any configured enterprise CIDR allowlist entry.
	 *
	 * @param string $ip IPv4 or IPv6 literal.
	 * @return bool
	 */
	public function isIpAllowlisted(string $ip): bool {
		$normalized = $this->unwrapMappedIpv4($ip);

		foreach ($this->allowlistCidrs as $cidr) {
			if (self::ipInCidr($normalized, $cidr)) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Check whether an IPv4 or IPv6 address falls inside a CIDR block using binary prefix matching.
	 *
	 * @param string $ip IP address literal.
	 * @param string $cidr CIDR specification (e.g. 10.0.0.0/8 or fe80::/10).
	 * @return bool
	 */
	public static function ipInCidr(string $ip, string $cidr): bool {
		$parts = explode('/', $cidr, 2);

		if (count($parts) !== 2 || !is_numeric($parts[1])) {
			return false;
		}

		$ipBin     = @inet_pton($ip);
		$subnetBin = @inet_pton($parts[0]);

		if ($ipBin === false || $subnetBin === false || strlen($ipBin) !== strlen($subnetBin)) {
			return false;
		}

		$maxBits = strlen($ipBin) * 8;
		$prefix  = (int) $parts[1];

		if ($prefix < 0 || $prefix > $maxBits) {
			return false;
		}

		$fullBytes = intdiv($prefix, 8);
		$remBits   = $prefix % 8;

		if ($fullBytes > 0 && substr($ipBin, 0, $fullBytes) !== substr($subnetBin, 0, $fullBytes)) {
			return false;
		}

		if ($remBits === 0) {
			return true;
		}

		$mask = (0xFF << (8 - $remBits)) & 0xFF;

		return (ord($ipBin[$fullBytes]) & $mask) === (ord($subnetBin[$fullBytes]) & $mask);
	}

	/**
	 * Resolve a hostname or IP literal to a deduplicated list of IP addresses.
	 *
	 * @param string $host Lowercase hostname or IP literal.
	 * @return list<string>
	 */
	private function resolveHost(string $host): array {
		if (filter_var($host, FILTER_VALIDATE_IP) !== false) {
			return [$host];
		}

		if ($this->dnsResolver !== null) {
			$resolved = ($this->dnsResolver)($host);

			return array_values(array_unique(array_filter($resolved, static fn (string $ip): bool => filter_var($ip, FILTER_VALIDATE_IP) !== false)));
		}

		$ips     = [];
		$records = @dns_get_record($host, DNS_A | DNS_AAAA);

		if (is_array($records)) {
			foreach ($records as $record) {
				if (isset($record['ip']) && is_string($record['ip'])) {
					$ips[] = $record['ip'];
				} elseif (isset($record['ipv6']) && is_string($record['ipv6'])) {
					$ips[] = $record['ipv6'];
				}
			}
		}

		if ($ips === []) {
			$fallback = @gethostbynamel($host);

			if (is_array($fallback)) {
				foreach ($fallback as $ip) {
					$ips[] = $ip;
				}
			}
		}

		return array_values(array_unique($ips));
	}

	/**
	 * Convert IPv4-mapped IPv6 addresses (::ffff:a.b.c.d) to dotted-quad IPv4 before CIDR checks.
	 *
	 * @param string $ip Raw IPv4 or IPv6 literal.
	 * @return string
	 */
	private function unwrapMappedIpv4(string $ip): string {
		$bin = @inet_pton($ip);

		if ($bin === false || strlen($bin) !== 16) {
			return $ip;
		}

		if (substr($bin, 0, 12) === "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff") {
			$ipv4 = @inet_ntop(substr($bin, 12, 4));

			if (is_string($ipv4)) {
				return $ipv4;
			}
		}

		return $ip;
	}
}
