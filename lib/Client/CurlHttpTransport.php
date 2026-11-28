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

use Somethingwithproof\WordPress\Security\SecurityException;

/**
 * Production ext-curl read-only HTTPS transport enforcing zero redirects, hard
 * byte caps during streaming, DNS-pinning via CURLOPT_RESOLVE, TLS verification,
 * and certificate expiry extraction.
 */
final class CurlHttpTransport implements HttpTransport {
	/**
	 * Execute a hardened HTTPS GET request through ext-curl.
	 *
	 * @param string $url Validated HTTPS endpoint URL.
	 * @param array<string, string> $headers Request headers.
	 * @param int $connectTimeout Connect timeout in seconds.
	 * @param int $readTimeout Total request timeout in seconds.
	 * @param int $maxBytes Maximum response body size in bytes.
	 * @param bool $verifyTls Verify TLS peer certificate and hostname.
	 * @param string|null $pinnedIp Optional resolved IP pinned for CURLOPT_RESOLVE.
	 * @return HttpResponse
	 * @throws SecurityException When ext-curl is missing, transfer fails, or byte cap is exceeded.
	 */
	public function get(
		string $url,
		array $headers,
		int $connectTimeout,
		int $readTimeout,
		int $maxBytes,
		bool $verifyTls,
		?string $pinnedIp = null,
	): HttpResponse {
		if (!function_exists('curl_init')) {
			throw new SecurityException('PHP ext-curl is required for live outbound HTTPS probes.');
		}

		$ch = curl_init($url);

		if ($ch === false) {
			throw new SecurityException('Unable to initialize cURL handle.');
		}

		$body            = '';
		$overflow        = false;
		$responseHeaders = [];
		$headerList      = [];

		foreach ($headers as $name => $value) {
			$headerList[] = $name . ': ' . $value;
		}

		curl_setopt($ch, CURLOPT_HTTPGET, true);
		curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
		curl_setopt($ch, CURLOPT_MAXREDIRS, 0);
		curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, $connectTimeout);
		curl_setopt($ch, CURLOPT_TIMEOUT, $readTimeout);
		curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, $verifyTls);
		curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, $verifyTls ? 2 : 0);
		curl_setopt($ch, CURLOPT_CERTINFO, true);
		curl_setopt($ch, CURLOPT_HTTPHEADER, $headerList);

		if (defined('CURLOPT_PROTOCOLS_STR')) {
			curl_setopt($ch, CURLOPT_PROTOCOLS_STR, 'https');
		} elseif (defined('CURLPROTO_HTTPS')) {
			curl_setopt($ch, CURLOPT_PROTOCOLS, CURLPROTO_HTTPS);
		}

		if ($pinnedIp !== null && $pinnedIp !== '') {
			$parsed = parse_url($url);
			$host   = is_array($parsed) && isset($parsed['host']) ? trim((string) $parsed['host'], '[]') : '';
			$port   = is_array($parsed) && isset($parsed['port']) ? (int) $parsed['port'] : 443;

			if ($host !== '' && filter_var($host, FILTER_VALIDATE_IP) === false) {
				$formattedIp = str_contains($pinnedIp, ':') ? '[' . $pinnedIp . ']' : $pinnedIp;
				curl_setopt($ch, CURLOPT_RESOLVE, [sprintf('%s:%d:%s', $host, $port, $formattedIp)]);
			}
		}

		curl_setopt($ch, CURLOPT_HEADERFUNCTION, static function ($handle, string $headerLine) use (&$responseHeaders): int {
			$len   = strlen($headerLine);
			$parts = explode(':', $headerLine, 2);

			if (count($parts) === 2) {
				$responseHeaders[strtolower(trim($parts[0]))] = trim($parts[1]);
			}

			return $len;
		});

		curl_setopt($ch, CURLOPT_WRITEFUNCTION, static function ($handle, string $chunk) use (&$body, &$overflow, $maxBytes): int {
			$chunkLen = strlen($chunk);

			if (strlen($body) + $chunkLen > $maxBytes) {
				$overflow = true;

				return 0;
			}

			$body .= $chunk;

			return $chunkLen;
		});

		$ok         = curl_exec($ch);
		$errno      = curl_errno($ch);
		$error      = curl_error($ch);
		$statusCode = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
		$ttfbSec    = (float) curl_getinfo($ch, CURLINFO_STARTTRANSFER_TIME);
		$totalSec   = (float) curl_getinfo($ch, CURLINFO_TOTAL_TIME);
		$certInfo   = curl_getinfo($ch, CURLINFO_CERTINFO);

		if ($overflow) {
			throw new SecurityException(sprintf('Outbound response exceeded hard cap of %d bytes.', $maxBytes));
		}

		if ($ok === false || $errno !== 0) {
			throw new SecurityException(sprintf('HTTPS probe failed (cURL #%d): %s', $errno, $error));
		}

		$tlsExpiryDays = self::extractTlsExpiryDays($certInfo);

		return new HttpResponse(
			$statusCode,
			$body,
			$responseHeaders,
			round($ttfbSec * 1000.0, 2),
			round($totalSec * 1000.0, 2),
			$tlsExpiryDays,
		);
	}

	/**
	 * Extract days remaining until peer leaf TLS certificate expiration from CURLINFO_CERTINFO.
	 *
	 * @param mixed $certInfo Value returned by curl_getinfo($ch, CURLINFO_CERTINFO).
	 * @return int|null
	 */
	public static function extractTlsExpiryDays(mixed $certInfo): ?int {
		if (!is_array($certInfo) || !isset($certInfo[0]) || !is_array($certInfo[0])) {
			return null;
		}

		$expireRaw = $certInfo[0]['Expire date'] ?? null;

		if (!is_string($expireRaw) || trim($expireRaw) === '') {
			return null;
		}

		$expiresAt = strtotime($expireRaw);

		if ($expiresAt === false) {
			return null;
		}

		return (int) floor(($expiresAt - time()) / 86400);
	}
}
