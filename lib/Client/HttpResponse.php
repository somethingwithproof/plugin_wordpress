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

/**
 * Immutable HTTP response value object returned by read-only HttpTransport implementations.
 */
final class HttpResponse {
	/**
	 * Construct an HttpResponse snapshot.
	 *
	 * @param int $statusCode HTTP response status code.
	 * @param string $body Raw response body bytes.
	 * @param array<string, string> $headers Lowercase-keyed response headers.
	 * @param float $ttfbMs Measured time-to-first-byte in milliseconds.
	 * @param float $totalMs Total request duration in milliseconds.
	 * @param int|null $tlsExpiryDays Days remaining until peer TLS certificate expiration, or null when unavailable.
	 */
	public function __construct(
		public readonly int $statusCode,
		public readonly string $body,
		public readonly array $headers = [],
		public readonly float $ttfbMs = 0.0,
		public readonly float $totalMs = 0.0,
		public readonly ?int $tlsExpiryDays = null,
	) {
	}

	/**
	 * Return response payload size in bytes.
	 *
	 * @return int
	 */
	public function bytes(): int {
		return strlen($this->body);
	}

	/**
	 * Return a response header value by case-insensitive name.
	 *
	 * @param string $name Header name.
	 * @return string|null
	 */
	public function header(string $name): ?string {
		$key = strtolower($name);

		return $this->headers[$key] ?? null;
	}
}
