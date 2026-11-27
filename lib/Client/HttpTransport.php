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
 * Strictly read-only HTTP transport contract for WordPress monitoring probes.
 *
 * Exposes GET only; write HTTP verbs (POST, PUT, PATCH, DELETE) are intentionally absent.
 */
interface HttpTransport {
	/**
	 * Execute a bounded read-only HTTPS GET request without following redirects.
	 *
	 * @param string $url Validated HTTPS endpoint URL.
	 * @param array<string, string> $headers Request headers keyed by header name.
	 * @param int $connectTimeout Bounded connect timeout in seconds.
	 * @param int $readTimeout Bounded read timeout in seconds.
	 * @param int $maxBytes Hard maximum response body cap in bytes.
	 * @param bool $verifyTls Enable TLS peer certificate and hostname verification.
	 * @param string|null $pinnedIp Optional resolved IP pinned to prevent DNS rebinding TOCTOU.
	 * @return HttpResponse
	 */
	public function get(
		string $url,
		array $headers,
		int $connectTimeout,
		int $readTimeout,
		int $maxBytes,
		bool $verifyTls,
		?string $pinnedIp = null,
	): HttpResponse;
}
