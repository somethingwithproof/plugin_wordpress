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

namespace Somethingwithproof\WordPress;

/**
 * Structured Cacti logger for plugin_wordpress with automatic redaction of
 * HTTP Basic Authorization headers and WordPress Application Password shapes.
 */
final class Log {
	/**
	 * Cacti log environment tag.
	 */
	private const ENVIRON = 'WORDPRESS';

	/**
	 * Record an informational log message through Cacti's logger.
	 *
	 * @param string $message Unredacted message text.
	 * @return void
	 */
	public static function info(string $message): void {
		self::write('NOTE', $message);
	}

	/**
	 * Record a warning log message through Cacti's logger.
	 *
	 * @param string $message Unredacted message text.
	 * @return void
	 */
	public static function warning(string $message): void {
		self::write('WARNING', $message);
	}

	/**
	 * Record an error log message through Cacti's logger.
	 *
	 * @param string $message Unredacted message text.
	 * @return void
	 */
	public static function error(string $message): void {
		self::write('ERROR', $message);
	}

	/**
	 * Scrub credentials, Basic auth headers, and Application Password patterns from text.
	 *
	 * @param string $message Raw log text.
	 * @return string Redacted single-line log string.
	 */
	public static function sanitize(string $message): string {
		$clean = preg_replace('/[\r\n\t]+/', ' ', $message) ?? $message;
		$clean = preg_replace('/Authorization:\s*Basic\s+[A-Za-z0-9+\/=]+/i', 'Authorization: Basic [REDACTED]', $clean) ?? $clean;
		$clean = preg_replace('/https?:\/\/[^\/\s@]+:[^\/\s@]+@/i', 'https://[REDACTED]@', $clean) ?? $clean;
		$clean = preg_replace('/\b[A-Za-z0-9]{4}(?:[ -][A-Za-z0-9]{4}){5}\b/', '[REDACTED_APP_PASSWORD]', $clean) ?? $clean;

		return trim($clean);
	}

	/**
	 * Dispatch a redacted log line to cacti_log when available.
	 *
	 * @param string $level Cacti log severity prefix.
	 * @param string $message Raw log message.
	 * @return void
	 */
	private static function write(string $level, string $message): void {
		if (!function_exists('cacti_log')) {
			return;
		}

		cacti_log($level . ': ' . self::sanitize($message), false, self::ENVIRON);
	}
}
