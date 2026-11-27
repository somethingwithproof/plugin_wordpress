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

namespace Somethingwithproof\WordPress\Db;

/**
 * Minimal prepared-statement database adapter decoupling plugin_wordpress
 * storage classes from Cacti's global db_* functions during unit testing.
 */
interface DbAdapter {
	/**
	 * Execute a write statement with positional bound parameters.
	 *
	 * @param string $sql Parameterized SQL statement.
	 * @param list<bool|float|int|string|null> $params Bound parameters.
	 * @return bool True on success.
	 */
	public function execute(string $sql, array $params = []): bool;

	/**
	 * Fetch a single scalar cell value or null when no row matches.
	 *
	 * @param string $sql Parameterized SQL query.
	 * @param list<bool|float|int|string|null> $params Bound parameters.
	 * @return mixed
	 */
	public function fetchCell(string $sql, array $params = []): mixed;

	/**
	 * Fetch a single associative row or null when no row matches.
	 *
	 * @param string $sql Parameterized SQL query.
	 * @param list<bool|float|int|string|null> $params Bound parameters.
	 * @return array<string, mixed>|null
	 */
	public function fetchRow(string $sql, array $params = []): ?array;

	/**
	 * Fetch all matching associative rows.
	 *
	 * @param string $sql Parameterized SQL query.
	 * @param list<bool|float|int|string|null> $params Bound parameters.
	 * @return list<array<string, mixed>>
	 */
	public function fetchAssoc(string $sql, array $params = []): array;
}
