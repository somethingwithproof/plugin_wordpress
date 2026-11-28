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
 * Production DbAdapter backed by Cacti's prepared db_*_prepared() functions.
 */
final class CactiDbAdapter implements DbAdapter {
	/**
	 * Construct a Cacti database adapter bound to an optional PDO connection.
	 *
	 * @param \PDO|false $connection Cacti PDO connection handle or false for default.
	 */
	public function __construct(private readonly \PDO|false $connection = false) {
	}

	/**
	 * Execute a prepared SQL write statement through Cacti's db_execute_prepared().
	 *
	 * @param string $sql Parameterized SQL statement.
	 * @param list<bool|float|int|string|null> $params Positional parameters.
	 * @return bool
	 */
	public function execute(string $sql, array $params = []): bool {
		return (bool) db_execute_prepared($sql, $params, true, $this->connection);
	}

	/**
	 * Fetch a single scalar cell through Cacti's db_fetch_cell_prepared().
	 *
	 * @param string $sql Parameterized SQL query.
	 * @param list<bool|float|int|string|null> $params Positional parameters.
	 * @return mixed
	 */
	public function fetchCell(string $sql, array $params = []): mixed {
		return db_fetch_cell_prepared($sql, $params, '', true, $this->connection);
	}

	/**
	 * Fetch a single associative row through Cacti's db_fetch_row_prepared().
	 *
	 * @param string $sql Parameterized SQL query.
	 * @param list<bool|float|int|string|null> $params Positional parameters.
	 * @return array<string, mixed>|null
	 */
	public function fetchRow(string $sql, array $params = []): ?array {
		$row = db_fetch_row_prepared($sql, $params, true, $this->connection);

		if (!is_array($row) || $row === []) {
			return null;
		}

		/** @var array<string, mixed> $normalized */
		$normalized = $row;

		return $normalized;
	}

	/**
	 * Fetch all matching rows through Cacti's db_fetch_assoc_prepared().
	 *
	 * @param string $sql Parameterized SQL query.
	 * @param list<bool|float|int|string|null> $params Positional parameters.
	 * @return list<array<string, mixed>>
	 */
	public function fetchAssoc(string $sql, array $params = []): array {
		$rows = db_fetch_assoc_prepared($sql, $params, true, $this->connection);

		if (!is_array($rows)) {
			return [];
		}

		$result = [];

		foreach ($rows as $row) {
			if (is_array($row)) {
				/** @var array<string, mixed> $typedRow */
				$typedRow = $row;
				$result[] = $typedRow;
			}
		}

		return $result;
	}
}
