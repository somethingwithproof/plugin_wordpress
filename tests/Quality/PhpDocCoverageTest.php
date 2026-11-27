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

namespace Somethingwithproof\WordPress\Tests\Quality;

use PHPUnit\Framework\TestCase;

/**
 * Enforces 100% AST-verified PHPDoc coverage across lib/, setup.php, and scripts/,
 * and enforces zero hard PHP imports of sibling plugins across all runtime files.
 */
final class PhpDocCoverageTest extends TestCase {
	/**
	 * Sibling plugin namespace prefixes that must never be imported at boot or runtime.
	 *
	 * @var list<string>
	 */
	private const FORBIDDEN_SIBLING_IMPORTS = [
		'Somethingwithproof\\Casc\\',
		'Somethingwithproof\\Doctor\\',
		'Somethingwithproof\\Mcp\\',
		'Somethingwithproof\\Api\\',
		'Somethingwithproof\\Cache\\',
		'Somethingwithproof\\Yaml\\',
		'Somethingwithproof\\Vault\\',
	];

	/**
	 * Verify that every class, interface, trait, enum, constant, property, method,
	 * and top-level function in lib/, setup.php, and scripts/ has complete PHPDoc.
	 */
	public function testHundredPercentPhpDocCoverage(): void {
		$root       = dirname(__DIR__, 2);
		$violations = [];

		$files   = $this->collectPhpFiles($root . '/lib');
		$files[] = $root . '/setup.php';

		foreach ($this->collectPhpFiles($root . '/scripts') as $scriptFile) {
			if (basename($scriptFile) === 'benchmark.php') {
				continue;
			}

			$files[] = $scriptFile;
		}

		foreach ($files as $file) {
			require_once $file;
			$symbols = $this->extractDeclaredSymbols($file);

			foreach ($symbols['types'] as $fqcn) {
				$ref = new \ReflectionClass($fqcn);
				$this->checkDocComment($ref->getDocComment(), $fqcn, $violations);

				foreach ($ref->getReflectionConstants() as $constant) {
					if ($constant->getDeclaringClass()->getName() !== $fqcn) {
						continue;
					}

					$this->checkDocComment(
						$constant->getDocComment(),
						$fqcn . '::' . $constant->getName(),
						$violations
					);
				}

				foreach ($ref->getProperties() as $property) {
					if ($property->getDeclaringClass()->getName() !== $fqcn) {
						continue;
					}

					$propLabel = $fqcn . '::$' . $property->getName();

					if ($property->isPromoted()) {
						$ctor    = $ref->getConstructor();
						$ctorDoc = $ctor !== null ? $ctor->getDocComment() : false;

						if (
							($property->getDocComment() === false || trim($property->getDocComment()) === '')
							&& ($ctorDoc === false || !str_contains($ctorDoc, '$' . $property->getName()))
						) {
							$violations[] = 'Missing PHPDoc for promoted property ' . $propLabel;
						}

						continue;
					}

					$this->checkDocComment($property->getDocComment(), $propLabel, $violations);
				}

				foreach ($ref->getMethods() as $method) {
					if ($method->getDeclaringClass()->getName() !== $fqcn) {
						continue;
					}

					$this->checkCallableDoc(
						$method->getDocComment(),
						$method->getParameters(),
						$fqcn . '::' . $method->getName() . '()',
						in_array($method->getName(), ['__construct', '__destruct'], true),
						$violations
					);
				}
			}

			foreach ($symbols['functions'] as $fnName) {
				$ref = new \ReflectionFunction($fnName);
				$this->checkCallableDoc(
					$ref->getDocComment(),
					$ref->getParameters(),
					$fnName . '()',
					false,
					$violations
				);
			}
		}

		$this->assertSame([], $violations, "PHPDoc coverage violations:\n" . implode("\n", $violations));
	}

	/**
	 * Verify zero hard cross-plugin PHP imports or includes across all runtime PHP files.
	 */
	public function testZeroCrossPluginPhpImports(): void {
		$root       = dirname(__DIR__, 2);
		$violations = [];
		$scanFiles  = array_merge(
			$this->collectPhpFiles($root . '/lib'),
			$this->collectPhpFiles($root . '/cli'),
			$this->collectPhpFiles($root . '/include'),
			$this->collectPhpFiles($root . '/scripts'),
			[
				$root . '/setup.php',
				$root . '/poller_wordpress.php',
				$root . '/wordpress_view.php',
				$root . '/wordpress_operator.php',
				$root . '/wordpress_admin.php',
			]
		);

		foreach ($scanFiles as $file) {
			if (!is_file($file)) {
				continue;
			}

			$source = (string) file_get_contents($file);

			foreach (self::FORBIDDEN_SIBLING_IMPORTS as $prefix) {
				if (str_contains($source, $prefix)) {
					$violations[] = sprintf('%s references sibling plugin namespace %s', basename($file), $prefix);
				}
			}

			if (preg_match('/\b(require|require_once|include|include_once)\b[^\n;]*plugins\/(casc|doctor|mcp|api|cache|yaml|vault)\b/i', $source) === 1) {
				$violations[] = sprintf('%s directly includes a sibling plugin file', basename($file));
			}
		}

		$this->assertSame([], $violations, "Cross-plugin import violations:\n" . implode("\n", $violations));
	}

	/**
	 * Recursively collect all PHP source files under a directory.
	 *
	 * @param string $dir Root directory.
	 * @return list<string>
	 */
	private function collectPhpFiles(string $dir): array {
		if (!is_dir($dir)) {
			return [];
		}

		$files    = [];
		$iterator = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($dir));

		foreach ($iterator as $entry) {
			if ($entry instanceof \SplFileInfo && $entry->isFile() && $entry->getExtension() === 'php') {
				$files[] = $entry->getPathname();
			}
		}

		sort($files, SORT_STRING);

		return $files;
	}

	/**
	 * Tokenize a PHP file to extract declared class-like types and top-level functions.
	 *
	 * @param string $file Absolute PHP file path.
	 * @return array{types: list<class-string>, functions: list<string>}
	 */
	private function extractDeclaredSymbols(string $file): array {
		$source = file_get_contents($file);
		$this->assertIsString($source, 'Unable to read ' . $file);

		$tokens    = token_get_all($source);
		$namespace = '';
		$types     = [];
		$functions = [];
		$depth     = 0;
		$count     = count($tokens);

		for ($i = 0; $i < $count; $i++) {
			$tok = $tokens[$i];

			if ($tok === '{') {
				$depth++;

				continue;
			}

			if ($tok === '}') {
				$depth = max(0, $depth - 1);

				continue;
			}

			if (!is_array($tok)) {
				continue;
			}

			if ($tok[0] === T_NAMESPACE) {
				$nsParts = [];

				for ($j = $i + 1; $j < $count; $j++) {
					if ($tokens[$j] === ';' || $tokens[$j] === '{') {
						break;
					}

					if (is_array($tokens[$j]) && in_array($tokens[$j][0], [T_STRING, T_NAME_QUALIFIED], true)) {
						$nsParts[] = $tokens[$j][1];
					}
				}

				$namespace = implode('\\', $nsParts);

				continue;
			}

			if (in_array($tok[0], [T_CLASS, T_INTERFACE, T_TRAIT, T_ENUM], true)) {
				$prev = $this->previousNonWhitespace($tokens, $i);

				if ($prev === T_NEW || $prev === T_DOUBLE_COLON) {
					continue;
				}

				$name = $this->nextStringToken($tokens, $i);

				if ($name !== null) {
					$fqcn = $namespace !== '' ? $namespace . '\\' . $name : $name;

					if (class_exists($fqcn) || interface_exists($fqcn) || trait_exists($fqcn)) {
						/** @var class-string $fqcn */
						$types[] = $fqcn;
					}
				}

				continue;
			}

			if ($tok[0] === T_FUNCTION && $depth === 0) {
				$name = $this->nextStringToken($tokens, $i);

				if ($name !== null) {
					$fqfn = $namespace !== '' ? $namespace . '\\' . $name : $name;

					if (function_exists($fqfn)) {
						$functions[] = $fqfn;
					}
				}
			}
		}

		return ['types' => $types, 'functions' => $functions];
	}

	/**
	 * Inspect the nearest preceding non-whitespace token ID.
	 *
	 * @param list<array{0: int, 1: string, 2: int}|string> $tokens Token stream.
	 * @param int $index Current token index.
	 * @return int|null
	 */
	private function previousNonWhitespace(array $tokens, int $index): ?int {
		for ($j = $index - 1; $j >= 0; $j--) {
			if (is_array($tokens[$j]) && $tokens[$j][0] === T_WHITESPACE) {
				continue;
			}

			return is_array($tokens[$j]) ? $tokens[$j][0] : null;
		}

		return null;
	}

	/**
	 * Read the next T_STRING identifier token after $index, stopping on '(' or '{'.
	 *
	 * @param list<array{0: int, 1: string, 2: int}|string> $tokens Token stream.
	 * @param int $index Current token index.
	 * @return string|null
	 */
	private function nextStringToken(array $tokens, int $index): ?string {
		$count = count($tokens);

		for ($j = $index + 1; $j < $count; $j++) {
			if ($tokens[$j] === '(' || $tokens[$j] === '{' || $tokens[$j] === ';') {
				return null;
			}

			if (is_array($tokens[$j]) && $tokens[$j][0] === T_STRING) {
				return $tokens[$j][1];
			}
		}

		return null;
	}

	/**
	 * Verify a symbol has a non-empty PHPDoc block.
	 *
	 * @param string|false $doc Docblock string or false.
	 * @param string $label Human-readable symbol label.
	 * @param list<string> $violations Violation accumulator.
	 * @return void
	 */
	private function checkDocComment(string|false $doc, string $label, array &$violations): void {
		if ($doc === false || trim($doc) === '') {
			$violations[] = 'Missing PHPDoc for ' . $label;
		}
	}

	/**
	 * Verify a method or function has a docblock, @param tags for all parameters, and @return when applicable.
	 *
	 * @param string|false $doc Docblock string or false.
	 * @param list<\ReflectionParameter> $parameters Reflected parameters.
	 * @param string $label Human-readable callable label.
	 * @param bool $omitReturn True for __construct and __destruct.
	 * @param list<string> $violations Violation accumulator.
	 * @return void
	 */
	private function checkCallableDoc(
		string|false $doc,
		array $parameters,
		string $label,
		bool $omitReturn,
		array &$violations,
	): void {
		if ($doc === false || trim($doc) === '') {
			$violations[] = 'Missing PHPDoc for ' . $label;

			return;
		}

		foreach ($parameters as $param) {
			if (!preg_match('/@param\s+[^@]*\$' . preg_quote($param->getName(), '/') . '\b/s', $doc)) {
				$violations[] = sprintf('Missing @param $%s in PHPDoc for %s', $param->getName(), $label);
			}
		}

		if (!$omitReturn && !str_contains($doc, '@return')) {
			$violations[] = 'Missing @return in PHPDoc for ' . $label;
		}
	}
}
