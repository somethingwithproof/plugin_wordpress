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

namespace Somethingwithproof\WordPress\Config;

/**
 * Zero-dependency YAML and XML codec for plugin_wordpress declarative Config
 * export, validation, planning, and deterministic SHA-256 plan hashing.
 */
final class YamlXmlCodec {
	/**
	 * Encode a declarative Config document (settings + sites) as deterministic YAML.
	 *
	 * @param array<string, mixed> $document Config document with settings keys and optional sites list.
	 * @return string
	 */
	public static function encodeYaml(array $document): string {
		$lines = [
			'apiVersion: cacti.net/v1alpha1',
			'kind: WordPressFleetConfig',
			'schemaVersion: ' . self::yamlScalar(ConfigSchema::SCHEMA_VERSION),
			'settings:',
		];

		$settings = $document['settings'] ?? [];

		if (is_array($settings)) {
			ksort($settings);

			foreach ($settings as $key => $value) {
				$lines[] = '  ' . (string) $key . ': ' . self::yamlScalar($value);
			}
		}

		$sites = $document['sites'] ?? [];

		if (!is_array($sites) || $sites === []) {
			$lines[] = 'sites: []';
		} else {
			$lines[] = 'sites:';

			foreach ($sites as $site) {
				if (!is_array($site)) {
					continue;
				}

				ksort($site);
				$first = true;

				foreach ($site as $field => $val) {
					$prefix  = $first ? '  - ' : '    ';
					$lines[] = $prefix . (string) $field . ': ' . self::yamlScalar($val);
					$first   = false;
				}
			}
		}

		return implode("\n", $lines) . "\n";
	}

	/**
	 * Encode a declarative Config document (settings + sites) as deterministic XML.
	 *
	 * @param array<string, mixed> $document Config document with settings keys and optional sites list.
	 * @return string
	 */
	public static function encodeXml(array $document): string {
		$lines = [
			'<?xml version="1.0" encoding="UTF-8"?>',
			'<wordpressFleetConfig apiVersion="cacti.net/v1alpha1" schemaVersion="' . self::xmlEscape(ConfigSchema::SCHEMA_VERSION) . '">',
			'  <settings>',
		];

		$settings = $document['settings'] ?? [];

		if (is_array($settings)) {
			ksort($settings);

			foreach ($settings as $key => $value) {
				$type    = self::scalarTypeName($value);
				$encoded = is_bool($value) ? ($value ? 'true' : 'false') : (is_scalar($value) ? (string) $value : '');
				$lines[] = sprintf(
					'    <setting name="%s" type="%s">%s</setting>',
					self::xmlEscape((string) $key),
					$type,
					self::xmlEscape($encoded)
				);
			}
		}

		$lines[] = '  </settings>';
		$lines[] = '  <sites>';

		$sites = $document['sites'] ?? [];

		if (is_array($sites)) {
			foreach ($sites as $site) {
				if (!is_array($site)) {
					continue;
				}

				ksort($site);
				$lines[] = '    <site>';

				foreach ($site as $field => $val) {
					$type    = self::scalarTypeName($val);
					$encoded = is_bool($val) ? ($val ? 'true' : 'false') : (is_scalar($val) ? (string) $val : '');
					$lines[] = sprintf(
						'      <field name="%s" type="%s">%s</field>',
						self::xmlEscape((string) $field),
						$type,
						self::xmlEscape($encoded)
					);
				}

				$lines[] = '    </site>';
			}
		}

		$lines[] = '  </sites>';
		$lines[] = '</wordpressFleetConfig>';

		return implode("\n", $lines) . "\n";
	}

	/**
	 * Decode a YAML or XML Config document into a normalized associative array.
	 *
	 * @param string $content Raw YAML or XML text.
	 * @return array{settings: array<string, mixed>, sites: list<array<string, mixed>>}
	 * @throws \InvalidArgumentException When the document cannot be parsed safely.
	 */
	public static function decode(string $content): array {
		$trimmed = ltrim($content);

		if ($trimmed === '') {
			throw new \InvalidArgumentException('Config document is empty.');
		}

		if (str_starts_with($trimmed, '<')) {
			return self::decodeXml($trimmed);
		}

		return self::decodeYaml($content);
	}

	/**
	 * Compute a deterministic SHA-256 confirmation hash for a Config plan.
	 *
	 * @param array<string, mixed> $desired Normalized desired Config document.
	 * @param list<array<string, mixed>> $actions Planned change operations.
	 * @return string 64-character lowercase hex digest.
	 */
	public static function planHash(array $desired, array $actions): string {
		$canonical = json_encode(
			['desired' => self::sortRecursive($desired), 'actions' => $actions],
			JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR
		);

		return hash('sha256', $canonical);
	}

	/**
	 * Parse the plugin's structured YAML Config format without external YAML extensions.
	 *
	 * @param string $yaml Raw YAML content.
	 * @return array{settings: array<string, mixed>, sites: list<array<string, mixed>>}
	 */
	private static function decodeYaml(string $yaml): array {
		$settings    = [];
		$sites       = [];
		$section     = '';
		$currentSite = null;

		foreach (preg_split('/\r\n|\n|\r/', $yaml) ?: [] as $rawLine) {
			$line = rtrim($rawLine);

			if (trim($line) === '' || str_starts_with(ltrim($line), '#')) {
				continue;
			}

			if (!str_starts_with($line, ' ')) {
				if ($currentSite !== null) {
					$sites[]     = $currentSite;
					$currentSite = null;
				}

				if (preg_match('/^([A-Za-z0-9_]+):\s*(.*)$/', $line, $m) === 1) {
					$section = $m[1];

					if ($section === 'sites' && trim($m[2]) === '[]') {
						$sites = [];
					}
				}

				continue;
			}

			if ($section === 'settings' && preg_match('/^\s{2}([A-Za-z0-9_]+):\s*(.*)$/', $line, $m) === 1) {
				$settings[$m[1]] = self::parseYamlScalar($m[2]);

				continue;
			}

			if ($section === 'sites') {
				if (preg_match('/^\s{2}-\s+([A-Za-z0-9_]+):\s*(.*)$/', $line, $m) === 1) {
					if ($currentSite !== null) {
						$sites[] = $currentSite;
					}

					$currentSite        = [];
					$currentSite[$m[1]] = self::parseYamlScalar($m[2]);
				} elseif ($currentSite !== null && preg_match('/^\s{4}([A-Za-z0-9_]+):\s*(.*)$/', $line, $m) === 1) {
					$currentSite[$m[1]] = self::parseYamlScalar($m[2]);
				}
			}
		}

		if ($currentSite !== null) {
			$sites[] = $currentSite;
		}

		return ['settings' => $settings, 'sites' => $sites];
	}

	/**
	 * Parse the plugin's structured XML Config format with XXE/network entity loading disabled.
	 *
	 * @param string $xml Raw XML content.
	 * @return array{settings: array<string, mixed>, sites: list<array<string, mixed>>}
	 * @throws \InvalidArgumentException When XML is malformed or contains DOCTYPE declarations.
	 */
	private static function decodeXml(string $xml): array {
		if (stripos($xml, '<!DOCTYPE') !== false || stripos($xml, '<!ENTITY') !== false) {
			throw new \InvalidArgumentException('XML DOCTYPE and ENTITY declarations are forbidden.');
		}

		$previous = libxml_use_internal_errors(true);

		try {
			$doc = simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_NONET | LIBXML_NOCDATA);

			if ($doc === false) {
				throw new \InvalidArgumentException('Malformed XML configuration document.');
			}

			$settings = [];

			if (isset($doc->settings)) {
				foreach ($doc->settings->setting as $setting) {
					$name            = (string) ($setting['name'] ?? '');
					$type            = (string) ($setting['type'] ?? 'string');
					$settings[$name] = self::castTypedScalar((string) $setting, $type);
				}
			}

			$sites = [];

			if (isset($doc->sites)) {
				foreach ($doc->sites->site as $siteNode) {
					$entry = [];

					foreach ($siteNode->field as $field) {
						$name         = (string) ($field['name'] ?? '');
						$type         = (string) ($field['type'] ?? 'string');
						$entry[$name] = self::castTypedScalar((string) $field, $type);
					}

					$sites[] = $entry;
				}
			}

			return ['settings' => $settings, 'sites' => $sites];
		} finally {
			libxml_clear_errors();
			libxml_use_internal_errors($previous);
		}
	}

	/**
	 * Format a PHP scalar as a safe YAML scalar literal.
	 *
	 * @param mixed $value Scalar value.
	 * @return string
	 */
	private static function yamlScalar(mixed $value): string {
		if (is_bool($value)) {
			return $value ? 'true' : 'false';
		}

		if (is_int($value) || is_float($value)) {
			return (string) $value;
		}

		$str = is_scalar($value) ? (string) $value : '';

		return "'" . str_replace("'", "''", $str) . "'";
	}

	/**
	 * Parse a YAML scalar token back into a typed PHP scalar.
	 *
	 * @param string $raw Raw YAML scalar token.
	 * @return bool|int|string
	 */
	private static function parseYamlScalar(string $raw): bool|int|string {
		$trimmed = trim($raw);

		if ($trimmed === 'true') {
			return true;
		}

		if ($trimmed === 'false') {
			return false;
		}

		if (preg_match('/^-?\d+$/', $trimmed) === 1) {
			return (int) $trimmed;
		}

		if (strlen($trimmed) >= 2 && $trimmed[0] === "'" && str_ends_with($trimmed, "'")) {
			return str_replace("''", "'", substr($trimmed, 1, -1));
		}

		if (strlen($trimmed) >= 2 && $trimmed[0] === '"' && str_ends_with($trimmed, '"')) {
			return stripcslashes(substr($trimmed, 1, -1));
		}

		return $trimmed;
	}

	/**
	 * Cast a string value from XML using its explicit type attribute.
	 *
	 * @param string $raw Raw element text.
	 * @param string $type Declared scalar type name.
	 * @return bool|int|string
	 */
	private static function castTypedScalar(string $raw, string $type): bool|int|string {
		if ($type === 'boolean') {
			return in_array(strtolower(trim($raw)), ['true', '1', 'on'], true);
		}

		if ($type === 'integer') {
			return (int) trim($raw);
		}

		return $raw;
	}

	/**
	 * Identify the XML type attribute label for a scalar value.
	 *
	 * @param mixed $value Value to inspect.
	 * @return string
	 */
	private static function scalarTypeName(mixed $value): string {
		if (is_bool($value)) {
			return 'boolean';
		}

		if (is_int($value)) {
			return 'integer';
		}

		return 'string';
	}

	/**
	 * Escape XML text and attribute values safely.
	 *
	 * @param string $value Unescaped text.
	 * @return string
	 */
	private static function xmlEscape(string $value): string {
		return htmlspecialchars($value, ENT_XML1 | ENT_QUOTES, 'UTF-8');
	}

	/**
	 * Recursively sort associative array keys for canonical plan hashing.
	 *
	 * @param array<mixed> $data Input structure.
	 * @return array<mixed>
	 */
	private static function sortRecursive(array $data): array {
		if (!array_is_list($data)) {
			ksort($data);
		}

		foreach ($data as $key => $val) {
			if (is_array($val)) {
				$data[$key] = self::sortRecursive($val);
			}
		}

		return $data;
	}
}
