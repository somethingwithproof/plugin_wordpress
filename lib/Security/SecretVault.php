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

use Somethingwithproof\WordPress\Config\ConfigSchema;
use Somethingwithproof\WordPress\Db\DbAdapter;

/**
 * AES-256-GCM at-rest vault for WordPress Application Passwords using an external
 * 256-bit keyfile (wordpress_vault_key_file).
 *
 * Ciphertexts are authenticated with site-slug AAD so credentials cannot be swapped
 * across sites, stored strictly in local-only plugin_wordpress_secrets (never
 * replicated to remote pollers), and never exported in CasC, Doctor, MCP, API, or logs.
 */
final class SecretVault {
	/**
	 * OpenSSL AEAD cipher algorithm.
	 */
	private const CIPHER = 'aes-256-gcm';

	/**
	 * Version prefix for persisted AES-256-GCM envelopes.
	 */
	private const ENVELOPE_VERSION = 'v1';

	/**
	 * Nonce size in bytes for AES-256-GCM (96-bit NIST recommendation).
	 */
	private const IV_LENGTH = 12;

	/**
	 * Authentication tag size in bytes (128-bit GCM tag).
	 */
	private const TAG_LENGTH = 16;

	/**
	 * Required symmetric key length in bytes (256-bit).
	 */
	private const KEY_LENGTH = 32;

	/**
	 * Cached raw 32-byte key loaded from the external keyfile.
	 */
	private ?string $cachedKey = null;

	/**
	 * Cached 16-hex-character SHA-256 key fingerprint (safe for diagnostics).
	 */
	private ?string $cachedFingerprint = null;

	/**
	 * Construct a SecretVault bound to a database adapter and external keyfile path.
	 *
	 * @param DbAdapter $db Database adapter backing plugin_wordpress_secrets.
	 * @param string $keyFilePath Absolute path to the external 256-bit keyfile.
	 * @param bool $enforcePermissions Reject world-readable keyfiles when true.
	 */
	public function __construct(
		private readonly DbAdapter $db,
		private readonly string $keyFilePath,
		private readonly bool $enforcePermissions = true,
	) {
	}

	/**
	 * Return the symbolic, non-secret vault reference string for a WordPress site slug.
	 *
	 * @param string $siteSlug Validated WordPress site slug.
	 * @return string
	 */
	public static function referenceFor(string $siteSlug): string {
		return 'vault:wordpress:' . $siteSlug;
	}

	/**
	 * Encrypt a WordPress Application Password using AES-256-GCM bound to the site slug AAD.
	 *
	 * @param string $siteSlug Validated WordPress site slug.
	 * @param string $plaintext Raw Application Password.
	 * @return string Versioned authenticated envelope (v1:<iv>:<tag>:<ciphertext>).
	 * @throws SecurityException When inputs are invalid, keyfile is unavailable, or encryption fails.
	 */
	public function encrypt(string $siteSlug, string $plaintext): string {
		self::assertValidSlug($siteSlug);

		if ($plaintext === '') {
			throw new SecurityException('Application Password plaintext must not be empty.');
		}

		$key = $this->loadKey();
		$iv  = random_bytes(self::IV_LENGTH);
		$tag = '';
		$aad = self::aadFor($siteSlug);

		$ciphertext = openssl_encrypt(
			$plaintext,
			self::CIPHER,
			$key,
			OPENSSL_RAW_DATA,
			$iv,
			$tag,
			$aad,
			self::TAG_LENGTH
		);

		if (!is_string($ciphertext) || strlen($tag) !== self::TAG_LENGTH) {
			throw new SecurityException('AES-256-GCM encryption failed.');
		}

		return self::ENVELOPE_VERSION
			. ':' . base64_encode($iv)
			. ':' . base64_encode($tag)
			. ':' . base64_encode($ciphertext);
	}

	/**
	 * Decrypt a persisted AES-256-GCM envelope and verify its tag against the site slug AAD.
	 *
	 * @param string $siteSlug Validated WordPress site slug.
	 * @param string $envelope Stored v1:<iv>:<tag>:<ciphertext> envelope.
	 * @return string Decrypted Application Password.
	 * @throws SecurityException When envelope is malformed, tampered, or bound to a different site.
	 */
	public function decrypt(string $siteSlug, string $envelope): string {
		self::assertValidSlug($siteSlug);

		$parts = explode(':', $envelope);

		if (count($parts) !== 4 || $parts[0] !== self::ENVELOPE_VERSION) {
			throw new SecurityException('Unsupported or malformed vault ciphertext envelope.');
		}

		$iv         = base64_decode($parts[1], true);
		$tag        = base64_decode($parts[2], true);
		$ciphertext = base64_decode($parts[3], true);

		if (!is_string($iv) || strlen($iv) !== self::IV_LENGTH
			|| !is_string($tag) || strlen($tag) !== self::TAG_LENGTH
			|| !is_string($ciphertext) || $ciphertext === ''
		) {
			throw new SecurityException('Vault ciphertext envelope failed structural validation.');
		}

		$key       = $this->loadKey();
		$aad       = self::aadFor($siteSlug);
		$plaintext = openssl_decrypt(
			$ciphertext,
			self::CIPHER,
			$key,
			OPENSSL_RAW_DATA,
			$iv,
			$tag,
			$aad
		);

		if (!is_string($plaintext)) {
			throw new SecurityException('Vault decryption failed authentication tag verification.');
		}

		return $plaintext;
	}

	/**
	 * Encrypt and persist a WordPress Application Password in plugin_wordpress_secrets.
	 *
	 * @param string $siteSlug Validated site slug.
	 * @param string $plaintext Raw Application Password.
	 * @return bool True on successful write.
	 */
	public function store(string $siteSlug, string $plaintext): bool {
		$envelope    = $this->encrypt($siteSlug, $plaintext);
		$fingerprint = $this->keyFingerprint();

		return $this->db->execute(
			'REPLACE INTO plugin_wordpress_secrets (site_slug, ciphertext, key_fingerprint, updated_at) VALUES (?, ?, ?, ?)',
			[$siteSlug, $envelope, $fingerprint, time()]
		);
	}

	/**
	 * Retrieve and decrypt the WordPress Application Password for a site slug.
	 *
	 * Falls back to soft-coupled cacti_vault_get('wordpress', $siteSlug) when no local
	 * secret row exists and an external vault helper is loaded at runtime.
	 *
	 * @param string $siteSlug Validated site slug.
	 * @return string|null Decrypted Application Password or null when not configured.
	 */
	public function retrieve(string $siteSlug): ?string {
		self::assertValidSlug($siteSlug);

		$row = $this->db->fetchRow(
			'SELECT ciphertext FROM plugin_wordpress_secrets WHERE site_slug = ?',
			[$siteSlug]
		);

		if ($row !== null && isset($row['ciphertext']) && is_string($row['ciphertext']) && $row['ciphertext'] !== '') {
			return $this->decrypt($siteSlug, $row['ciphertext']);
		}

		if (function_exists('cacti_vault_get')) {
			$external = cacti_vault_get('wordpress', $siteSlug);

			if (is_string($external) && $external !== '') {
				return $external;
			}
		}

		return null;
	}

	/**
	 * Remove a stored encrypted credential for a site slug.
	 *
	 * @param string $siteSlug Validated site slug.
	 * @return bool
	 */
	public function delete(string $siteSlug): bool {
		self::assertValidSlug($siteSlug);

		return $this->db->execute(
			'DELETE FROM plugin_wordpress_secrets WHERE site_slug = ?',
			[$siteSlug]
		);
	}

	/**
	 * Check whether an encrypted secret row exists for a site slug without decrypting it.
	 *
	 * @param string $siteSlug Validated site slug.
	 * @return bool
	 */
	public function hasSecret(string $siteSlug): bool {
		self::assertValidSlug($siteSlug);

		$count = $this->db->fetchCell(
			'SELECT COUNT(*) FROM plugin_wordpress_secrets WHERE site_slug = ?',
			[$siteSlug]
		);

		return is_numeric($count) && (int) $count > 0;
	}

	/**
	 * Return the number of encrypted credentials currently stored locally.
	 *
	 * @return int
	 */
	public function countStoredSecrets(): int {
		$count = $this->db->fetchCell('SELECT COUNT(*) FROM plugin_wordpress_secrets');

		return is_numeric($count) ? (int) $count : 0;
	}

	/**
	 * Return a safe non-secret diagnostic summary of the vault keyfile configuration.
	 *
	 * @return array{configured: bool, readable: bool, permissionsOk: bool, keyFingerprint: string, storedSecrets: int, error: string}
	 */
	public function healthStatus(): array {
		$stored = $this->countStoredSecrets();

		if ($this->keyFilePath === '') {
			return [
				'configured'     => false,
				'readable'       => false,
				'permissionsOk'  => false,
				'keyFingerprint' => '',
				'storedSecrets'  => $stored,
				'error'          => 'wordpress_vault_key_file is not configured.',
			];
		}

		try {
			$this->loadKey();

			return [
				'configured'     => true,
				'readable'       => true,
				'permissionsOk'  => true,
				'keyFingerprint' => $this->keyFingerprint(),
				'storedSecrets'  => $stored,
				'error'          => '',
			];
		} catch (SecurityException $error) {
			return [
				'configured'     => true,
				'readable'       => is_readable($this->keyFilePath),
				'permissionsOk'  => false,
				'keyFingerprint' => '',
				'storedSecrets'  => $stored,
				'error'          => $error->getMessage(),
			];
		}
	}

	/**
	 * Return a 16-hex-character SHA-256 fingerprint of the active 256-bit vault key.
	 *
	 * @return string
	 */
	public function keyFingerprint(): string {
		if ($this->cachedFingerprint === null) {
			$this->loadKey();
		}

		return $this->cachedFingerprint ?? '';
	}

	/**
	 * Load and validate the 256-bit symmetric key from the configured external keyfile.
	 *
	 * Accepts 32 raw bytes, 64 hex characters, or a "base64:<encoded>" string decoding to 32 bytes.
	 *
	 * @return string Raw 32-byte key material.
	 * @throws SecurityException When the keyfile is missing, world-readable, unreadable, or wrong length.
	 */
	private function loadKey(): string {
		if ($this->cachedKey !== null) {
			return $this->cachedKey;
		}

		if ($this->keyFilePath === '' || !is_file($this->keyFilePath) || !is_readable($this->keyFilePath)) {
			throw new SecurityException('Vault keyfile is missing or unreadable.');
		}

		if ($this->enforcePermissions) {
			$perms = @fileperms($this->keyFilePath);

			if (is_int($perms) && ($perms & 0o007) !== 0) {
				throw new SecurityException('Vault keyfile must not be world-accessible (recommended chmod 0600).');
			}
		}

		$raw = @file_get_contents($this->keyFilePath);

		if (!is_string($raw) || $raw === '') {
			throw new SecurityException('Vault keyfile is empty or could not be read.');
		}

		$key = self::decodeKeyMaterial($raw);

		if (strlen($key) !== self::KEY_LENGTH) {
			throw new SecurityException('Vault keyfile must supply exactly 256 bits (32 bytes) of key material.');
		}

		$this->cachedKey         = $key;
		$this->cachedFingerprint = substr(hash('sha256', $key), 0, 16);

		return $this->cachedKey;
	}

	/**
	 * Decode raw binary, 64-character hex, or base64-prefixed 256-bit keyfile content.
	 *
	 * @param string $raw Raw file contents.
	 * @return string Decoded key bytes.
	 */
	private static function decodeKeyMaterial(string $raw): string {
		if (strlen($raw) === self::KEY_LENGTH) {
			return $raw;
		}

		$trimmed = trim($raw);

		if (strlen($trimmed) === 64 && ctype_xdigit($trimmed)) {
			$decoded = hex2bin($trimmed);

			if (is_string($decoded)) {
				return $decoded;
			}
		}

		if (str_starts_with($trimmed, 'base64:')) {
			$decoded = base64_decode(substr($trimmed, 7), true);

			if (is_string($decoded)) {
				return $decoded;
			}
		}

		return '';
	}

	/**
	 * Build deterministic Authenticated Additional Data binding ciphertext to a site slug.
	 *
	 * @param string $siteSlug Validated site slug.
	 * @return string
	 */
	private static function aadFor(string $siteSlug): string {
		return 'wordpress:site:' . $siteSlug;
	}

	/**
	 * Assert a site slug matches the canonical lowercase identifier pattern.
	 *
	 * @param string $siteSlug Candidate slug.
	 * @return void
	 * @throws SecurityException When slug format is invalid.
	 */
	private static function assertValidSlug(string $siteSlug): void {
		if (preg_match(ConfigSchema::SLUG_PATTERN, $siteSlug) !== 1) {
			throw new SecurityException('Invalid WordPress site slug for vault operation.');
		}
	}
}
