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

chdir('../../');
include('./include/auth.php');
include_once('./plugins/wordpress/setup.php');

if (!wordpress_page_start()) {
	exit;
}

$wp_messages = array();
$wp_errors   = array();

if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
	$wp_csrf = isset_request_var(\Somethingwithproof\WordPress\Ui\CsrfGuard::FIELD_NAME)
		? (string) get_nfilter_request_var(\Somethingwithproof\WordPress\Ui\CsrfGuard::FIELD_NAME)
		: '';

	if (!\Somethingwithproof\WordPress\Ui\CsrfGuard::verify($_SESSION, $wp_csrf)) {
		http_response_code(403);
		$wp_errors[] = __('CSRF verification failed. Reload the page and retry.', 'wordpress');
	} else {
		$wp_action = isset_request_var('action') ? (string) get_nfilter_request_var('action') : '';

		if ($wp_action === 'save_site') {
			$wp_slug = isset_request_var('slug') ? trim((string) get_nfilter_request_var('slug')) : '';
			$wp_site = array(
				'slug'           => $wp_slug,
				'name'           => isset_request_var('name') ? trim((string) get_nfilter_request_var('name')) : '',
				'base_url'       => isset_request_var('base_url') ? trim((string) get_nfilter_request_var('base_url')) : '',
				'username'       => isset_request_var('username') ? trim((string) get_nfilter_request_var('username')) : '',
				'poller_id'      => isset_request_var('poller_id') ? max(1, (int) get_nfilter_request_var('poller_id')) : 1,
				'enabled'        => true,
				'verify_tls'     => true,
			);

			$wp_validation = \Somethingwithproof\WordPress\Config\ConfigSchema::validateSite($wp_site);

			if ($wp_validation !== array()) {
				$wp_errors = $wp_validation;
			} else {
				wordpress_repository()->upsertSite($wp_site);
				$wp_messages[] = __('Saved WordPress site inventory entry.', 'wordpress');

				$wp_password = isset_request_var('app_password') ? trim((string) get_nfilter_request_var('app_password')) : '';

				if ($wp_password !== '') {
					try {
						wordpress_vault()->store($wp_slug, $wp_password);
						$wp_messages[] = __('Encrypted Application Password stored in local AES-256-GCM vault.', 'wordpress');
					} catch (\Somethingwithproof\WordPress\Security\SecurityException $error) {
						$wp_errors[] = $error->getMessage();
					}
				}
			}
		} elseif ($wp_action === 'delete_site') {
			$wp_slug = isset_request_var('slug') ? trim((string) get_nfilter_request_var('slug')) : '';

			if (preg_match(\Somethingwithproof\WordPress\Config\ConfigSchema::SLUG_PATTERN, $wp_slug) === 1) {
				wordpress_repository()->deleteSite($wp_slug);
				wordpress_vault()->delete($wp_slug);
				$wp_messages[] = __('Deleted WordPress site and associated local vault secret.', 'wordpress');
			} else {
				$wp_errors[] = __('Invalid site slug.', 'wordpress');
			}
		} else {
			$wp_errors[] = __('Unsupported administrator action.', 'wordpress');
		}
	}
}

$wp_csrf_field = \Somethingwithproof\WordPress\Ui\CsrfGuard::hiddenField($_SESSION);
$wp_sites      = wordpress_repository()->listSites();
$wp_secrets    = array();

foreach ($wp_sites as $wp_row) {
	$slug              = (string) ($wp_row['slug'] ?? '');
	$wp_secrets[$slug] = $slug !== '' && wordpress_vault()->hasSecret($slug);
}

$wp_vault_health = wordpress_vault()->healthStatus();
$wp_settings     = wordpress_settings();

top_header();
html_start_box(__('WordPress Inventory, Vault Credentials & Poller Assignment (Administrator)', 'wordpress'), '100%', false, 3, 'center', '');
print '<tr><td>' . \Somethingwithproof\WordPress\Ui\PagesRenderer::renderAdminConsole($wp_csrf_field, $wp_sites, $wp_secrets, $wp_vault_health, $wp_settings, $wp_messages, $wp_errors) . '</td></tr>';
html_end_box();
bottom_footer();
