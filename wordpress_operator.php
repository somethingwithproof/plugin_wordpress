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

$wp_messages    = array();
$wp_errors      = array();
$wp_probe_res   = null;

if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
	$wp_csrf = isset_request_var(\Somethingwithproof\WordPress\Ui\CsrfGuard::FIELD_NAME)
		? (string) get_nfilter_request_var(\Somethingwithproof\WordPress\Ui\CsrfGuard::FIELD_NAME)
		: '';

	if (!\Somethingwithproof\WordPress\Ui\CsrfGuard::verify($_SESSION, $wp_csrf)) {
		http_response_code(403);
		$wp_errors[] = __('CSRF verification failed. Reload the page and retry.', 'wordpress');
	} else {
		$wp_action = isset_request_var('action') ? (string) get_nfilter_request_var('action') : '';

		if ($wp_action === 'dry_run_probe') {
			$wp_slug = isset_request_var('site_slug') ? trim((string) get_nfilter_request_var('site_slug')) : '';

			if ($wp_slug === '') {
				$wp_errors[] = __('Select a site to probe.', 'wordpress');
			} else {
				$wp_probe_res = wordpress_poller()->probeSite($wp_slug, false);

				if ($wp_probe_res === null) {
					$wp_errors[] = __('Unknown WordPress site slug.', 'wordpress');
				} else {
					$wp_messages[] = __('Completed read-only dry-run probe.', 'wordpress');
				}
			}
		} else {
			$wp_errors[] = __('Unsupported operator action.', 'wordpress');
		}
	}
}

$wp_csrf_field = \Somethingwithproof\WordPress\Ui\CsrfGuard::hiddenField($_SESSION);
$wp_sites      = wordpress_repository()->listSites();
$wp_analysis   = (new \Somethingwithproof\WordPress\Metrics\FleetAnalyzer(wordpress_settings()))->analyze(wordpress_repository()->loadSnapshots());

top_header();
html_start_box(__('WordPress Drift, Site Health, Cron & Dry-Run Probes (Operator)', 'wordpress'), '100%', false, 3, 'center', '');
print '<tr><td>' . \Somethingwithproof\WordPress\Ui\PagesRenderer::renderOperatorConsole($wp_csrf_field, $wp_sites, $wp_analysis, $wp_probe_res, $wp_messages, $wp_errors) . '</td></tr>';
html_end_box();
bottom_footer();
