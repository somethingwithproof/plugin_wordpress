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

$wp_settings  = wordpress_settings();
$wp_snapshots = wordpress_repository()->loadSnapshots();
$wp_analysis  = (new \Somethingwithproof\WordPress\Metrics\FleetAnalyzer($wp_settings))->analyze($wp_snapshots);
$wp_templates = \Somethingwithproof\WordPress\Metrics\FleetAnalyzer::tholdTemplates($wp_settings);

top_header();
html_start_box(__('WordPress Fleet Health & Metrics Overview (View)', 'wordpress'), '100%', false, 3, 'center', '');
print '<tr><td>' . \Somethingwithproof\WordPress\Ui\PagesRenderer::renderViewConsole($wp_analysis, $wp_snapshots, $wp_templates) . '</td></tr>';
html_end_box();
bottom_footer();
