<?php
/**
 * WP Contact Uninstall
 * 
 * This file runs when the plugin is deleted from WordPress.
 * It removes all plugin data including encrypted credentials.
 */

// If uninstall not called from WordPress, exit
if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

// Remove plugin options from database
delete_option('wp_contact_options');

// Remove encrypted credentials file
$config_file = plugin_dir_path(__FILE__) . 'config/credentials.enc';
if (file_exists($config_file)) {
    // Overwrite with random data before deletion (secure erase)
    $handle = fopen($config_file, 'w');
    if ($handle) {
        fwrite($handle, random_bytes(1024));
        fclose($handle);
    }
    unlink($config_file);
}

// Remove config directory files
$config_dir = plugin_dir_path(__FILE__) . 'config';
if (is_dir($config_dir)) {
    $files = glob($config_dir . '/*');
    foreach ($files as $file) {
        if (is_file($file)) {
            unlink($file);
        }
    }
    // Remove .htaccess (hidden file)
    $htaccess = $config_dir . '/.htaccess';
    if (file_exists($htaccess)) {
        unlink($htaccess);
    }
    rmdir($config_dir);
}

// Clean up any transients
global $wpdb;
$wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_wp_contact_%'");
$wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_timeout_wp_contact_%'");
