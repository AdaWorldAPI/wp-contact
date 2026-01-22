<?php
/**
 * Plugin Name: WP Contact
 * Plugin URI: https://github.com/AdaWorldAPI/wp-contact
 * Description: Elegant contact form with Microsoft Graph email delivery and encrypted credentials
 * Version: 1.0.0
 * Author: Jan Hübener
 * License: MIT
 * Text Domain: wp-contact
 */

if (!defined('ABSPATH')) {
    exit;
}

define('WP_CONTACT_VERSION', '1.0.0');
define('WP_CONTACT_PATH', plugin_dir_path(__FILE__));
define('WP_CONTACT_URL', plugin_dir_url(__FILE__));
define('WP_CONTACT_CONFIG_FILE', WP_CONTACT_PATH . 'config/credentials.enc');

class WP_Contact_Form {
    
    private static $instance = null;
    private $encryption_key = null;
    
    public static function instance() {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }
    
    private function __construct() {
        $this->init_encryption_key();
        $this->init_hooks();
    }
    
    private function init_encryption_key() {
        // Derive encryption key from WordPress salts (unique per installation)
        $this->encryption_key = hash('sha256', AUTH_KEY . SECURE_AUTH_KEY . 'wp_contact_v1', true);
    }
    
    private function init_hooks() {
        add_action('admin_menu', [$this, 'add_admin_menu']);
        add_action('admin_init', [$this, 'register_settings']);
        add_action('wp_enqueue_scripts', [$this, 'enqueue_frontend_assets']);
        add_action('admin_enqueue_scripts', [$this, 'enqueue_admin_assets']);
        add_action('wp_ajax_wp_contact_submit', [$this, 'handle_form_submission']);
        add_action('wp_ajax_nopriv_wp_contact_submit', [$this, 'handle_form_submission']);
        add_shortcode('WP_Contact', [$this, 'render_contact_form']);
        
        register_activation_hook(__FILE__, [$this, 'activate']);
        register_deactivation_hook(__FILE__, [$this, 'deactivate']);
    }
    
    public function activate() {
        // Create config directory with restricted permissions
        $config_dir = WP_CONTACT_PATH . 'config';
        if (!file_exists($config_dir)) {
            wp_mkdir_p($config_dir);
            chmod($config_dir, 0755);
        }
        
        // Create .htaccess to protect config directory
        $htaccess = $config_dir . '/.htaccess';
        if (!file_exists($htaccess)) {
            file_put_contents($htaccess, "Deny from all\n");
            chmod($htaccess, 0644);
        }
        
        // Create index.php to prevent directory listing
        $index = $config_dir . '/index.php';
        if (!file_exists($index)) {
            file_put_contents($index, "<?php // Silence is golden\n");
            chmod($index, 0644);
        }
        
        flush_rewrite_rules();
    }
    
    public function deactivate() {
        flush_rewrite_rules();
    }
    
    // ═══════════════════════════════════════════════════════════════
    // ENCRYPTION / DECRYPTION
    // ═══════════════════════════════════════════════════════════════
    
    private function encrypt($data) {
        $iv = openssl_random_pseudo_bytes(16);
        $encrypted = openssl_encrypt(
            json_encode($data),
            'AES-256-CBC',
            $this->encryption_key,
            OPENSSL_RAW_DATA,
            $iv
        );
        return base64_encode($iv . $encrypted);
    }
    
    private function decrypt($encrypted_data) {
        $data = base64_decode($encrypted_data);
        $iv = substr($data, 0, 16);
        $encrypted = substr($data, 16);
        $decrypted = openssl_decrypt(
            $encrypted,
            'AES-256-CBC',
            $this->encryption_key,
            OPENSSL_RAW_DATA,
            $iv
        );
        return json_decode($decrypted, true);
    }
    
    public function save_credentials($credentials) {
        $encrypted = $this->encrypt($credentials);
        $config_dir = WP_CONTACT_PATH . 'config';
        
        if (!file_exists($config_dir)) {
            wp_mkdir_p($config_dir);
            chmod($config_dir, 0755);
        }
        
        $result = file_put_contents(WP_CONTACT_CONFIG_FILE, $encrypted);
        if ($result !== false) {
            chmod(WP_CONTACT_CONFIG_FILE, 0640);
        }
        return $result !== false;
    }
    
    public function get_credentials() {
        if (!file_exists(WP_CONTACT_CONFIG_FILE)) {
            return null;
        }
        $encrypted = file_get_contents(WP_CONTACT_CONFIG_FILE);
        return $this->decrypt($encrypted);
    }
    
    // ═══════════════════════════════════════════════════════════════
    // MICROSOFT GRAPH API
    // ═══════════════════════════════════════════════════════════════
    
    private function get_access_token() {
        $creds = $this->get_credentials();
        if (!$creds) {
            return new WP_Error('no_credentials', 'Microsoft Graph credentials not configured');
        }
        
        $token_url = "https://login.microsoftonline.com/{$creds['tenant_id']}/oauth2/v2.0/token";
        
        $response = wp_remote_post($token_url, [
            'body' => [
                'client_id' => $creds['client_id'],
                'client_secret' => $creds['client_secret'],
                'scope' => 'https://graph.microsoft.com/.default',
                'grant_type' => 'client_credentials'
            ],
            'timeout' => 30
        ]);
        
        if (is_wp_error($response)) {
            return $response;
        }
        
        $body = json_decode(wp_remote_retrieve_body($response), true);
        
        if (isset($body['access_token'])) {
            return $body['access_token'];
        }
        
        return new WP_Error('token_error', $body['error_description'] ?? 'Failed to obtain access token');
    }
    
    public function send_email_via_graph($to, $subject, $html_body, $from_name = null) {
        $token = $this->get_access_token();
        if (is_wp_error($token)) {
            return $token;
        }
        
        $creds = $this->get_credentials();
        $sender_email = $creds['sender_email'] ?? get_option('admin_email');
        
        $message = [
            'message' => [
                'subject' => $subject,
                'body' => [
                    'contentType' => 'HTML',
                    'content' => $html_body
                ],
                'toRecipients' => [
                    ['emailAddress' => ['address' => $to]]
                ],
                'from' => [
                    'emailAddress' => [
                        'address' => $sender_email,
                        'name' => $from_name ?? get_bloginfo('name')
                    ]
                ]
            ],
            'saveToSentItems' => 'true'
        ];
        
        $graph_url = "https://graph.microsoft.com/v1.0/users/{$sender_email}/sendMail";
        
        $response = wp_remote_post($graph_url, [
            'headers' => [
                'Authorization' => 'Bearer ' . $token,
                'Content-Type' => 'application/json'
            ],
            'body' => json_encode($message),
            'timeout' => 30
        ]);
        
        if (is_wp_error($response)) {
            return $response;
        }
        
        $code = wp_remote_retrieve_response_code($response);
        if ($code === 202 || $code === 200) {
            return true;
        }
        
        $body = json_decode(wp_remote_retrieve_body($response), true);
        return new WP_Error('send_failed', $body['error']['message'] ?? 'Email send failed');
    }
    
    // ═══════════════════════════════════════════════════════════════
    // EMAIL TEMPLATE - Nostalgia with Understatement
    // ═══════════════════════════════════════════════════════════════
    
    private function get_email_template($data) {
        $site_name = get_bloginfo('name');
        $timestamp = current_time('F j, Y \a\t g:i a');
        
        $name = esc_html($data['name']);
        $email = esc_html($data['email']);
        $subject = esc_html($data['subject'] ?? 'No subject');
        $message = nl2br(esc_html($data['message']));
        
        return <<<HTML
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>New Message</title>
    <!--[if mso]>
    <style type="text/css">
        body, table, td {font-family: Georgia, serif !important;}
    </style>
    <![endif]-->
</head>
<body style="margin: 0; padding: 0; background-color: #f7f5f2; font-family: Georgia, 'Times New Roman', serif;">
    
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background-color: #f7f5f2;">
        <tr>
            <td align="center" style="padding: 40px 20px;">
                
                <!-- Main Container -->
                <table role="presentation" width="600" cellspacing="0" cellpadding="0" border="0" style="background-color: #fffefa; border: 1px solid #e8e4dc; max-width: 600px;">
                    
                    <!-- Header -->
                    <tr>
                        <td style="padding: 48px 48px 32px 48px; border-bottom: 1px solid #e8e4dc;">
                            <p style="margin: 0; font-size: 11px; letter-spacing: 3px; color: #9a958c; text-transform: uppercase; font-family: 'Courier New', monospace;">
                                {$site_name}
                            </p>
                            <h1 style="margin: 16px 0 0 0; font-size: 28px; font-weight: 400; color: #3d3a35; letter-spacing: -0.5px; font-family: Georgia, serif;">
                                Someone reached out.
                            </h1>
                        </td>
                    </tr>
                    
                    <!-- Metadata -->
                    <tr>
                        <td style="padding: 32px 48px 24px 48px; background-color: #fcfaf7;">
                            <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0">
                                <tr>
                                    <td width="80" style="padding-bottom: 12px; font-size: 12px; color: #9a958c; text-transform: uppercase; letter-spacing: 1px; font-family: 'Courier New', monospace; vertical-align: top;">
                                        From
                                    </td>
                                    <td style="padding-bottom: 12px; font-size: 16px; color: #3d3a35; font-family: Georgia, serif;">
                                        {$name}
                                    </td>
                                </tr>
                                <tr>
                                    <td style="padding-bottom: 12px; font-size: 12px; color: #9a958c; text-transform: uppercase; letter-spacing: 1px; font-family: 'Courier New', monospace; vertical-align: top;">
                                        Email
                                    </td>
                                    <td style="padding-bottom: 12px; font-size: 16px; color: #3d3a35; font-family: Georgia, serif;">
                                        <a href="mailto:{$email}" style="color: #6b685f; text-decoration: none; border-bottom: 1px solid #c9c4b9;">{$email}</a>
                                    </td>
                                </tr>
                                <tr>
                                    <td style="font-size: 12px; color: #9a958c; text-transform: uppercase; letter-spacing: 1px; font-family: 'Courier New', monospace; vertical-align: top;">
                                        Re
                                    </td>
                                    <td style="font-size: 16px; color: #3d3a35; font-family: Georgia, serif;">
                                        {$subject}
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>
                    
                    <!-- Divider -->
                    <tr>
                        <td style="padding: 0 48px;">
                            <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0">
                                <tr>
                                    <td style="border-bottom: 1px solid #e8e4dc;"></td>
                                </tr>
                            </table>
                        </td>
                    </tr>
                    
                    <!-- Message Body -->
                    <tr>
                        <td style="padding: 32px 48px 48px 48px;">
                            <p style="margin: 0 0 24px 0; font-size: 13px; color: #9a958c; text-transform: uppercase; letter-spacing: 2px; font-family: 'Courier New', monospace;">
                                Their words
                            </p>
                            <div style="font-size: 17px; line-height: 1.7; color: #4a4741; font-family: Georgia, serif;">
                                {$message}
                            </div>
                        </td>
                    </tr>
                    
                    <!-- Footer -->
                    <tr>
                        <td style="padding: 32px 48px; background-color: #3d3a35; border-top: 3px solid #5c584f;">
                            <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0">
                                <tr>
                                    <td>
                                        <p style="margin: 0 0 8px 0; font-size: 12px; color: #a09b92; font-family: 'Courier New', monospace; letter-spacing: 1px;">
                                            {$timestamp}
                                        </p>
                                        <p style="margin: 0; font-size: 13px; color: #7a756c; font-family: Georgia, serif; font-style: italic;">
                                            Delivered with quiet grace.
                                        </p>
                                    </td>
                                    <td align="right" style="vertical-align: bottom;">
                                        <p style="margin: 0; font-size: 10px; color: #5c584f; font-family: 'Courier New', monospace; letter-spacing: 2px;">
                                            ◆
                                        </p>
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>
                    
                </table>
                
                <!-- Sub-footer -->
                <table role="presentation" width="600" cellspacing="0" cellpadding="0" border="0" style="max-width: 600px;">
                    <tr>
                        <td style="padding: 24px 48px; text-align: center;">
                            <p style="margin: 0; font-size: 11px; color: #b0aa9f; font-family: Georgia, serif;">
                                This message arrived via the contact form at {$site_name}.<br>
                                Reply directly to correspond with {$name}.
                            </p>
                        </td>
                    </tr>
                </table>
                
            </td>
        </tr>
    </table>
    
</body>
</html>
HTML;
    }
    
    // ═══════════════════════════════════════════════════════════════
    // ADMIN SETTINGS
    // ═══════════════════════════════════════════════════════════════
    
    public function add_admin_menu() {
        add_options_page(
            'WP Contact Settings',
            'WP Contact',
            'manage_options',
            'wp-contact-settings',
            [$this, 'render_settings_page']
        );
    }
    
    public function register_settings() {
        register_setting('wp_contact_settings', 'wp_contact_options', [$this, 'sanitize_and_save_settings']);
    }
    
    public function sanitize_and_save_settings($input) {
        // Only save credentials to encrypted file, not to database
        if (!empty($input['tenant_id']) && !empty($input['client_id']) && !empty($input['client_secret'])) {
            $credentials = [
                'tenant_id' => sanitize_text_field($input['tenant_id']),
                'client_id' => sanitize_text_field($input['client_id']),
                'client_secret' => sanitize_text_field($input['client_secret']),
                'sender_email' => sanitize_email($input['sender_email'] ?? '')
            ];
            
            $this->save_credentials($credentials);
        }
        
        // Return only non-sensitive settings for database
        return [
            'form_title' => sanitize_text_field($input['form_title'] ?? ''),
            'success_message' => sanitize_textarea_field($input['success_message'] ?? ''),
            'credentials_saved' => !empty($input['tenant_id'])
        ];
    }
    
    public function render_settings_page() {
        if (!current_user_can('manage_options')) {
            return;
        }
        
        $options = get_option('wp_contact_options', []);
        $credentials = $this->get_credentials();
        $has_credentials = !empty($credentials);
        
        ?>
        <div class="wrap wp-contact-settings">
            <style>
                .wp-contact-settings {
                    max-width: 800px;
                    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
                }
                .wpc-card {
                    background: #fff;
                    border: 1px solid #e0e0e0;
                    border-radius: 8px;
                    padding: 24px;
                    margin-bottom: 24px;
                }
                .wpc-card h2 {
                    margin-top: 0;
                    padding-bottom: 16px;
                    border-bottom: 1px solid #f0f0f0;
                    font-size: 18px;
                    font-weight: 500;
                }
                .wpc-field {
                    margin-bottom: 20px;
                }
                .wpc-field label {
                    display: block;
                    font-weight: 500;
                    margin-bottom: 6px;
                    color: #333;
                }
                .wpc-field input[type="text"],
                .wpc-field input[type="email"],
                .wpc-field input[type="password"],
                .wpc-field textarea {
                    width: 100%;
                    max-width: 500px;
                    padding: 10px 12px;
                    border: 1px solid #ddd;
                    border-radius: 4px;
                    font-size: 14px;
                }
                .wpc-field .description {
                    margin-top: 6px;
                    color: #666;
                    font-size: 13px;
                }
                .wpc-status {
                    display: inline-flex;
                    align-items: center;
                    gap: 8px;
                    padding: 8px 16px;
                    border-radius: 4px;
                    font-size: 13px;
                    margin-bottom: 16px;
                }
                .wpc-status.configured {
                    background: #e8f5e9;
                    color: #2e7d32;
                }
                .wpc-status.not-configured {
                    background: #fff3e0;
                    color: #e65100;
                }
                .wpc-security-note {
                    background: #f5f5f5;
                    border-left: 4px solid #666;
                    padding: 12px 16px;
                    margin-bottom: 20px;
                    font-size: 13px;
                    color: #555;
                }
                .wpc-shortcode {
                    background: #2d2d2d;
                    color: #b5e853;
                    padding: 12px 16px;
                    border-radius: 4px;
                    font-family: 'Fira Code', 'Monaco', monospace;
                    font-size: 14px;
                }
            </style>
            
            <h1 style="margin-bottom: 24px;">WP Contact</h1>
            
            <form method="post" action="options.php">
                <?php settings_fields('wp_contact_settings'); ?>
                
                <!-- Microsoft Graph Settings -->
                <div class="wpc-card">
                    <h2>🔐 Microsoft Graph Credentials</h2>
                    
                    <div class="wpc-status <?php echo $has_credentials ? 'configured' : 'not-configured'; ?>">
                        <?php if ($has_credentials): ?>
                            <span>●</span> Credentials encrypted and stored securely
                        <?php else: ?>
                            <span>○</span> Not configured
                        <?php endif; ?>
                    </div>
                    
                    <div class="wpc-security-note">
                        <strong>Security:</strong> Credentials are encrypted using AES-256-CBC with WordPress salts and stored in a protected file (not in the database). The config file is protected by .htaccess rules.
                    </div>
                    
                    <div class="wpc-field">
                        <label for="tenant_id">Tenant ID</label>
                        <input type="text" id="tenant_id" name="wp_contact_options[tenant_id]" 
                               placeholder="<?php echo $has_credentials ? '••••••••-••••-••••-••••-••••••••••••' : 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'; ?>"
                               autocomplete="off">
                        <p class="description">Azure AD Tenant ID (leave blank to keep existing)</p>
                    </div>
                    
                    <div class="wpc-field">
                        <label for="client_id">Client ID</label>
                        <input type="text" id="client_id" name="wp_contact_options[client_id]" 
                               placeholder="<?php echo $has_credentials ? '••••••••-••••-••••-••••-••••••••••••' : 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'; ?>"
                               autocomplete="off">
                        <p class="description">Application (client) ID from Azure AD</p>
                    </div>
                    
                    <div class="wpc-field">
                        <label for="client_secret">Client Secret</label>
                        <input type="password" id="client_secret" name="wp_contact_options[client_secret]" 
                               placeholder="<?php echo $has_credentials ? '••••••••••••••••••••••••' : 'Enter client secret'; ?>"
                               autocomplete="new-password">
                        <p class="description">Client secret value (not the secret ID)</p>
                    </div>
                    
                    <div class="wpc-field">
                        <label for="sender_email">Sender Email</label>
                        <input type="email" id="sender_email" name="wp_contact_options[sender_email]" 
                               placeholder="<?php echo $has_credentials && !empty($credentials['sender_email']) ? $credentials['sender_email'] : 'noreply@yourdomain.com'; ?>"
                               autocomplete="off">
                        <p class="description">Email address to send from (must have Send.Mail permission in Azure)</p>
                    </div>
                </div>
                
                <!-- Form Settings -->
                <div class="wpc-card">
                    <h2>✉️ Form Settings</h2>
                    
                    <div class="wpc-field">
                        <label for="form_title">Form Title</label>
                        <input type="text" id="form_title" name="wp_contact_options[form_title]" 
                               value="<?php echo esc_attr($options['form_title'] ?? 'Get in touch'); ?>">
                    </div>
                    
                    <div class="wpc-field">
                        <label for="success_message">Success Message</label>
                        <textarea id="success_message" name="wp_contact_options[success_message]" rows="2"><?php echo esc_textarea($options['success_message'] ?? 'Thank you. Your message has been sent.'); ?></textarea>
                    </div>
                    
                    <div class="wpc-field">
                        <label>Recipient Email</label>
                        <input type="text" value="<?php echo esc_attr(get_option('admin_email')); ?>" disabled>
                        <p class="description">Messages are sent to the WordPress admin email (Settings → General)</p>
                    </div>
                </div>
                
                <!-- Usage -->
                <div class="wpc-card">
                    <h2>📋 Usage</h2>
                    <p>Add this shortcode to any page or post:</p>
                    <div class="wpc-shortcode">[WP_Contact]</div>
                </div>
                
                <?php submit_button('Save Settings'); ?>
            </form>
        </div>
        <?php
    }
    
    // ═══════════════════════════════════════════════════════════════
    // FRONTEND FORM
    // ═══════════════════════════════════════════════════════════════
    
    public function render_contact_form($atts) {
        $options = get_option('wp_contact_options', []);
        $title = $options['form_title'] ?? 'Get in touch';
        $nonce = wp_create_nonce('wp_contact_nonce');
        
        ob_start();
        ?>
        <div class="wp-contact-form" id="wp-contact-form">
            <style>
                .wp-contact-form {
                    --wpc-bg: #fffefa;
                    --wpc-border: #e8e4dc;
                    --wpc-text: #3d3a35;
                    --wpc-muted: #9a958c;
                    --wpc-accent: #5c584f;
                    font-family: Georgia, 'Times New Roman', serif;
                    max-width: 560px;
                    margin: 0 auto;
                }
                .wp-contact-form * {
                    box-sizing: border-box;
                }
                .wp-contact-form__inner {
                    background: var(--wpc-bg);
                    border: 1px solid var(--wpc-border);
                    padding: 48px;
                }
                .wp-contact-form__title {
                    font-size: 11px;
                    letter-spacing: 3px;
                    color: var(--wpc-muted);
                    text-transform: uppercase;
                    margin: 0 0 8px 0;
                    font-family: 'Courier New', monospace;
                }
                .wp-contact-form__heading {
                    font-size: 28px;
                    font-weight: 400;
                    color: var(--wpc-text);
                    margin: 0 0 32px 0;
                    letter-spacing: -0.5px;
                }
                .wp-contact-form__field {
                    margin-bottom: 24px;
                }
                .wp-contact-form__label {
                    display: block;
                    font-size: 12px;
                    letter-spacing: 2px;
                    color: var(--wpc-muted);
                    text-transform: uppercase;
                    margin-bottom: 8px;
                    font-family: 'Courier New', monospace;
                }
                .wp-contact-form__input,
                .wp-contact-form__textarea {
                    width: 100%;
                    padding: 14px 16px;
                    font-size: 16px;
                    font-family: Georgia, serif;
                    color: var(--wpc-text);
                    background: #fff;
                    border: 1px solid var(--wpc-border);
                    outline: none;
                    transition: border-color 0.2s ease;
                }
                .wp-contact-form__input:focus,
                .wp-contact-form__textarea:focus {
                    border-color: var(--wpc-accent);
                }
                .wp-contact-form__textarea {
                    min-height: 160px;
                    resize: vertical;
                    line-height: 1.6;
                }
                .wp-contact-form__submit {
                    display: inline-block;
                    padding: 14px 32px;
                    font-size: 12px;
                    letter-spacing: 2px;
                    text-transform: uppercase;
                    font-family: 'Courier New', monospace;
                    color: #fff;
                    background: var(--wpc-text);
                    border: none;
                    cursor: pointer;
                    transition: background 0.2s ease;
                }
                .wp-contact-form__submit:hover {
                    background: var(--wpc-accent);
                }
                .wp-contact-form__submit:disabled {
                    opacity: 0.6;
                    cursor: not-allowed;
                }
                .wp-contact-form__message {
                    padding: 16px;
                    margin-bottom: 24px;
                    font-size: 15px;
                }
                .wp-contact-form__message--success {
                    background: #f0f7f0;
                    border: 1px solid #c8e6c9;
                    color: #2e5a2e;
                }
                .wp-contact-form__message--error {
                    background: #fdf2f2;
                    border: 1px solid #f5c6c6;
                    color: #8b2525;
                }
                .wp-contact-form__footer {
                    margin-top: 32px;
                    padding-top: 24px;
                    border-top: 1px solid var(--wpc-border);
                    font-size: 13px;
                    color: var(--wpc-muted);
                    font-style: italic;
                }
                @media (max-width: 600px) {
                    .wp-contact-form__inner {
                        padding: 32px 24px;
                    }
                    .wp-contact-form__heading {
                        font-size: 24px;
                    }
                }
            </style>
            
            <div class="wp-contact-form__inner">
                <p class="wp-contact-form__title"><?php echo esc_html(get_bloginfo('name')); ?></p>
                <h2 class="wp-contact-form__heading"><?php echo esc_html($title); ?></h2>
                
                <div class="wp-contact-form__message" style="display: none;"></div>
                
                <form class="wp-contact-form__form" method="post">
                    <input type="hidden" name="wp_contact_nonce" value="<?php echo esc_attr($nonce); ?>">
                    
                    <div class="wp-contact-form__field">
                        <label class="wp-contact-form__label" for="wpc-name">Your name</label>
                        <input type="text" id="wpc-name" name="name" class="wp-contact-form__input" required>
                    </div>
                    
                    <div class="wp-contact-form__field">
                        <label class="wp-contact-form__label" for="wpc-email">Email address</label>
                        <input type="email" id="wpc-email" name="email" class="wp-contact-form__input" required>
                    </div>
                    
                    <div class="wp-contact-form__field">
                        <label class="wp-contact-form__label" for="wpc-subject">Subject</label>
                        <input type="text" id="wpc-subject" name="subject" class="wp-contact-form__input">
                    </div>
                    
                    <div class="wp-contact-form__field">
                        <label class="wp-contact-form__label" for="wpc-message">Your message</label>
                        <textarea id="wpc-message" name="message" class="wp-contact-form__textarea" required></textarea>
                    </div>
                    
                    <button type="submit" class="wp-contact-form__submit">Send message</button>
                </form>
                
                <p class="wp-contact-form__footer">
                    Every message finds its way.
                </p>
            </div>
        </div>
        
        <script>
        (function() {
            const form = document.querySelector('.wp-contact-form__form');
            const messageEl = document.querySelector('.wp-contact-form__message');
            const submitBtn = form.querySelector('.wp-contact-form__submit');
            
            form.addEventListener('submit', async function(e) {
                e.preventDefault();
                
                submitBtn.disabled = true;
                submitBtn.textContent = 'Sending...';
                messageEl.style.display = 'none';
                
                const formData = new FormData(form);
                formData.append('action', 'wp_contact_submit');
                
                try {
                    const response = await fetch('<?php echo admin_url('admin-ajax.php'); ?>', {
                        method: 'POST',
                        body: formData
                    });
                    
                    const data = await response.json();
                    
                    messageEl.className = 'wp-contact-form__message';
                    messageEl.classList.add(data.success ? 'wp-contact-form__message--success' : 'wp-contact-form__message--error');
                    messageEl.textContent = data.data.message;
                    messageEl.style.display = 'block';
                    
                    if (data.success) {
                        form.reset();
                    }
                } catch (error) {
                    messageEl.className = 'wp-contact-form__message wp-contact-form__message--error';
                    messageEl.textContent = 'Something went wrong. Please try again.';
                    messageEl.style.display = 'block';
                }
                
                submitBtn.disabled = false;
                submitBtn.textContent = 'Send message';
            });
        })();
        </script>
        <?php
        return ob_get_clean();
    }
    
    // ═══════════════════════════════════════════════════════════════
    // FORM SUBMISSION HANDLER
    // ═══════════════════════════════════════════════════════════════
    
    public function handle_form_submission() {
        // Verify nonce
        if (!wp_verify_nonce($_POST['wp_contact_nonce'] ?? '', 'wp_contact_nonce')) {
            wp_send_json_error(['message' => 'Security check failed.']);
        }
        
        // Rate limiting (simple implementation)
        $ip = $_SERVER['REMOTE_ADDR'];
        $transient_key = 'wp_contact_' . md5($ip);
        $attempts = get_transient($transient_key) ?: 0;
        
        if ($attempts >= 5) {
            wp_send_json_error(['message' => 'Please wait a moment before sending another message.']);
        }
        
        set_transient($transient_key, $attempts + 1, 300); // 5 minute window
        
        // Validate fields
        $name = sanitize_text_field($_POST['name'] ?? '');
        $email = sanitize_email($_POST['email'] ?? '');
        $subject = sanitize_text_field($_POST['subject'] ?? 'Contact Form Message');
        $message = sanitize_textarea_field($_POST['message'] ?? '');
        
        if (empty($name) || empty($email) || empty($message)) {
            wp_send_json_error(['message' => 'Please fill in all required fields.']);
        }
        
        if (!is_email($email)) {
            wp_send_json_error(['message' => 'Please enter a valid email address.']);
        }
        
        // Honeypot check (if field exists and is filled, it's a bot)
        if (!empty($_POST['website'])) {
            wp_send_json_error(['message' => 'Submission blocked.']);
        }
        
        // Prepare email
        $admin_email = get_option('admin_email');
        $email_subject = sprintf('[%s] %s', get_bloginfo('name'), $subject);
        
        $html_body = $this->get_email_template([
            'name' => $name,
            'email' => $email,
            'subject' => $subject,
            'message' => $message
        ]);
        
        // Send via Microsoft Graph
        $result = $this->send_email_via_graph($admin_email, $email_subject, $html_body, $name);
        
        if (is_wp_error($result)) {
            // Log the error
            error_log('WP Contact Form Error: ' . $result->get_error_message());
            
            // Try fallback to wp_mail
            $headers = [
                'Content-Type: text/html; charset=UTF-8',
                'Reply-To: ' . $name . ' <' . $email . '>'
            ];
            
            $fallback = wp_mail($admin_email, $email_subject, $html_body, $headers);
            
            if (!$fallback) {
                wp_send_json_error(['message' => 'Unable to send message. Please try again later.']);
            }
        }
        
        $options = get_option('wp_contact_options', []);
        $success_message = $options['success_message'] ?? 'Thank you. Your message has been sent.';
        
        wp_send_json_success(['message' => $success_message]);
    }
    
    public function enqueue_frontend_assets() {
        // Assets are inline for simplicity
    }
    
    public function enqueue_admin_assets($hook) {
        if ($hook !== 'settings_page_wp-contact-settings') {
            return;
        }
        // Admin styles are inline
    }
}

// Initialize
WP_Contact_Form::instance();
