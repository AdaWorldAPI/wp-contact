# WP Contact

A WordPress contact form plugin with Microsoft Graph email delivery and encrypted credential storage.

## Features

- **Encrypted Credentials** — Client ID, Secret, and Tenant ID are encrypted with AES-256-CBC using WordPress salts
- **Microsoft Graph API** — Sends emails via Microsoft Graph (more reliable than SMTP)
- **Nostalgic Design** — Clean, understated email templates with a timeless aesthetic
- **Security First** — Config files protected by .htaccess, rate limiting, CSRF protection
- **Fallback** — Automatically falls back to wp_mail() if Graph API fails

## Installation

1. Upload the `wp-contact` folder to `/wp-content/plugins/`
2. Activate the plugin in WordPress admin
3. Go to **Settings → WP Contact**
4. Enter your Microsoft Graph credentials

## Azure AD Setup

### 1. Register an Application

1. Go to [Azure Portal](https://portal.azure.com) → Azure Active Directory
2. Navigate to **App registrations** → **New registration**
3. Name: `WordPress Contact Form` (or similar)
4. Supported account types: Single tenant
5. Click **Register**

### 2. Get Credentials

From the app overview page, copy:
- **Application (client) ID** → Client ID
- **Directory (tenant) ID** → Tenant ID

### 3. Create Client Secret

1. Go to **Certificates & secrets**
2. Click **New client secret**
3. Add a description, select expiry (24 months recommended)
4. **Copy the Value immediately** (it won't be shown again)

### 4. Configure API Permissions

1. Go to **API permissions**
2. Click **Add a permission**
3. Select **Microsoft Graph** → **Application permissions**
4. Add: `Mail.Send`
5. Click **Grant admin consent** (requires admin)

### 5. Configure Sender Mailbox (Important!)

The sender email must be a valid mailbox in your Microsoft 365 tenant:
- Can be a shared mailbox (no license needed)
- Can be a licensed user mailbox
- Cannot be a distribution group or alias

## File Permissions

The plugin sets these permissions automatically:

```
config/                 755 (drwxr-xr-x)
config/.htaccess        644 (-rw-r--r--)
config/index.php        644 (-rw-r--r--)
config/credentials.enc  640 (-rw-r-----)
```

## Usage

Add the shortcode to any page:

```
[wp_contact]
```

## Security Notes

1. **Credentials are NOT stored in the database** — They're encrypted and saved to a protected file
2. **Encryption key is derived from WordPress salts** — Unique per installation
3. **.htaccess protection** — Direct access to config directory is blocked
4. **Rate limiting** — 5 submissions per IP per 5 minutes
5. **CSRF protection** — WordPress nonces on all forms

## Email Template

The email template features:
- Warm, muted color palette (#fffefa, #3d3a35, #9a958c)
- Georgia and Courier New fonts
- Clean metadata display
- Dark footer with timestamp
- Mobile responsive

## Troubleshooting

### "Failed to obtain access token"
- Verify Tenant ID, Client ID, and Client Secret
- Check that admin consent was granted

### "Email send failed"
- Verify sender email has a mailbox in the tenant
- Check Mail.Send permission was granted
- Ensure admin consent was clicked

### Testing
Use the Azure AD application page to verify permissions are correct.

## License

MIT License

---

*Delivered with quiet grace.*
