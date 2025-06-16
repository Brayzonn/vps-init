# VPS Initialization with Enhanced Logging

An extensible shell script designed to streamline the initial setup of fresh Ubuntu or Debian VPS instances. Ideal for developers who need a reliable, repeatable baseline configuration for app hosting.

## Quick Start (5 Minutes)

**Just want to get a server running fast?** Follow these steps:

### Prerequisites
- **SSH Access**: Terminal access to your VPS
- **User Account**: Non-root user with sudo privileges  
- **Server**: Fresh Ubuntu 18.04+ or Debian 10+ VPS
- **Local Machine**: Terminal/command line access
- **Domain**: Domain name with DNS A record pointing to your server IP

### 1. Run the Setup Script

**Option A: Copy from Local Machine (Recommended)**
```bash
# Copy the initialization script from your local machine to your server's home directory
# Usage: run this from the directory containing init.sh
scp init.sh user@YOUR_SERVER_IP:/home/user/init.sh

# SSH into your server
ssh user@YOUR_SERVER_IP

# Run the script
chmod +x init.sh
./init.sh
```

**Option B: From GitHub Repository**
```bash
# On your server
curl -sSL https://raw.githubusercontent.com/yourusername/yourrepo/main/init.sh | bash
```

**Option C: Copy Script Content Directly**
```bash
# On your server, create the script file
nano init.sh
# Paste the script content, save and exit (Ctrl+X, Y, Enter)
chmod +x init.sh
./init.sh
```

☕ *Grab coffee - this takes 7-15 minutes*

**What this does**: Installs Node.js, PM2, Nginx, configures security (firewall, fail2ban, SSH keys), sets up automated backups and monitoring.

### 2. Add SSL Certificate  
```bash
sudo certbot --nginx -d yourdomain.com
```
*Enables HTTPS for your domain*

**Note**: Your domain's DNS must be pointing to your server IP before running this command.

### 3. Deploy Your App

**For Server Apps (Node.js APIs):**
```bash
git clone https://github.com/yourusername/your-app.git
cd your-app
npm ci
npm run build  # if TypeScript
pm2 start app.js --name "your-app"
pm2 save
```

**For Client Apps (React/Vue/Angular):**
```bash
git clone https://github.com/yourusername/your-app.git
cd your-app
npm ci
npm run build
sudo cp -r dist/* /var/www/html/          # or build/* depending on your setup
sudo systemctl reload nginx              
```

**For Full-Stack Apps:**
```bash
git clone https://github.com/yourusername/your-app.git
cd your-app

# Deploy server first
cd server
npm ci
npm run build  # if TypeScript
pm2 start app.js --name "your-app-api"

# Deploy client
cd ../client
npm ci
npm run build
sudo cp -r dist/* /var/www/html/
sudo systemctl reload nginx
pm2 save
```
*Your app is now running with process management*

### 4. Done! 
Your app is now running at `https://yourdomain.com`

**Quick verification**:
```bash
pm2 status                    # Check your app is running
sudo ufw status              # Verify firewall is active
sudo fail2ban-client status  # Check intrusion prevention
```

---

## Table of Contents

- [Features](#features)
- [What Gets Installed](#what-gets-installed)
- [Function Documentation](#function-documentation)
- [Code Flow](#code-flow)
- [Usage](#usage)
- [Configuration](#configuration)
- [Logging](#logging)
- [Post-Installation Steps](#post-installation-steps)
- [Troubleshooting](#troubleshooting)

## Features

- **Security First**: UFW firewall, Fail2ban intrusion prevention, SSH key enforcement
- **Comprehensive Logging**: Structured logging with timestamps and color coding
- **Automated Updates**: Unattended security updates and system maintenance
- **Modern Stack**: Node.js 20.x LTS, PM2 process manager, Nginx web server
- **Backup System**: Automated daily/weekly/monthly backups with retention policies
- **Monitoring**: Log analysis with Logwatch and disk space monitoring
- **Production Ready**: SSL certificate support via Let's Encrypt/Certbot

## What Gets Installed

### Core Components
| Component | Version | Purpose |
|-----------|---------|---------|
| **Node.js** | 20.x LTS | JavaScript runtime environment |
| **npm** | Latest | Node.js package manager |
| **PM2** | Latest | Process manager for Node.js applications |
| **Nginx** | Latest | High-performance web server and reverse proxy |
| **Certbot** | Latest | Let's Encrypt SSL certificate automation |
| **UFW** | System | Uncomplicated Firewall for network security |
| **Fail2ban** | Latest | Intrusion prevention system |

### Security & Monitoring Tools
- **Logwatch**: Daily log analysis and reporting
- **Unattended Upgrades**: Automatic security updates
- **Custom Backup System**: Automated file and configuration backups
- **Disk Space Monitoring**: Automated alerts for disk usage

### System Utilities
- Essential development tools: `curl`, `wget`, `git`, `unzip`
- Security tools: `ca-certificates`, `gnupg`
- System utilities: `software-properties-common`, `lsb-release`

## Function Documentation

### 🔧 Configuration & Setup Functions

#### **`setup_logging()`**
**Purpose**: Initializes the comprehensive logging system with timestamped entries.  
**Importance**: Creates audit trails and debugging information for all script operations.  
**Creates**: Log directory structure and formatted log files with system information headers.

#### **`log_info()`, `log_warn()`, `log_error()`**
**Purpose**: Standardized logging functions with color coding and timestamps.  
**Importance**: Provides consistent, readable output and maintains permanent records of all operations.  
**Features**: Color-coded terminal output, timestamped file logging, dual logging to specific and general logs.

#### **`log_command()`**
**Purpose**: Executes system commands while capturing and logging all output.  
**Importance**: Critical for debugging - shows exactly which commands succeeded or failed and why.  
**Features**: Real-time output display, complete command logging, error capture and reporting.

### System Validation Functions

#### **`check_root()`**
**Purpose**: Security check to prevent script execution as root user.  
**Importance**: Prevents permission issues and follows security best practices.  
**Security**: Reduces risk of system damage and ensures proper user privilege separation.

#### **`check_os()`**
**Purpose**: Validates operating system compatibility (Ubuntu/Debian only).  
**Importance**: Ensures package manager commands and system paths will work correctly.  
**Compatibility**: Reads `/etc/os-release` to verify supported distributions.

### System Foundation Functions

#### **`update_system()`**
**Purpose**: Updates package repositories, upgrades system packages, installs essential tools.  
**Importance**: **Foundation step** - ensures system currency and provides required dependencies.  
**Key Actions**: 
- Updates package lists (`apt-get update`)
- Upgrades installed packages (`apt-get upgrade`)
- Installs core tools including UFW firewall

#### **`install_nodejs()`**
**Purpose**: Installs Node.js 20.x LTS and configures npm with global package directory.  
**Importance**: **Core runtime** - Required for modern web applications and PM2 process manager.  
**Configuration**: Sets up `~/.npm-global` directory and updates `PATH` for global npm packages.

#### **`install_pm2()`**
**Purpose**: Installs PM2 process manager and configures automatic startup on system boot.  
**Importance**: **Process management** - Ensures applications stay running, handles crashes, enables zero-downtime deployments.  
**Features**: System service integration, automatic process resurrection, startup script generation.

#### **`install_nginx()`**
**Purpose**: Installs Nginx web server, resolves conflicts with Apache, configures firewall rules.  
**Importance**: **Web infrastructure** - Handles HTTP/HTTPS traffic, SSL termination, reverse proxy for Node.js apps.  
**Smart Features**: Detects and stops conflicting Apache installations, checks port 80 availability.

#### **`install_certbot()`**
**Purpose**: Installs Let's Encrypt SSL certificate management tools.  
**Importance**: **SSL/TLS encryption** - Essential for production websites requiring HTTPS.  
**Integration**: Nginx plugin support for automated certificate installation and renewal.

### Security & Hardening Functions

#### **`setup_firewall()`**
**Purpose**: Configures UFW firewall with restrictive default policies.  
**Importance**: **Network security perimeter** - Blocks unauthorized access while allowing essential services.  
**Configuration**: 
- Denies all incoming connections by default
- Allows SSH (port 22) and HTTP/HTTPS (ports 80/443)
- Enables automatic firewall activation

#### **`cleanup_unwanted_services()`**
**Purpose**: Intelligently scans for and removes unnecessary services, particularly mail servers.  
**Importance**: **Attack surface reduction** - Eliminates potential security vulnerabilities from unused services.  
**Smart Detection**: 
- Identifies services by port analysis
- Preserves essential system services (SSH, DNS, web)
- Removes common unnecessary services (mail servers, POP3, IMAP)

#### **`remove_mail_service()`**
**Purpose**: Safely removes various mail server packages (exim4, postfix, sendmail).  
**Importance**: **Surgical service removal** - Handles different mail server types appropriately.  
**Safety**: Uses proper systemctl commands and package removal with error handling.

#### **`install_fail2ban()`**
**Purpose**: Installs and configures intrusion prevention system.  
**Importance**: **Active defense** - Automatically bans IP addresses after failed login attempts.  
**Protection**: 
- SSH brute force protection
- Nginx authentication failure protection
- Configurable ban times and retry limits

#### **`setup_ssh_key_auth()`**
**Purpose**: Enforces SSH key-only authentication, disables password login.  
**Importance**: **Authentication hardening** - Eliminates brute force password attacks.  
**Safety Features**: 
- Verifies SSH keys exist before disabling passwords
- Creates configuration backups
- Tests SSH configuration before applying changes

### Automation & Monitoring Functions

#### **`setup_auto_updates()`**
**Purpose**: Configures automatic security updates via unattended-upgrades.  
**Importance**: **Maintenance automation** - Keeps system secure without manual intervention.  
**Configuration**: Daily update checks, automatic security patch installation, email notifications.

#### **`setup_log_monitoring()`**
**Purpose**: Installs Logwatch for daily log analysis and sets up disk space monitoring.  
**Importance**: **System observability** - Early warning system for security events and capacity issues.  
**Features**: 
- Daily log analysis reports
- Disk usage monitoring with configurable thresholds
- Automated alerting via system logger

#### **`setup_backup_system()`**
**Purpose**: Creates comprehensive automated backup system with intelligent retention.  
**Importance**: **Disaster recovery** - Protects against data loss and enables quick restoration.  
**Backup Strategy**: 
- Daily backups (7-day retention)
- Weekly backups (28-day retention)
- Monthly backups (90-day retention)
- Automated cleanup of old backups

#### **`setup_nginx_config()`**
**Purpose**: Configures Nginx with basic server block and example Node.js proxy configuration.  
**Importance**: **Web server foundation** - Provides base configuration for hosting applications.  
**Features**: Configuration backup, syntax testing, example reverse proxy setup for Node.js apps.

### Maintenance Functions

#### **`cleanup()`**
**Purpose**: Removes unnecessary packages and cleans package cache.  
**Importance**: **System optimization** - Keeps system lean and frees disk space.  
**Actions**: Runs `apt-get autoremove` and `apt-get autoclean` to clean up unused packages.

#### **`cleanup_logs()`**
**Purpose**: Implements log rotation to prevent disk space exhaustion.  
**Importance**: **Log management** - Prevents script logs from consuming all available disk space.  
**Strategy**: Keeps only the 10 most recent setup logs and trims general log when it exceeds 1MB.

### Utility Functions

#### **`show_log_summary()`**
**Purpose**: Displays comprehensive summary of log locations and useful commands.  
**Importance**: **User guidance** - Helps administrators review and troubleshoot the setup process.  
**Information**: Log file paths, review commands, and monitoring shortcuts.

#### **`handle_error()`**
**Purpose**: Global error handler that captures script failures and provides diagnostic information.  
**Importance**: **Debugging support** - When script fails, provides clear guidance on where to find details.  
**Integration**: Works with `trap handle_error ERR` to catch all script failures.

## Code Flow

### Execution Sequence

The script follows a carefully designed sequence to ensure dependencies are met and security is maintained:

```
INITIALIZATION PHASE
├── setup_logging()          # Initialize logging system
├── check_root()             # Verify non-root execution
└── check_os()               # Confirm Ubuntu/Debian compatibility

FOUNDATION PHASE  
├── update_system()          # Update packages, install UFW
├── install_nodejs()         # Install Node.js runtime
├── install_pm2()            # Install process manager
├── install_nginx()          # Install web server
├── cleanup_unwanted_services()  # Remove unnecessary services
└── install_certbot()        # Install SSL tools

SECURITY PHASE
├── setup_firewall()         # Configure network security
├── setup_nginx_config()     # Configure web server
├── install_fail2ban()       # Setup intrusion prevention
├── setup_ssh_key_auth()     # Harden SSH authentication
├── setup_auto_updates()     # Enable automatic updates
├── setup_log_monitoring()   # Setup log analysis
└── setup_backup_system()    # Configure backup automation

FINALIZATION PHASE
├── cleanup()                # Clean system packages
├── cleanup_logs()           # Rotate script logs
└── show_log_summary()       # Display completion summary
```

### Dependency Chain Logic

**Critical Dependencies:**
1. **System Foundation** → Package updates and essential tools must be installed first
2. **Node.js** → Required before PM2 installation  
3. **Nginx** → Should be running before security hardening
4. **UFW** → Must be installed before firewall configuration

**Security Philosophy:**
- **Defense in Depth**: Multiple security layers (firewall + fail2ban + SSH keys)
- **Fail Safe**: Script continues with warnings for optional security features
- **Audit Trail**: Every action is logged for security compliance

## Usage

### Basic Usage
```bash
# Standard installation
./init.sh
```

### Advanced Usage
```bash
# Run with custom logging
LOG_DIR="/custom/log/path" ./init.sh

# View real-time progress
tail -f ~/logs/vps-setup-*.log
```

### Environment Variables
| Variable | Default | Description |
|----------|---------|-------------|
| `LOG_DIR` | `$HOME/logs` | Directory for log files |
| `DEBIAN_FRONTEND` | `noninteractive` | Prevents package installation prompts |

## Configuration

### SSH Key Setup (Required for SSH Hardening)
```bash
# On your local machine
ssh-keygen -t rsa -b 4096 -C "your_email@example.com"
ssh-copy-id username@your-server-ip

# Test key authentication before running script
ssh -o PreferredAuthentications=publickey username@your-server-ip
```

### Firewall Configuration
The script configures UFW with these default rules:
- **Allow**: SSH (port 22), HTTP (port 80), HTTPS (port 443)
- **Deny**: All other incoming connections
- **Allow**: All outgoing connections

### Fail2ban Configuration
Default protection includes:
- **SSH**: 3 failed attempts = 1 hour ban
- **Nginx**: Protection against authentication failures and suspicious requests
- **Customizable**: Edit `/etc/fail2ban/jail.local` after installation

## Logging

### Log Files Structure
```
~/logs/
├── vps-setup-YYYYMMDD_HHMMSS.log  # Individual setup session logs
├── deployments.log                 # Aggregated log of all operations
└── (automatic rotation of old setup logs)
```

### Log Levels
- **[INFO]**: Normal operations and successful completions
- **[WARN]**: Non-critical issues that don't stop execution  
- **[ERROR]**: Critical failures that halt script execution

### Log Review Commands
```bash
# View latest setup log
cat ~/logs/vps-setup-*.log | tail -1

# Monitor real-time activity
tail -f ~/logs/deployments.log

# Search for errors
grep ERROR ~/logs/deployments.log

# View setup summary
ls -la ~/logs/vps-setup-*.log
```

## Post-Installation Steps

### 1. SSL Certificate Setup
```bash
# Install SSL certificate for your domain
sudo certbot --nginx -d yourdomain.com
```

### 2. Deploy Your Application
```bash
# Clone your application
git clone https://github.com/yourusername/your-app.git
cd your-app

# Install dependencies
npm ci

# Build if needed (TypeScript projects, React/Vue/Angular apps)
npm run build

# For API projects: Start server with PM2
pm2 start app.js --name "your-app"
pm2 save

# For client projects: Deploy built files to nginx
sudo cp -r dist/* /var/www/html/          # React/Angular
# OR
sudo cp -r build/* /var/www/html/         # Some React setups
sudo systemctl reload nginx

# For full-stack: Deploy both server and client components

# Note: Future releases will include automated webhook deployment that handles these steps automatically on git push.
```

### 3. Configure Nginx for Your App
```bash
# Edit Nginx configuration
sudo nano /etc/nginx/sites-available/default

# Add proxy configuration for your Node.js app
# location /api {
#     proxy_pass http://localhost:3000;
#     # ... proxy headers
# }

# Test and reload
sudo nginx -t
sudo systemctl reload nginx
```

### 4. Verify Security Setup
```bash
# Check firewall status
sudo ufw status verbose

# Check fail2ban status  
sudo fail2ban-client status

# Verify SSH key authentication
ssh -o PreferredAuthentications=publickey username@your-server-ip

# Check automated backups
ls -la /opt/backups/
```

## Troubleshooting

### Common Issues

**Script fails with "permission denied"**
```bash
# Ensure user has sudo privileges
sudo -v

# Check if user is in sudo group
groups $USER
```

**Nginx fails to start**
```bash
# Check what's using port 80
sudo netstat -tulpn | grep :80

# Check nginx logs
sudo journalctl -u nginx
```

**SSH key authentication setup fails**
```bash
# Verify SSH keys exist
ls -la ~/.ssh/authorized_keys

# Check SSH key permissions
chmod 600 ~/.ssh/authorized_keys
chmod 700 ~/.ssh
```

**UFW command not found**
```bash
# Install UFW manually
sudo apt-get update
sudo apt-get install -y ufw
```

### Log Analysis
```bash
# Check for script errors
grep ERROR ~/logs/vps-setup-*.log

# Review system logs during setup time
sudo journalctl --since "1 hour ago"

# Check specific service status
systemctl status nginx
systemctl status fail2ban
systemctl status unattended-upgrades
```

### Recovery Commands
```bash
# Restore SSH configuration if locked out
sudo cp /etc/ssh/sshd_config.backup /etc/ssh/sshd_config
sudo systemctl restart sshd

# Reset firewall if needed
sudo ufw --force reset

# Restore nginx configuration
sudo cp /etc/nginx/nginx.conf.backup /etc/nginx/nginx.conf
sudo systemctl restart nginx
```

## Contributing

We welcome contributions! Please follow these guidelines:

### Development Setup
1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Test your changes on a fresh VPS
4. Commit your changes: `git commit -m 'Add amazing feature'`
5. Push to the branch: `git push origin feature/amazing-feature`
6. Open a Pull Request

### Testing Guidelines
- Test on Ubuntu 20.04+ and Debian 11+
- Verify idempotent behavior (safe to run multiple times)
- Check logging output for clarity and completeness
- Ensure security functions work correctly

### Code Style
- Use consistent bash scripting practices
- Add comprehensive logging for new functions
- Follow existing error handling patterns
- Update documentation for new features

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Node.js](https://nodejs.org/) for the JavaScript runtime
- [PM2](https://pm2.keymetrics.io/) for process management
- [Nginx](https://nginx.org/) for web server capabilities
- [Let's Encrypt](https://letsencrypt.org/) for free SSL certificates
- [Fail2ban](https://www.fail2ban.org/) for intrusion prevention
- [Ubuntu](https://ubuntu.com/) and [Debian](https://www.debian.org/) communities

---

**Made with love for the DevOps community**