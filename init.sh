#!/bin/bash
## VPS Initialization 

#######################################
# CONFIGURATION
#######################################
set -euo pipefail  

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' 


LOG_DIR="$HOME/logs"
LOG_FILE="$LOG_DIR/vps-setup-$(date +%Y%m%d_%H%M%S).log"
GENERAL_LOG="$LOG_DIR/deployments.log"

#######################################
# LOGGING SETUP
#######################################
setup_logging() {
    mkdir -p "$LOG_DIR"
    
    cat > "$LOG_FILE" <<EOF
    =====================================
    VPS Setup Script Log
    =====================================
    Date: $(date)
    User: $(whoami)
    Host: $(hostname)
    =====================================

EOF

    log_info "Logging to: $LOG_FILE"
}

log_info() {
    local message="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    echo -e "${GREEN}[INFO]${NC} $message"
    
    echo "[$timestamp] [INFO] $message" >> "$LOG_FILE"
    echo "[$timestamp] [INFO] $message" >> "$GENERAL_LOG"
}

log_warn() {
    local message="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    echo -e "${YELLOW}[WARN]${NC} $message"
    echo "[$timestamp] [WARN] $message" >> "$LOG_FILE"
    echo "[$timestamp] [WARN] $message" >> "$GENERAL_LOG"
}

log_error() {
    local message="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    echo -e "${RED}[ERROR]${NC} $message"
    echo "[$timestamp] [ERROR] $message" >> "$LOG_FILE"
    echo "[$timestamp] [ERROR] $message" >> "$GENERAL_LOG"
}

log_command() {
    local command="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    log_info "Executing: $command"
    
    if eval "$command" 2>&1 | tee -a "$LOG_FILE"; then
        log_info "Command completed successfully: $command"
        return 0
    else
        log_error "Command failed: $command"
        return 1
    fi
}

#######################################
# SYSTEM CHECKS
#######################################
check_root() {
    if [[ $EUID -eq 0 ]]; then
        log_error "This script should not be run as root"
        exit 1
    fi
}

check_os() {
    if [[ ! -f /etc/os-release ]]; then
        log_error "Cannot determine OS. This script supports Ubuntu/Debian."
        exit 1
    fi
    
    . /etc/os-release
    if [[ "$ID" != "ubuntu" && "$ID" != "debian" ]]; then
        log_error "This script only supports Ubuntu/Debian. Detected: $ID"
        exit 1
    fi
    
    log_info "Detected OS: $PRETTY_NAME"
}

#######################################
# SYSTEM UPDATES
#######################################
update_system() {
    log_info "Updating system packages..."

     export DEBIAN_FRONTEND=noninteractive

     export NEEDRESTART_MODE=a
    
    echo "postfix postfix/main_mailer_type select No configuration" | sudo debconf-set-selections
    echo "postfix postfix/mailname string localhost" | sudo debconf-set-selections

    log_command "sudo apt-get update"
    log_command "sudo apt-get upgrade -y"
    log_command "sudo apt-get install -y curl wget git unzip software-properties-common ca-certificates gnupg lsb-release ufw"
}

#######################################
# PACKAGE INSTALLS  
#######################################
install_nodejs() {
    log_info "Installing Node.js..."
    
    log_command "curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -"
    log_command "sudo apt-get install -y nodejs"
    
    node_version=$(node --version)
    npm_version=$(npm --version)
    log_info "Node.js installed: $node_version"
    log_info "npm installed: $npm_version"
    
    mkdir -p ~/.npm-global
    npm config set prefix '~/.npm-global'
    
    if ! grep -q 'npm-global/bin' ~/.bashrc; then
        echo 'export PATH=~/.npm-global/bin:$PATH' >> ~/.bashrc
        export PATH=~/.npm-global/bin:$PATH
        log_info "Added npm global path to .bashrc"
    fi
}

install_pm2() {
    log_info "Installing PM2..."
    
    log_command "npm install -g pm2"
    
    pm2_startup_cmd=$(pm2 startup 2>/dev/null | grep "sudo env" || true)
    if [[ -n "$pm2_startup_cmd" ]]; then
        eval "$pm2_startup_cmd"
        log_info "PM2 startup configuration completed"
    else
        log_warn "PM2 startup configuration may have failed"
    fi
    
    log_info "PM2 installed successfully"
}

install_nginx() {
    log_info "Installing Nginx..."
    
    log_info "Checking for conflicting web servers..."
    if systemctl is-active --quiet apache2; then
        log_info "Apache2 is running, stopping it..."
        log_command "sudo systemctl stop apache2"
        log_command "sudo systemctl disable apache2"
        log_info "Apache2 stopped and disabled"
    else
        log_info "No Apache2 service found running"
    fi
    
    if sudo lsof -i :80 >/dev/null 2>&1; then
        log_warn "Something is still using port 80:"
        sudo lsof -i :80 | tee -a "$LOG_FILE"
    fi
    
    log_command "sudo apt-get install -y nginx"
    log_command "sudo systemctl start nginx"
    log_command "sudo systemctl enable nginx"
    
    if command -v ufw &> /dev/null && sudo ufw allow 'Nginx Full'; then
        log_info "UFW rule added for Nginx"
    else
        log_warn "UFW not available or rule addition failed"
    fi
    
    if systemctl is-active --quiet nginx; then
        log_info "Nginx installed and started successfully"
        nginx_version=$(nginx -v 2>&1)
        log_info "Nginx version: $nginx_version"
    else
        log_error "Nginx failed to start, checking status..."
        systemctl status nginx.service | tee -a "$LOG_FILE"
    fi
}

install_certbot() {
    log_info "Installing Certbot..."
    
    log_command "sudo apt-get install -y certbot python3-certbot-nginx"
    
    log_info "Certbot installed. Run 'sudo certbot --nginx -d yourdomain.com' to get SSL certificate"
}

#######################################
# SYSTEM CONFIGURATION & SECURITY
#######################################
setup_firewall() {
    log_info "Setting up basic firewall..."
    
    if command -v ufw &> /dev/null; then
        log_command "sudo ufw --force reset"
        log_command "sudo ufw default deny incoming"
        log_command "sudo ufw default allow outgoing"
        log_command "sudo ufw allow ssh"
        log_command "sudo ufw allow 'Nginx Full'"
        log_command "sudo ufw --force enable"
        log_info "UFW firewall configured"
    else
        log_warn "UFW not available, skipping firewall setup"
    fi
}

cleanup_unwanted_services() {
    log_info "Scanning for unnecessary services..."

    local expected_services=(
        "22"     # SSH
        "53"     # DNS (systemd-resolved)
        "80"     # HTTP (nginx)
        "443"    # HTTPS (nginx, when SSL added)
    )
    
    local listening_services=$(sudo netstat -tulpn | grep LISTEN)
    
    log_info "Analyzing listening services..."
    echo "$listening_services" | tee -a "$LOG_FILE"
    
    while IFS= read -r line; do
        local port=$(echo "$line" | awk '{print $4}' | sed 's/.*://' | grep -o '[0-9]*')
        local process=$(echo "$line" | awk '{print $7}' | cut -d'/' -f2 | cut -d':' -f1)
        local bind_address=$(echo "$line" | awk '{print $4}' | cut -d':' -f1)
        
        [[ -z "$port" || -z "$process" ]] && continue
        
        if [[ " ${expected_services[@]} " =~ " ${port} " ]]; then
            log_info "Port $port ($process): Expected service - keeping"
        elif [[ "$port" == "53" && ("$bind_address" == "127.0.0.53" || "$bind_address" == "000.0.0.53") ]]; then
            log_info "Port $port ($process): System DNS resolver - keeping"
        else
            case "$port" in
                25|587|465) 
                    log_warn "Found mail server on port $port ($process) - removing..."
                    remove_mail_service "$process"
                    ;;
                110|995)   
                    log_warn "Found POP3 service on port $port ($process) - not needed for web server"
                    ;;
                143|993)     
                    log_warn "Found IMAP service on port $port ($process) - not needed for web server"
                    ;;
                *)
                    log_warn "Unexpected service on port $port ($process) - please review if needed"
                    ;;
            esac
        fi
    done <<< "$listening_services"
    
    log_info "Service cleanup completed"
}

remove_mail_service() {
    local service_name="$1"
    
    case "$service_name" in
        exim4*)
            log_info "Removing exim4 mail server..."
            log_command "sudo systemctl stop exim4" || log_warn "Failed to stop exim4 service"
            log_command "sudo systemctl disable exim4" || log_warn "Failed to disable exim4 service"
            log_command "sudo apt-get remove --purge -y exim4*" || log_warn "Failed to remove exim4 packages"
            ;;
        postfix*)
            log_info "Removing postfix mail server..."
            log_command "sudo systemctl stop postfix" || log_warn "Failed to stop postfix service"
            log_command "sudo systemctl disable postfix" || log_warn "Failed to disable postfix service"
            log_command "sudo apt-get remove --purge -y postfix*" || log_warn "Failed to remove postfix packages"
            ;;
        sendmail*)
            log_info "Removing sendmail..."
            log_command "sudo systemctl stop sendmail" || log_warn "Failed to stop sendmail service"
            log_command "sudo systemctl disable sendmail" || log_warn "Failed to disable sendmail service"
            log_command "sudo apt-get remove --purge -y sendmail*" || log_warn "Failed to remove sendmail packages"
            ;;
        *)
            log_warn "Unknown mail service: $service_name - manual review needed"
            ;;
    esac
}

install_fail2ban() {
    log_info "Installing and configuring Fail2Ban..."
    
    log_command "sudo apt-get install -y fail2ban"
    
    sudo tee /etc/fail2ban/jail.local > /dev/null <<EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
ignoreip = 127.0.0.1/8 ::1

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600

[nginx-http-auth]
enabled = true
filter = nginx-http-auth
port = http,https
logpath = /var/log/nginx/error.log

[nginx-noscript]
enabled = true
port = http,https
filter = nginx-noscript
logpath = /var/log/nginx/access.log
maxretry = 6
EOF

    log_command "sudo systemctl start fail2ban"
    log_command "sudo systemctl enable fail2ban"
    
    log_info "Fail2Ban installed and configured"
    log_info "Check status with: sudo fail2ban-client status"
}

setup_ssh_key_auth() {
    log_info "Configuring SSH key authentication..."
    
    if [[ ! -d ~/.ssh ]]; then
        log_warn "~/.ssh directory not found. Please set up SSH keys first."
        log_info "Run: ssh-keygen -t rsa -b 4096 -C 'your_email@example.com'"
        return 1
    fi
    
    if [[ ! -f ~/.ssh/authorized_keys ]] || [[ ! -s ~/.ssh/authorized_keys ]]; then
        log_warn "No SSH keys found in ~/.ssh/authorized_keys"
        log_info "Please add your public key to ~/.ssh/authorized_keys before disabling password auth"
        return 1
    fi
    
    log_command "sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup"
    
    sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
    sudo sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
    sudo sed -i 's/#PubkeyAuthentication yes/PubkeyAuthentication yes/' /etc/ssh/sshd_config
    sudo sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
    sudo sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
    
    if sudo sshd -t; then
        log_command "sudo systemctl restart sshd"
        log_info "SSH key authentication enabled, password authentication disabled"
        log_warn "Make sure you can connect via SSH keys before logging out!"
    else
        log_error "SSH configuration test failed, reverting changes"
        log_command "sudo cp /etc/ssh/sshd_config.backup /etc/ssh/sshd_config"
        return 1
    fi
}

setup_auto_updates() {
    log_info "Setting up automatic security updates..."
    
    log_command "sudo apt-get install -y unattended-upgrades apt-listchanges"
    
    sudo tee /etc/apt/apt.conf.d/20auto-upgrades > /dev/null <<EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
EOF

    sudo sed -i 's|//\s*"\${distro_id}:\${distro_codename}-security";|        "\${distro_id}:\${distro_codename}-security";|' /etc/apt/apt.conf.d/50unattended-upgrades
    
    if command -v mail &> /dev/null; then
        sudo sed -i "s|//Unattended-Upgrade::Mail \"root\";|Unattended-Upgrade::Mail \"$(whoami)\";|" /etc/apt/apt.conf.d/50unattended-upgrades
    fi
    
    log_command "sudo systemctl enable unattended-upgrades"
    log_command "sudo systemctl start unattended-upgrades"
    
    log_info "Automatic security updates configured"
    log_info "Check status with: sudo systemctl status unattended-upgrades"
}

setup_log_monitoring() {
    log_info "Setting up file-based log monitoring with logwatch..."
    
    log_command "sudo apt-get install -y --no-install-recommends logwatch"
    
    sudo tee /etc/logwatch/conf/logwatch.conf > /dev/null <<EOF
LogDir = /var/log
TmpDir = /var/cache/logwatch
Output = file
Filename = /var/log/logwatch/daily-report.txt
Print = Yes
Range = yesterday
Detail = Med
Service = All
EOF

    sudo mkdir -p /var/log/logwatch
    
    sudo tee /etc/cron.daily/00logwatch > /dev/null <<'EOF'
#!/bin/bash
REPORT_FILE="/var/log/logwatch/daily-report-$(date +%Y%m%d).txt"
/usr/sbin/logwatch --output file --filename "$REPORT_FILE" --detail high
# Keep only last 30 days of reports
find /var/log/logwatch -name "daily-report-*.txt" -mtime +30 -delete
EOF

    sudo chmod +x /etc/cron.daily/00logwatch
    log_info "Daily reports will be saved to /var/log/logwatch/"
}

setup_backup_system() {
    log_info "Setting up basic backup system..."
    
    BACKUP_DIR="/opt/backups"
    sudo mkdir -p "$BACKUP_DIR"/{daily,weekly,monthly}
    sudo chown $(whoami):$(whoami) "$BACKUP_DIR" -R
    
    sudo tee /opt/backups/backup-script.sh > /dev/null <<EOF
#!/bin/bash
# Simple backup script
set -euo pipefail

BACKUP_DIR="/opt/backups"
DATE=\$(date +%Y%m%d_%H%M%S)
HOSTNAME=\$(hostname)

# Function to create backup
create_backup() {
    local backup_type=\$1
    local retention_days=\$2
    
    echo "Creating \$backup_type backup..."
    
    # Backup important directories
    tar -czf "\$BACKUP_DIR/\$backup_type/system-\$backup_type-\$DATE.tar.gz" \\
        --exclude='/proc' --exclude='/tmp' --exclude='/mnt' --exclude='/dev' \\
        --exclude='/sys' --exclude='/opt/backups' --exclude='/var/cache' \\
        /etc /home /var/log /var/www 2>/dev/null || true
    
    # Backup nginx config
    tar -czf "\$BACKUP_DIR/\$backup_type/nginx-\$backup_type-\$DATE.tar.gz" /etc/nginx/ 2>/dev/null || true
    
    # Backup PM2 ecosystem
    if command -v pm2 &> /dev/null; then
        pm2 save
        cp ~/.pm2/dump.pm2 "\$BACKUP_DIR/\$backup_type/pm2-\$backup_type-\$DATE.json" 2>/dev/null || true
    fi
    
    # Clean old backups
    find "\$BACKUP_DIR/\$backup_type" -name "*.tar.gz" -mtime +\$retention_days -delete 2>/dev/null || true
    find "\$BACKUP_DIR/\$backup_type" -name "*.json" -mtime +\$retention_days -delete 2>/dev/null || true
    
    echo "\$backup_type backup completed: \$(ls -la \$BACKUP_DIR/\$backup_type/*\$DATE*)"
}

# Determine backup type based on day
if [[ "\$(date +%u)" == "7" ]]; then
    create_backup "weekly" 28
elif [[ "\$(date +%d)" == "01" ]]; then
    create_backup "monthly" 90
else
    create_backup "daily" 7
fi
EOF

    sudo chmod +x /opt/backups/backup-script.sh
    
    (crontab -l 2>/dev/null; echo "0 2 * * * /opt/backups/backup-script.sh >> /var/log/backup.log 2>&1") | crontab -
    
    sudo tee /opt/backups/restore-helper.sh > /dev/null <<'EOF'
#!/bin/bash
echo "Available backups:"
echo "=================="
ls -la /opt/backups/*/
echo
echo "To restore a backup:"
echo "1. sudo tar -xzf /opt/backups/[type]/[backup-file] -C /"
echo "2. sudo systemctl restart nginx"
echo "3. pm2 resurrect (for PM2 apps)"
echo
echo "CAUTION: Always test restores on a separate system first!"
EOF

    sudo chmod +x /opt/backups/restore-helper.sh
    
    log_info "Backup system configured"
    log_info "Daily backups will run at 2 AM"
    log_info "Check backups with: ls -la /opt/backups/"
    log_info "Restore help: /opt/backups/restore-helper.sh"
}


setup_nginx_config() {
    log_info "Setting up basic Nginx configuration..."
    
    log_command "sudo cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.backup"
    
    sudo tee /etc/nginx/sites-available/default > /dev/null <<EOF
        server {
            listen 80 default_server;
            listen [::]:80 default_server;
            
            root /var/www/html;
            index index.html index.htm index.nginx-debian.html;
            
            server_name _;
            
            location / {
                try_files \$uri \$uri/ =404;
            }
            
            # Example Node.js app proxy 
            # location /api {
            #     proxy_pass http://localhost:3000;
            #     proxy_http_version 1.1;
            #     proxy_set_header Upgrade \$http_upgrade;
            #     proxy_set_header Connection 'upgrade';
            #     proxy_set_header Host \$host;
            #     proxy_set_header X-Real-IP \$remote_addr;
            #     proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            #     proxy_set_header X-Forwarded-Proto \$scheme;
            #     proxy_cache_bypass \$http_upgrade;
            # }
        }
EOF
    
    if sudo nginx -t; then
        log_command "sudo systemctl reload nginx"
        log_info "Nginx configuration updated successfully"
    else
        log_error "Nginx configuration test failed"
        return 1
    fi
}



#######################################
# CLEANUP AND MAINTENANCE
#######################################
cleanup() {
    log_info "Cleaning up..."
    log_command "sudo apt-get autoremove -y"
    log_command "sudo apt-get autoclean"
}

cleanup_logs() {
    log_info "Cleaning up old logs..."
    cd "$LOG_DIR"
    
    ls -t vps-setup-*.log 2>/dev/null | tail -n +11 | xargs rm -f 2>/dev/null || true
    
    if [[ -f "$GENERAL_LOG" && $(stat -c%s "$GENERAL_LOG") -gt 1048576 ]]; then
        tail -n 1000 "$GENERAL_LOG" > "${GENERAL_LOG}.tmp"
        mv "${GENERAL_LOG}.tmp" "$GENERAL_LOG"
        log_info "Trimmed general log file"
    fi
}

#######################################
# LOG REVIEW FUNCTIONS
#######################################
show_log_summary() {
    echo
    log_info "Setup Summary:"
    echo "============================================="
    echo "Log file: $LOG_FILE"
    echo "General log: $GENERAL_LOG"
    echo "============================================="
    echo
    echo "To review this setup later:"
    echo "  cat $LOG_FILE"
    echo
    echo "To see recent setup activity:"
    echo "  tail -50 $GENERAL_LOG"
    echo
    echo "To see all setup logs:"
    echo "  ls -la $LOG_DIR/vps-setup-*.log"
    echo
}

#######################################
# ERROR HANDLING
#######################################
handle_error() {
    local exit_code=$?
    log_error "Script failed with exit code $exit_code"
    log_error "Check the log file for details: $LOG_FILE"
    exit $exit_code
}

trap handle_error ERR

#######################################
# MAIN EXECUTION
#######################################
main() {
    setup_logging
    
    log_info "Starting VPS setup script..."
    log_info "All operations will be logged to: $LOG_FILE"
    
    check_root
    check_os
    
    update_system
    install_nodejs
    install_pm2
    install_nginx
    cleanup_unwanted_services
    install_certbot
    
    setup_firewall
    setup_nginx_config
    install_fail2ban
    setup_ssh_key_auth
    setup_auto_updates
    setup_log_monitoring
    setup_backup_system
    
    cleanup
    cleanup_logs
    
    log_info "Server setup completed successfully!"
    log_info "Next steps:"
    log_info "1. Configure your domain DNS to point to this server"
    log_info "2. Run: sudo certbot --nginx -d yourdomain.com"
    log_info "3. Deploy your application and configure PM2"
    log_info "4. Update Nginx configuration for your app"
    
    echo
    log_info "Installed versions:"
    echo "Node.js: $(node --version)" | tee -a "$LOG_FILE"
    echo "npm: $(npm --version)" | tee -a "$LOG_FILE"
    echo "PM2: $(pm2 --version)" | tee -a "$LOG_FILE"
    echo "Nginx: $(nginx -v 2>&1)" | tee -a "$LOG_FILE"
    echo "Certbot: $(certbot --version)" | tee -a "$LOG_FILE"
    
    show_log_summary
}

main "$@"