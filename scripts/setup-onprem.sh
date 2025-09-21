#!/bin/bash

# On-Premise Encrypted Chat Application Setup Script
# This script sets up the persistent directories and configurations for on-premise deployment

set -e

# Configuration
INSTALL_DIR="/opt/encrypted-chat"
SERVICE_USER="chatapp"
SERVICE_GROUP="chatapp"
BACKUP_DIR="/opt/encrypted-chat/backups"
LOG_DIR="/opt/encrypted-chat/logs"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

# Check prerequisites
check_prerequisites() {
    log_step "Checking prerequisites..."
    
    # Check if required commands exist
    for cmd in docker docker-compose curl systemctl; do
        if ! command -v $cmd &> /dev/null; then
            log_error "$cmd is not installed"
            exit 1
        fi
    done
    
    # Check Docker daemon
    if ! systemctl is-active --quiet docker; then
        log_warn "Docker is not running, starting..."
        systemctl start docker
        systemctl enable docker
    fi
    
    log_info "Prerequisites check passed"
}

# Create system user and group
create_user() {
    log_step "Creating system user and group..."
    
    if ! getent group $SERVICE_GROUP > /dev/null 2>&1; then
        groupadd --system $SERVICE_GROUP
        log_info "Created group: $SERVICE_GROUP"
    fi
    
    if ! getent passwd $SERVICE_USER > /dev/null 2>&1; then
        useradd --system --gid $SERVICE_GROUP --home-dir $INSTALL_DIR \
                --shell /bin/false --comment "Encrypted Chat Service User" $SERVICE_USER
        log_info "Created user: $SERVICE_USER"
    fi
}

# Set up persistent data directories
echo "Creating persistent data directories..."
mkdir -p "${DATA_DIR}/postgres"
mkdir -p "${DATA_DIR}/redis"
mkdir -p "${DATA_DIR}/nginx/ssl"
mkdir -p "${DATA_DIR}/logs"
mkdir -p "${DATA_DIR}/backups"

# Set proper permissions
chmod 755 "${DATA_DIR}"
chmod 700 "${DATA_DIR}/postgres"
chmod 755 "${DATA_DIR}/redis"
chmod 755 "${DATA_DIR}/nginx"
chmod 755 "${DATA_DIR}/logs"
chmod 700 "${DATA_DIR}/backups"

# Generate SSL certificates if they don't exist
if [ ! -f "${DATA_DIR}/nginx/ssl/cert.pem" ] || [ ! -f "${DATA_DIR}/nginx/ssl/key.pem" ]; then
    echo "Generating self-signed SSL certificates..."
    openssl req -x509 -newkey rsa:4096 -keyout "${DATA_DIR}/nginx/ssl/key.pem" -out "${DATA_DIR}/nginx/ssl/cert.pem" -days 365 -nodes -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"
    chmod 600 "${DATA_DIR}/nginx/ssl/key.pem"
    chmod 644 "${DATA_DIR}/nginx/ssl/cert.pem"
fi

# Initialize PostgreSQL database
echo "Initializing PostgreSQL database..."
if [ ! -d "${DATA_DIR}/postgres/data" ]; then
    docker run --rm -v "${DATA_DIR}/postgres:/var/lib/postgresql/data" 
        -e POSTGRES_DB="${DB_NAME}" 
        -e POSTGRES_USER="${DB_USER}" 
        -e POSTGRES_PASSWORD="${DB_PASSWORD}" 
        postgres:15-alpine 
        sh -c "initdb -D /var/lib/postgresql/data --auth-local=trust --auth-host=md5"
fi

# Create environment file for Docker Compose
echo "Creating environment configuration..."
cat > .env.onprem << EOF
# Database Configuration
POSTGRES_DB=${DB_NAME}
POSTGRES_USER=${DB_USER}
POSTGRES_PASSWORD=${DB_PASSWORD}
DATABASE_URL=postgresql://${DB_USER}:${DB_PASSWORD}@postgres:5432/${DB_NAME}

# Application Configuration
NODE_ENV=production
JWT_SECRET=${JWT_SECRET}
PORT=3000

# Redis Configuration
REDIS_URL=redis://redis:6379

# Data Directory
DATA_DIR=${DATA_DIR}
EOF

# Create backup script
echo "Creating backup script..."
cat > "${DATA_DIR}/backup.sh" << 'EOF'
#!/bin/bash

# Backup script for on-premise chat application
BACKUP_DIR="/opt/chat-app/data/backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Backup PostgreSQL database
echo "Backing up PostgreSQL database..."
docker exec chat-postgres pg_dump -U chatuser chatdb > "${BACKUP_DIR}/postgres_${TIMESTAMP}.sql"

# Backup Redis data
echo "Backing up Redis data..."
docker exec chat-redis redis-cli BGSAVE
docker cp chat-redis:/data/dump.rdb "${BACKUP_DIR}/redis_${TIMESTAMP}.rdb"

# Compress backups older than 7 days
find "${BACKUP_DIR}" -name "*.sql" -mtime +7 -exec gzip {} \;
find "${BACKUP_DIR}" -name "*.rdb" -mtime +7 -exec gzip {} \;

# Remove backups older than 30 days
find "${BACKUP_DIR}" -name "*.gz" -mtime +30 -delete

echo "Backup completed: ${TIMESTAMP}"
EOF

chmod +x "${DATA_DIR}/backup.sh"

# Generate SSL certificates
generate_ssl_certificates() {
    log_step "Generating SSL certificates..."
    
    SSL_DIR="$INSTALL_DIR/ssl"
    mkdir -p "$SSL_DIR"
    
    # Generate self-signed certificate for local development
    if [ ! -f "$SSL_DIR/cert.pem" ]; then
        openssl req -x509 -newkey rsa:4096 -keyout "$SSL_DIR/key.pem" \
                    -out "$SSL_DIR/cert.pem" -days 365 -nodes \
                    -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"
        
        chmod 600 "$SSL_DIR/key.pem"
        chmod 644 "$SSL_DIR/cert.pem"
        chown $SERVICE_USER:$SERVICE_GROUP "$SSL_DIR"/*
        
        log_info "Generated self-signed SSL certificate"
    else
        log_info "SSL certificate already exists"
    fi
}

# Create configuration files
create_configurations() {
    log_step "Creating configuration files..."
    
    # Redis configuration
    cat > "$INSTALL_DIR/config/redis/redis.conf" << 'EOF'
# Redis configuration for encrypted chat
port 6379
bind 0.0.0.0
protected-mode yes
requirepass changeme

# Persistence
appendonly yes
appendfsync everysec
save 900 1
save 300 10
save 60 10000

# Memory management
maxmemory 1gb
maxmemory-policy allkeys-lru

# Security
rename-command FLUSHDB ""
rename-command FLUSHALL ""
rename-command DEBUG ""
rename-command CONFIG "CONFIG_b835b4e9c1d6f4b2a8e8f9c0d4e5a6b7"

# Logging
loglevel notice
syslog-enabled yes
syslog-ident redis-encrypted-chat
EOF

    # Promtail configuration
    cat > "$INSTALL_DIR/config/promtail/promtail-config.yml" << 'EOF'
server:
  http_listen_port: 9080
  grpc_listen_port: 0

positions:
  filename: /tmp/positions.yaml

clients:
  - url: http://loki:3100/loki/api/v1/push

scrape_configs:
  - job_name: containers
    static_configs:
      - targets:
          - localhost
        labels:
          job: containerlogs
          __path__: /var/lib/docker/containers/*/*log

  - job_name: nginx
    static_configs:
      - targets:
          - localhost
        labels:
          job: nginx
          __path__: /var/log/nginx/*.log

  - job_name: application
    static_configs:
      - targets:
          - localhost
        labels:
          job: application
          __path__: /var/log/app/*.log
EOF
    
    # Environment file template
    cat > "$INSTALL_DIR/.env.production" << 'EOF'
# Production Environment Configuration
NODE_ENV=production
JWT_SECRET=CHANGE_THIS_TO_A_SECURE_SECRET_KEY
CORS_ORIGIN=https://your-domain.com

# Database Configuration
POSTGRES_DB=chatapp
POSTGRES_USER=chatuser
POSTGRES_PASSWORD=CHANGE_THIS_PASSWORD
DATABASE_URL=postgres://chatuser:CHANGE_THIS_PASSWORD@postgres:5432/chatapp

# Redis Configuration
REDIS_PASSWORD=CHANGE_THIS_REDIS_PASSWORD
REDIS_URL=redis://:CHANGE_THIS_REDIS_PASSWORD@redis:6379

# Frontend Configuration
REACT_APP_API_URL=https://your-domain.com/api
REACT_APP_SOCKET_URL=https://your-domain.com

# Docker Configuration
REGISTRY_URL=ghcr.io/your-org
IMAGE_TAG=latest
BACKEND_REPLICAS=2
FRONTEND_REPLICAS=2

# Monitoring
GRAFANA_PASSWORD=CHANGE_THIS_GRAFANA_PASSWORD
LOG_LEVEL=info
EOF
    
    # Set ownership
    chown -R $SERVICE_USER:$SERVICE_GROUP "$INSTALL_DIR/config"
    chown $SERVICE_USER:$SERVICE_GROUP "$INSTALL_DIR/.env.production"
    chmod 600 "$INSTALL_DIR/.env.production"
    
    log_info "Configuration files created"
}

# Create backup scripts
create_backup_scripts() {
    log_step "Creating backup scripts..."
    
    # PostgreSQL backup script
    cat > "$INSTALL_DIR/scripts/postgres-backup.sh" << 'EOF'
#!/bin/bash
BACKUP_DIR="/backups"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="postgres_backup_${DATE}.sql.gz"

echo "Starting PostgreSQL backup: $BACKUP_FILE"

pg_dump -h $PGHOST -p $PGPORT -U $PGUSER -d $PGDATABASE \
    --verbose --clean --if-exists --create \
    | gzip > "${BACKUP_DIR}/${BACKUP_FILE}"

if [ $? -eq 0 ]; then
    echo "Backup completed successfully: $BACKUP_FILE"
    
    # Remove backups older than retention period
    find $BACKUP_DIR -name "postgres_backup_*.sql.gz" -mtime +${BACKUP_RETENTION_DAYS:-30} -delete
    
    # Log backup size
    BACKUP_SIZE=$(du -h "${BACKUP_DIR}/${BACKUP_FILE}" | cut -f1)
    echo "Backup size: $BACKUP_SIZE"
else
    echo "Backup failed!"
    exit 1
fi
EOF

    # Redis backup script
    cat > "$INSTALL_DIR/scripts/redis-backup.sh" << 'EOF'
#!/bin/bash
BACKUP_DIR="/backups"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="redis_backup_${DATE}.rdb"

echo "Starting Redis backup: $BACKUP_FILE"

# Create backup using BGSAVE
redis-cli -h $REDIS_HOST -p $REDIS_PORT -a $REDIS_PASSWORD BGSAVE

# Wait for background save to complete
while [ $(redis-cli -h $REDIS_HOST -p $REDIS_PORT -a $REDIS_PASSWORD PING) != "PONG" ]; do
    sleep 1
done

# Copy the dump file
docker cp encrypted-chat-redis:/data/dump.rdb "${BACKUP_DIR}/${BACKUP_FILE}"

if [ $? -eq 0 ]; then
    echo "Backup completed successfully: $BACKUP_FILE"
    
    # Compress backup
    gzip "${BACKUP_DIR}/${BACKUP_FILE}"
    
    # Remove old backups
    find $BACKUP_DIR -name "redis_backup_*.rdb.gz" -mtime +30 -delete
else
    echo "Redis backup failed!"
    exit 1
fi
EOF

    # Make scripts executable
    chmod +x "$INSTALL_DIR/scripts/"*.sh
    chown -R $SERVICE_USER:$SERVICE_GROUP "$INSTALL_DIR/scripts"
    
    log_info "Backup scripts created"
}

# Create systemd service
create_systemd_service() {
    log_step "Creating systemd service..."
    
    cat > /etc/systemd/system/encrypted-chat.service << EOF
[Unit]
Description=Encrypted Chat Application
Documentation=https://github.com/your-org/encrypted-chat
Requires=docker.service
After=docker.service
StartLimitIntervalSec=0

[Service]
Type=forking
RemainAfterExit=yes
User=root
Group=root
WorkingDirectory=$INSTALL_DIR
ExecStartPre=/usr/bin/docker-compose -f docker-compose.onprem.yml pull
ExecStart=/usr/bin/docker-compose -f docker-compose.onprem.yml up -d
ExecStop=/usr/bin/docker-compose -f docker-compose.onprem.yml down
ExecReload=/usr/bin/docker-compose -f docker-compose.onprem.yml restart
TimeoutStartSec=300
TimeoutStopSec=120
Restart=on-failure
RestartSec=30

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable encrypted-chat.service
    
    log_info "Systemd service created and enabled"
}

# Setup log rotation
setup_log_rotation() {
    log_step "Setting up log rotation..."
    
    cat > /etc/logrotate.d/encrypted-chat << 'EOF'
/opt/encrypted-chat/logs/*/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
    postrotate
        /bin/systemctl reload encrypted-chat
    endscript
}
EOF
    
    log_info "Log rotation configured"
}

# Setup firewall
setup_firewall() {
    log_step "Configuring firewall..."
    
    if command -v ufw &> /dev/null; then
        # UFW firewall
        ufw allow 22/tcp comment "SSH"
        ufw allow 80/tcp comment "HTTP"
        ufw allow 443/tcp comment "HTTPS"
        ufw allow 3000/tcp comment "Grafana"
        ufw allow 9090/tcp comment "Prometheus"
        ufw --force enable
        log_info "UFW firewall configured"
    elif command -v firewall-cmd &> /dev/null; then
        # Firewalld
        firewall-cmd --permanent --add-service=ssh
        firewall-cmd --permanent --add-service=http
        firewall-cmd --permanent --add-service=https
        firewall-cmd --permanent --add-port=3000/tcp
        firewall-cmd --permanent --add-port=9090/tcp
        firewall-cmd --reload
        log_info "Firewalld configured"
    else
        log_warn "No supported firewall found. Please configure manually."
    fi
}

# Create monitoring alerts
create_monitoring_alerts() {
    log_step "Creating monitoring alert rules..."
    
    mkdir -p "$INSTALL_DIR/monitoring/rules"
    
    cat > "$INSTALL_DIR/monitoring/rules/alerts.yml" << 'EOF'
groups:
  - name: encrypted-chat-alerts
    rules:
      - alert: ServiceDown
        expr: up == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Service {{ $labels.instance }} is down"
          description: "{{ $labels.instance }} has been down for more than 1 minute."

      - alert: HighMemoryUsage
        expr: (node_memory_MemTotal_bytes - node_memory_MemAvailable_bytes) / node_memory_MemTotal_bytes > 0.9
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High memory usage on {{ $labels.instance }}"
          description: "Memory usage is above 90% for more than 5 minutes."

      - alert: HighDiskUsage
        expr: (node_filesystem_size_bytes - node_filesystem_free_bytes) / node_filesystem_size_bytes > 0.9
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High disk usage on {{ $labels.instance }}"
          description: "Disk usage is above 90% for more than 5 minutes."

      - alert: DatabaseConnectionFail
        expr: postgres_up == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "PostgreSQL database is down"
          description: "Cannot connect to PostgreSQL database."

      - alert: RedisConnectionFail
        expr: redis_up == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Redis is down"
          description: "Cannot connect to Redis instance."
EOF
    
    chown -R $SERVICE_USER:$SERVICE_GROUP "$INSTALL_DIR/monitoring"
    
    log_info "Monitoring alerts configured"
}

# Print setup summary
print_summary() {
    log_step "Setup Summary"
    
    cat << EOF

${GREEN}✅ Encrypted Chat Application Setup Complete!${NC}

📁 Installation Directory: $INSTALL_DIR
👤 Service User: $SERVICE_USER
🔐 SSL Certificates: $INSTALL_DIR/ssl/
⚙️  Configuration: $INSTALL_DIR/.env.production

${YELLOW}⚠️  IMPORTANT: Update the following before starting:${NC}

1. Edit configuration file:
   sudo nano $INSTALL_DIR/.env.production
   
   Update these values:
   - JWT_SECRET
   - POSTGRES_PASSWORD
   - REDIS_PASSWORD
   - GRAFANA_PASSWORD
   - CORS_ORIGIN
   - REACT_APP_API_URL
   - REACT_APP_SOCKET_URL

2. Copy application files:
   sudo cp docker-compose.onprem.yml $INSTALL_DIR/
   sudo chown $SERVICE_USER:$SERVICE_GROUP $INSTALL_DIR/docker-compose.onprem.yml

3. Start the service:
   sudo systemctl start encrypted-chat
   sudo systemctl status encrypted-chat

${BLUE}📊 Access Points:${NC}
- Application: https://localhost (or your domain)
- Grafana: http://localhost:3000 (admin/password from .env)
- Prometheus: http://localhost:9090

${BLUE}🛠️  Management Commands:${NC}
- Start: sudo systemctl start encrypted-chat
- Stop: sudo systemctl stop encrypted-chat
- Restart: sudo systemctl restart encrypted-chat
- Status: sudo systemctl status encrypted-chat
- Logs: sudo journalctl -u encrypted-chat -f

${BLUE}💾 Backup Commands:${NC}
- Manual backup: sudo docker exec encrypted-chat-postgres-backup /usr/local/bin/backup.sh
- Backup location: $BACKUP_DIR

${BLUE}🔍 Troubleshooting:${NC}
- Check service logs: sudo journalctl -u encrypted-chat -f
- Check container logs: sudo docker-compose -f $INSTALL_DIR/docker-compose.onprem.yml logs
- Health check: curl -f http://localhost/health

EOF
}

# Main setup function
main() {
    log_info "Starting Encrypted Chat On-Premise Setup"
    
    check_root
    check_prerequisites
    create_user
    create_directories
    generate_ssl_certificates
    create_configurations
    create_backup_scripts
    create_systemd_service
    setup_log_rotation
    setup_firewall
    create_monitoring_alerts
    print_summary
    
    log_info "Setup completed successfully!"
}

# Run main function
main "$@"
