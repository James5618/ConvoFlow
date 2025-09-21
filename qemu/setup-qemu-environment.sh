#!/bin/bash

# QEMU Environment Setup Script for Encrypted Chat Application
# This script creates and configures QEMU virtual machines for on-premise deployment

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
QEMU_DIR="$SCRIPT_DIR/vms"
ISO_DIR="$SCRIPT_DIR/isos"
BRIDGE_NAME="br-chat"
NETWORK_PREFIX="192.168.100"

# VM Configuration
VMS=(
    "chat-app:4096:20:2:${NETWORK_PREFIX}.10"     # Application server
    "chat-db:8192:50:4:${NETWORK_PREFIX}.11"      # Database server
    "chat-lb:2048:10:2:${NETWORK_PREFIX}.12"      # Load balancer/reverse proxy
    "chat-monitor:4096:30:2:${NETWORK_PREFIX}.13"  # Monitoring server
)

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
    if [ "$EUID" -ne 0 ]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

# Check prerequisites
check_prerequisites() {
    local missing_tools=()
    
    log_step "Checking prerequisites..."
    
    # Check for required tools
    for tool in qemu-system-x86_64 qemu-img brctl ip iptables; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done
    
    if [ ${#missing_tools[@]} -ne 0 ]; then
        log_error "Missing required tools: ${missing_tools[*]}"
        log_info "Install with: apt-get install qemu-kvm qemu-utils bridge-utils iproute2 iptables"
        exit 1
    fi
    
    # Check for KVM support
    if [ ! -e /dev/kvm ]; then
        log_warn "KVM not available. VMs will run slower without hardware acceleration."
    fi
    
    log_info "Prerequisites check passed"
}

# Setup networking
setup_network() {
    log_step "Setting up network bridge..."
    
    # Create bridge if it doesn't exist
    if ! brctl show | grep -q "$BRIDGE_NAME"; then
        brctl addbr "$BRIDGE_NAME"
        ip addr add "${NETWORK_PREFIX}.1/24" dev "$BRIDGE_NAME"
        ip link set dev "$BRIDGE_NAME" up
        log_info "Created bridge: $BRIDGE_NAME"
    else
        log_info "Bridge $BRIDGE_NAME already exists"
    fi
    
    # Enable IP forwarding
    echo 1 > /proc/sys/net/ipv4/ip_forward
    
    # Setup NAT for internet access
    iptables -t nat -C POSTROUTING -s "${NETWORK_PREFIX}.0/24" ! -d "${NETWORK_PREFIX}.0/24" -j MASQUERADE 2>/dev/null || \
    iptables -t nat -A POSTROUTING -s "${NETWORK_PREFIX}.0/24" ! -d "${NETWORK_PREFIX}.0/24" -j MASQUERADE
    
    # Allow forwarding
    iptables -C FORWARD -i "$BRIDGE_NAME" -o "$BRIDGE_NAME" -j ACCEPT 2>/dev/null || \
    iptables -A FORWARD -i "$BRIDGE_NAME" -o "$BRIDGE_NAME" -j ACCEPT
    
    log_info "Network setup completed"
}

# Download Ubuntu Server ISO
download_iso() {
    log_step "Checking for Ubuntu Server ISO..."
    
    mkdir -p "$ISO_DIR"
    local iso_file="$ISO_DIR/ubuntu-22.04-server-amd64.iso"
    
    if [ ! -f "$iso_file" ]; then
        log_info "Downloading Ubuntu Server 22.04 LTS..."
        wget -O "$iso_file" "https://releases.ubuntu.com/22.04/ubuntu-22.04.3-live-server-amd64.iso"
    else
        log_info "Ubuntu Server ISO already exists"
    fi
}

# Create VM disk image
create_vm_disk() {
    local vm_name="$1"
    local disk_size="$2"
    local vm_dir="$QEMU_DIR/$vm_name"
    local disk_file="$vm_dir/${vm_name}.qcow2"
    
    mkdir -p "$vm_dir"
    
    if [ ! -f "$disk_file" ]; then
        log_info "Creating disk for $vm_name (${disk_size}GB)..."
        qemu-img create -f qcow2 "$disk_file" "${disk_size}G"
    else
        log_info "Disk for $vm_name already exists"
    fi
}

# Generate cloud-init configuration
generate_cloud_init() {
    local vm_name="$1"
    local ip_address="$2"
    local vm_dir="$QEMU_DIR/$vm_name"
    
    # Create user-data file
    cat > "$vm_dir/user-data" << EOF
#cloud-config
hostname: $vm_name
users:
  - name: ubuntu
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    ssh_authorized_keys:
      - ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC... # Add your public key here
package_update: true
packages:
  - docker.io
  - docker-compose
  - git
  - curl
  - wget
  - htop
  - vim
  - net-tools
runcmd:
  - systemctl enable docker
  - systemctl start docker
  - usermod -aG docker ubuntu
  - ufw --force enable
  - ufw allow ssh
  - ufw allow 80
  - ufw allow 443
write_files:
  - path: /etc/netplan/50-cloud-init.yaml
    content: |
      network:
        version: 2
        ethernets:
          enp0s3:
            dhcp4: false
            addresses:
              - $ip_address/24
            gateway4: ${NETWORK_PREFIX}.1
            nameservers:
              addresses:
                - 8.8.8.8
                - 8.8.4.4
final_message: "The system is finally up, after \$UPTIME seconds"
EOF

    # Create meta-data file
    cat > "$vm_dir/meta-data" << EOF
instance-id: $vm_name
local-hostname: $vm_name
EOF

    # Create cloud-init ISO
    if command -v genisoimage &> /dev/null; then
        genisoimage -output "$vm_dir/cloud-init.iso" -volid cidata -joliet -rock "$vm_dir/user-data" "$vm_dir/meta-data"
    elif command -v mkisofs &> /dev/null; then
        mkisofs -output "$vm_dir/cloud-init.iso" -volid cidata -joliet -rock "$vm_dir/user-data" "$vm_dir/meta-data"
    else
        log_error "Neither genisoimage nor mkisofs found. Install with: apt-get install genisoimage"
        exit 1
    fi
}

# Create VM start script
create_vm_script() {
    local vm_name="$1"
    local memory="$2"
    local cpus="$3"
    local ip_address="$4"
    local vm_dir="$QEMU_DIR/$vm_name"
    
    cat > "$vm_dir/start-${vm_name}.sh" << EOF
#!/bin/bash

# Start script for $vm_name VM
VM_NAME="$vm_name"
VM_DIR="$vm_dir"
MEMORY="$memory"
CPUS="$cpus"
DISK="\$VM_DIR/\${VM_NAME}.qcow2"
ISO_FILE="$ISO_DIR/ubuntu-22.04-server-amd64.iso"
CLOUD_INIT="\$VM_DIR/cloud-init.iso"
PIDFILE="\$VM_DIR/\${VM_NAME}.pid"
MONITOR_SOCKET="\$VM_DIR/\${VM_NAME}.monitor"

# Check if VM is already running
if [ -f "\$PIDFILE" ] && kill -0 \$(cat "\$PIDFILE") 2>/dev/null; then
    echo "VM \$VM_NAME is already running (PID: \$(cat \$PIDFILE))"
    exit 1
fi

# Create TAP interface
TAP_INTERFACE="tap-\$VM_NAME"
ip tuntap add dev \$TAP_INTERFACE mode tap
ip link set dev \$TAP_INTERFACE up
brctl addif $BRIDGE_NAME \$TAP_INTERFACE

# Start QEMU
qemu-system-x86_64 \\
    -name "\$VM_NAME" \\
    -machine type=pc,accel=kvm \\
    -cpu host \\
    -smp "\$CPUS" \\
    -m "\$MEMORY" \\
    -drive file="\$DISK",format=qcow2,if=virtio \\
    -drive file="\$CLOUD_INIT",format=raw,if=virtio,readonly=on \\
    -netdev tap,id=net0,ifname=\$TAP_INTERFACE,script=no,downscript=no \\
    -device virtio-net-pci,netdev=net0,mac=52:54:00:12:34:\$(printf "%02x" \${ip_address##*.}) \\
    -vnc :"\$((\${ip_address##*.} - 10))" \\
    -monitor unix:\$MONITOR_SOCKET,server,nowait \\
    -daemonize \\
    -pidfile "\$PIDFILE"

echo "VM \$VM_NAME started successfully"
echo "IP Address: $ip_address"
echo "VNC Port: \$((\${ip_address##*.} - 10 + 5900))"
echo "Monitor: \$MONITOR_SOCKET"
EOF

    chmod +x "$vm_dir/start-${vm_name}.sh"
    
    # Create stop script
    cat > "$vm_dir/stop-${vm_name}.sh" << EOF
#!/bin/bash

VM_NAME="$vm_name"
VM_DIR="$vm_dir"
PIDFILE="\$VM_DIR/\${VM_NAME}.pid"
TAP_INTERFACE="tap-\$VM_NAME"

if [ -f "\$PIDFILE" ]; then
    PID=\$(cat "\$PIDFILE")
    if kill -0 "\$PID" 2>/dev/null; then
        echo "Stopping VM \$VM_NAME (PID: \$PID)..."
        kill "\$PID"
        
        # Wait for process to terminate
        timeout=30
        while kill -0 "\$PID" 2>/dev/null && [ \$timeout -gt 0 ]; do
            sleep 1
            timeout=\$((timeout - 1))
        done
        
        if kill -0 "\$PID" 2>/dev/null; then
            echo "Force killing VM \$VM_NAME..."
            kill -9 "\$PID"
        fi
        
        rm -f "\$PIDFILE"
        echo "VM \$VM_NAME stopped"
    else
        echo "VM \$VM_NAME is not running"
        rm -f "\$PIDFILE"
    fi
else
    echo "No PID file found for VM \$VM_NAME"
fi

# Clean up TAP interface
if ip link show \$TAP_INTERFACE &>/dev/null; then
    brctl delif $BRIDGE_NAME \$TAP_INTERFACE 2>/dev/null || true
    ip link delete \$TAP_INTERFACE 2>/dev/null || true
fi
EOF

    chmod +x "$vm_dir/stop-${vm_name}.sh"
}

# Create management scripts
create_management_scripts() {
    log_step "Creating management scripts..."
    
    # Master start script
    cat > "$QEMU_DIR/start-all.sh" << 'EOF'
#!/bin/bash

echo "Starting all VMs..."
for vm_dir in */; do
    if [ -f "$vm_dir/start-${vm_dir%/}.sh" ]; then
        echo "Starting ${vm_dir%/}..."
        ./"$vm_dir/start-${vm_dir%/}.sh"
        sleep 5
    fi
done
echo "All VMs started"
EOF

    # Master stop script  
    cat > "$QEMU_DIR/stop-all.sh" << 'EOF'
#!/bin/bash

echo "Stopping all VMs..."
for vm_dir in */; do
    if [ -f "$vm_dir/stop-${vm_dir%/}.sh" ]; then
        echo "Stopping ${vm_dir%/}..."
        ./"$vm_dir/stop-${vm_dir%/}.sh"
    fi
done
echo "All VMs stopped"
EOF

    # Status script
    cat > "$QEMU_DIR/status.sh" << 'EOF'
#!/bin/bash

echo "VM Status:"
echo "=========="
for vm_dir in */; do
    vm_name="${vm_dir%/}"
    pidfile="$vm_dir/${vm_name}.pid"
    
    if [ -f "$pidfile" ] && kill -0 $(cat "$pidfile") 2>/dev/null; then
        pid=$(cat "$pidfile")
        echo "✓ $vm_name (PID: $pid) - RUNNING"
    else
        echo "✗ $vm_name - STOPPED"
    fi
done
EOF

    chmod +x "$QEMU_DIR"/*.sh
}

# Setup VMs
setup_vms() {
    log_step "Setting up virtual machines..."
    
    mkdir -p "$QEMU_DIR"
    
    for vm_config in "${VMS[@]}"; do
        IFS=':' read -r vm_name memory disk_size cpus ip_address <<< "$vm_config"
        
        log_info "Setting up VM: $vm_name"
        create_vm_disk "$vm_name" "$disk_size"
        generate_cloud_init "$vm_name" "$ip_address"
        create_vm_script "$vm_name" "$memory" "$cpus" "$ip_address"
    done
    
    create_management_scripts
}

# Create README
create_documentation() {
    log_step "Creating documentation..."
    
    cat > "$SCRIPT_DIR/README.md" << 'EOF'
# QEMU Virtual Machine Environment for Encrypted Chat Application

This directory contains scripts and configurations for setting up a QEMU-based virtual machine environment for the encrypted chat application.

## VM Architecture

- **chat-app** (192.168.100.10): Main application server
- **chat-db** (192.168.100.11): PostgreSQL database server  
- **chat-lb** (192.168.100.12): Nginx load balancer/reverse proxy
- **chat-monitor** (192.168.100.13): Prometheus/Grafana monitoring

## Prerequisites

- QEMU/KVM installed
- Bridge utilities
- Root access
- At least 16GB RAM and 100GB disk space

## Setup

1. Run the setup script as root:
   ```bash
   sudo ./setup-qemu-environment.sh
   ```

2. Start all VMs:
   ```bash
   cd vms
   ./start-all.sh
   ```

3. Check VM status:
   ```bash
   ./status.sh
   ```

## VM Management

### Individual VM Control
```bash
cd vms/chat-app
./start-chat-app.sh    # Start VM
./stop-chat-app.sh     # Stop VM
```

### All VMs
```bash
cd vms
./start-all.sh    # Start all VMs
./stop-all.sh     # Stop all VMs
./status.sh       # Check status
```

## Network Configuration

- Bridge: br-chat (192.168.100.1/24)
- VMs have static IPs in 192.168.100.0/24 range
- Internet access via NAT

## VNC Access

Each VM exposes VNC on port 5900 + (last octet of IP - 10):
- chat-app: VNC port 5900 (192.168.100.10)
- chat-db: VNC port 5901 (192.168.100.11)
- chat-lb: VNC port 5902 (192.168.100.12)
- chat-monitor: VNC port 5903 (192.168.100.13)

## SSH Access

Default user: ubuntu
SSH keys: Configure in user-data files before VM creation

## Next Steps

After VMs are running, use Ansible playbooks to configure and deploy the application.
EOF
    
    log_info "Documentation created: $SCRIPT_DIR/README.md"
}

# Print summary
print_summary() {
    echo ""
    log_info "QEMU Environment Setup Complete!"
    echo ""
    echo "VM Configuration:"
    echo "=================="
    for vm_config in "${VMS[@]}"; do
        IFS=':' read -r vm_name memory disk_size cpus ip_address <<< "$vm_config"
        echo "  $vm_name: $ip_address (${memory}MB RAM, ${disk_size}GB disk, ${cpus} CPUs)"
    done
    echo ""
    echo "Next Steps:"
    echo "==========="
    echo "1. Start VMs: cd vms && ./start-all.sh"
    echo "2. Check status: ./status.sh"
    echo "3. Use Ansible playbooks to configure VMs"
    echo "4. Deploy application using CI/CD pipeline"
    echo ""
    echo "Network: $BRIDGE_NAME (${NETWORK_PREFIX}.1/24)"
    echo "VM Directory: $QEMU_DIR"
    echo "Documentation: $SCRIPT_DIR/README.md"
}

# Main function
main() {
    log_info "Starting QEMU Environment Setup for Encrypted Chat Application"
    
    check_root
    check_prerequisites
    setup_network
    download_iso
    setup_vms
    create_documentation
    print_summary
}

# Run main function
main "$@"
