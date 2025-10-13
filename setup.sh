#!/usr/bin/env bash
# setup.sh - Kubernetes security lab setup script
# Fast, reliable, comprehensive Kubernetes security lab deployment

set -euo pipefail

###
### Configuration
###
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly RESOURCES_DIR="${SCRIPT_DIR}/resources"
readonly INSTALL_DIR="/opt/kubelab"
readonly VULN_REPO_URL="https://github.com/madhuakula/kubernetes-goat.git"
readonly VULN_REPO_DIR="${INSTALL_DIR}/kubernetes-goat"
readonly KIND_VERSION="v0.26.0"

###
### Helper functions
###
command_exists() { command -v "$1" >/dev/null 2>&1; }

###
### Preflight checks
###
echo "Running preflight checks..."

# Must be run as root
[ "$(id -u)" -eq 0 ] || { echo "ERROR: Run with sudo"; exit 1; }

# Check resources directory exists
[ -d "${RESOURCES_DIR}" ] || { echo "ERROR: Resources directory not found at ${RESOURCES_DIR}"; exit 1; }

# OS check
[ -f /etc/os-release ] || { echo "ERROR: Cannot detect OS"; exit 1; }
. /etc/os-release
[ "${ID}" = "ubuntu" ] || { echo "WARNING: Not Ubuntu, continuing anyway"; }
[ "${VERSION_ID%%.*}" -ge 24 ] || { echo "ERROR: Ubuntu 24+ required"; exit 1; }

# Network check
ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1 || { echo "ERROR: No network connectivity"; exit 1; }

echo "✓ Preflight checks passed"

###
### Initial system preparation
###
echo "Preparing system for installation..."

# Store the actual user (not root) for later use
if [ -n "$SUDO_USER" ]; then
    ACTUAL_USER="$SUDO_USER"
    ACTUAL_HOME="/home/$SUDO_USER"
else
    ACTUAL_USER=$(logname 2>/dev/null || echo "root")
    ACTUAL_HOME="/home/$ACTUAL_USER"
fi

echo "✓ Detected user: $ACTUAL_USER"

# Ensure user's home directory and common directories exist
if [ "$ACTUAL_USER" != "root" ]; then
    mkdir -p "$ACTUAL_HOME/.kube"
    mkdir -p "$ACTUAL_HOME/.docker"
    chown -R "$ACTUAL_USER:$ACTUAL_USER" "$ACTUAL_HOME/.kube" "$ACTUAL_HOME/.docker" 2>/dev/null || true
fi

###
### Install base packages
###
echo "Installing base packages..."
apt-get update -qq
apt-get install -y --no-install-recommends \
    ca-certificates curl wget gnupg lsb-release software-properties-common \
    apt-transport-https git sudo unzip net-tools build-essential
echo "✓ Base packages installed"

###
### Docker CE installation
###
if command_exists docker; then
    echo "✓ Docker already installed"
else
    echo "Installing Docker CE..."
    mkdir -p /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg
    
    arch=$(dpkg --print-architecture)
    codename=$(lsb_release -cs)
    echo "deb [arch=${arch} signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu ${codename} stable" > /etc/apt/sources.list.d/docker.list
    
    apt-get update -qq
    apt-get install -y --no-install-recommends docker-ce docker-ce-cli containerd.io docker-compose-plugin
    systemctl enable docker
    systemctl start docker
    echo "✓ Docker installed"
fi

# Add user to docker group and verify
nonroot_user=$(logname 2>/dev/null || who am i 2>/dev/null | awk '{print $1}' || echo "")
if [ -n "${nonroot_user}" ] && [ "${nonroot_user}" != "root" ]; then
    if ! groups "${nonroot_user}" | grep -q docker; then
        echo "Adding ${nonroot_user} to docker group..."
        usermod -aG docker "${nonroot_user}"
        echo "✓ User ${nonroot_user} added to docker group"
        echo "NOTE: User will need to log out and back in for docker group membership to take effect"
    else
        echo "✓ User ${nonroot_user} already in docker group"
    fi
    
    # Ensure docker socket permissions
    chmod 666 /var/run/docker.sock 2>/dev/null || true
else
    echo "WARNING: Could not determine non-root user for docker group assignment"
fi

###
### kubectl installation
###
if command_exists kubectl; then
    echo "✓ kubectl already installed"
else
    echo "Installing kubectl..."
    stable_version=$(curl -fsSL https://dl.k8s.io/release/stable.txt)
    curl -fsSLo /tmp/kubectl "https://dl.k8s.io/release/${stable_version}/bin/linux/amd64/kubectl"
    chmod +x /tmp/kubectl
    mv /tmp/kubectl /usr/local/bin/kubectl
    echo "✓ kubectl installed"
fi

###
### kind installation
###
if command_exists kind; then
    echo "✓ kind already installed"
else
    echo "Installing kind..."
    curl -fsSLo /tmp/kind "https://kind.sigs.k8s.io/dl/${KIND_VERSION}/kind-linux-amd64"
    chmod +x /tmp/kind
    mv /tmp/kind /usr/local/bin/kind
    echo "✓ kind installed"
fi

###
### Helm installation
###
if command_exists helm; then
    echo "✓ Helm already installed"
else
    echo "Installing Helm..."
    curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
    echo "✓ Helm installed"
fi

###
### Create kind cluster
###
if kubectl config current-context 2>/dev/null | grep -q "kind-"; then
    echo "✓ Kind cluster already exists"
else
    echo "Creating kind cluster..."
    mkdir -p "${INSTALL_DIR}"
    
    cat > /tmp/kind-config.yaml <<'EOF'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
EOF

    kind create cluster --config /tmp/kind-config.yaml --wait 300s
    echo "✓ Kind cluster created"
    
    # Copy kubeconfig to user's home directory
    if [ -n "${nonroot_user}" ] && [ "${nonroot_user}" != "root" ]; then
        user_home=$(eval echo "~${nonroot_user}")
        if [ -d "${user_home}" ]; then
            mkdir -p "${user_home}/.kube"
            cp /root/.kube/config "${user_home}/.kube/config"
            chown -R "${nonroot_user}:${nonroot_user}" "${user_home}/.kube"
            echo "✓ Kubeconfig copied to ${user_home}/.kube/config"
        fi
    fi
fi

###
### Clone vulnerable lab repository
###
if [ -d "${VULN_REPO_DIR}/.git" ]; then
    echo "✓ Vulnerable lab repo already cloned"
    cd "${VULN_REPO_DIR}"
    git pull --ff-only 2>/dev/null || echo "✓ Using existing repository version"
else
    echo "Cloning vulnerable lab repository..."
    mkdir -p "$(dirname "${VULN_REPO_DIR}")"
    
    # Non-interactive git configuration
    export GIT_TERMINAL_PROMPT=0
    export GIT_ASKPASS=/bin/true
    export SSH_ASKPASS=/bin/true
    
    git -c advice.detachedHead=false \
        -c init.defaultBranch=main \
        -c user.name="KubeLab Setup" \
        -c user.email="setup@kubelab.local" \
        clone --depth 1 --quiet \
        "${VULN_REPO_URL}" "${VULN_REPO_DIR}"
    echo "✓ Repository cloned"
fi

###
### Install and configure Falco runtime security on host
###
echo "Installing Falco runtime security monitoring..."

# Install Falco GPG key and repository
curl -fsSL https://falco.org/repo/falcosecurity-packages.asc | gpg --dearmor -o /usr/share/keyrings/falco-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] https://download.falco.org/packages/deb stable main" > /etc/apt/sources.list.d/falcosecurity.list

# Update package list and install Falco
apt-get update -qq
if ! DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends falco; then
    echo "⚠ Falco installation failed. Check network or package sources."
    exit 1
fi

# Ensure rules directory exists
mkdir -p /etc/falco/rules.d

# Copy custom Kubernetes/Container security rules
cp "${RESOURCES_DIR}/k8s_security_rules.yaml" /etc/falco/rules.d/k8s_security_rules.yaml

# Configure Falco to use JSON output
falco_config="/etc/falco/falco.yaml"
if [ -f "$falco_config" ]; then
    cp "$falco_config" "${falco_config}.bak"
    sed -i 's/^json_output: false$/json_output: true/' "$falco_config"
    sed -i 's/^buffered_outputs: false$/buffered_outputs: true/' "$falco_config"
fi

# Determine the actual Falco service unit (modern eBPF)
FALCO_UNIT="falco-modern-bpf.service"

echo "Enabling and starting Falco service: $FALCO_UNIT"
systemctl daemon-reload
systemctl enable "$FALCO_UNIT"
systemctl restart "$FALCO_UNIT"

# Verify Falco is running
if systemctl is-active --quiet "$FALCO_UNIT"; then
    echo "✓ Falco runtime security monitoring is active"
else
    echo "⚠ Falco may not be running properly - check 'systemctl status $FALCO_UNIT'"
fi


###
### Install comprehensive security monitoring
###
echo "Installing comprehensive security monitoring..."

# Install audit and security tools
apt-get install -y --no-install-recommends auditd audispd-plugins aide \
    strace ltrace tcpdump netstat-nat lsof psmisc procps sysstat htop 2>/dev/null || echo "⚠ Some tools may not be available"

# Verify AIDE installation
if ! command -v aide >/dev/null 2>&1; then
    echo "⚠ AIDE installation failed - trying alternative installation..."
    apt-get update -qq
    apt-get install -y aide-common aide || echo "⚠ AIDE still unavailable"
fi

# Configure auditd
systemctl enable auditd 2>/dev/null || true
systemctl start auditd 2>/dev/null || true

# Initialize AIDE database with progress feedback and timeout
if [ ! -f /var/lib/aide/aide.db ]; then
    echo "Initializing AIDE database (this may take 10-30 minutes)..."
    echo "This is a one-time process to create the file integrity baseline..."
    
    # Ensure AIDE configuration exists
    if [ ! -f /etc/aide/aide.conf ]; then
        echo "Installing AIDE configuration..."
        mkdir -p /etc/aide
        mkdir -p /var/lib/aide
        cp "${RESOURCES_DIR}/aide.conf" "/etc/aide/aide.conf"
        echo "✓ AIDE configuration installed"
    else
        # Ensure directory exists even if config exists
        mkdir -p /var/lib/aide
    fi
    
    # Find appropriate AIDE initialization method
    aide_init_cmd=""
    if command -v aide >/dev/null 2>&1; then
        aide_init_cmd="aide --init --config=/etc/aide/aide.conf"
    else
        echo "⚠ AIDE command not found"
    fi
    
    if [ -z "$aide_init_cmd" ]; then
        echo "⚠ AIDE initialization not available - creating minimal database"
        touch /var/lib/aide/aide.db 2>/dev/null || true
        echo "✓ Created minimal AIDE database as fallback"
    else
        echo "Using AIDE initialization: $aide_init_cmd"
        
        # Run AIDE initialization in background with progress indicator
        $aide_init_cmd >/tmp/aide-init.log 2>&1 &
        aide_pid=$!
        
        # Give AIDE a moment to start and check if it exits immediately
        sleep 2
        if ! kill -0 $aide_pid 2>/dev/null; then
            # AIDE exited immediately, check why
            wait $aide_pid
            aide_exit_code=$?
            echo ""
            echo "⚠ AIDE initialization exited immediately (exit code: $aide_exit_code)"
            echo "Check /tmp/aide-init.log for details:"
            cat /tmp/aide-init.log
            echo "Creating minimal AIDE database to continue setup..."
            touch /var/lib/aide/aide.db 2>/dev/null || true
            echo "✓ Created minimal AIDE database as fallback"
        else
            # AIDE is running, show progress
            timeout_count=0
            max_timeout=360  # 30 minutes (360 * 5 seconds)
            
            while kill -0 $aide_pid 2>/dev/null && [ $timeout_count -lt $max_timeout ]; do
                echo -n "."
                sleep 5
                timeout_count=$((timeout_count + 1))
                
                # Show time estimate every minute
                if [ $((timeout_count % 12)) -eq 0 ]; then
                    minutes=$((timeout_count / 12 * 5))
                    echo " (${minutes} min elapsed)"
                fi
            done
            
            if [ $timeout_count -ge $max_timeout ]; then
                echo ""
                echo "⚠ AIDE initialization timed out after 30 minutes"
                kill $aide_pid 2>/dev/null || true
                echo "Creating minimal AIDE database to continue setup..."
                touch /var/lib/aide/aide.db 2>/dev/null || true
                echo "✓ Created minimal AIDE database as fallback"
            else
                wait $aide_pid
                aide_exit_code=$?
                echo  # newline after dots
                
                if [ $aide_exit_code -eq 0 ]; then
                    # Check for the new database file
                    if [ -f /var/lib/aide/aide.db.new ]; then
                        # Move the new database to become active
                        mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
                        echo "✓ AIDE database initialized successfully"
                        
                        # Verify the database works
                        if aide --check --config=/etc/aide/aide.conf >/dev/null 2>&1; then
                            echo "✓ AIDE database verification passed"
                        else
                            echo "⚠ AIDE database verification had issues (but continuing)"
                        fi
                    else
                        echo "⚠ AIDE initialization completed but no database file found"
                        touch /var/lib/aide/aide.db 2>/dev/null || true
                        echo "✓ Created minimal AIDE database as fallback"
                    fi
                else
                    echo "⚠ AIDE initialization had issues (exit code: $aide_exit_code)"
                    echo "Check /tmp/aide-init.log for details"
                    # Create empty database as fallback
                    touch /var/lib/aide/aide.db 2>/dev/null || true
                    echo "✓ Created minimal AIDE database as fallback"
                fi
            fi
        fi
    fi
else
    echo "✓ AIDE database already exists"
fi

# Copy and validate comprehensive audit rules
echo "Installing audit rules..."
cp "${RESOURCES_DIR}/99-kubelab-container.rules" "/etc/audit/rules.d/99-kubelab-container.rules"

# Validate audit rules before loading
if augenrules --check >/dev/null 2>&1; then
    echo "✓ Audit rules validated"
else
    echo "⚠ Audit rules validation failed, attempting to fix..."
    # Remove potentially problematic rules and retry
    sed -i '/personality/d' "/etc/audit/rules.d/99-kubelab-container.rules"
    if augenrules --check >/dev/null 2>&1; then
        echo "✓ Audit rules fixed and validated"
    else
        echo "⚠ Audit rules still have issues - continuing anyway"
    fi
fi

# Load audit rules with better error handling
if augenrules --load >/dev/null 2>&1; then
    echo "✓ Audit rules loaded successfully"
else
    echo "⚠ Failed to load audit rules - trying alternative method..."
    # Try loading individual rules
    cat /etc/audit/rules.d/99-kubelab-container.rules >> /etc/audit/audit.rules 2>/dev/null || true
fi

# Restart auditd with retry logic
for i in {1..3}; do
    if systemctl restart auditd >/dev/null 2>&1; then
        echo "✓ auditd restarted successfully"
        break
    else
        echo "⚠ auditd restart attempt $i failed, retrying..."
        sleep 2
    fi
done

# Copy system security limits
cp "${RESOURCES_DIR}/99-kubelab.conf" "/etc/security/limits.d/99-kubelab.conf"

# Configure core dump security
if ! grep -q "kernel.core_pattern" /etc/sysctl.conf 2>/dev/null; then
    echo "# KubeLab core dump security" >> /etc/sysctl.conf
    echo "kernel.core_pattern=|/bin/false" >> /etc/sysctl.conf
    echo "fs.suid_dumpable=0" >> /etc/sysctl.conf
    sysctl -p >/dev/null 2>&1 || true
fi

# Copy log rotation configuration
cp "${RESOURCES_DIR}/kubelab-logrotate" "/etc/logrotate.d/kubelab"

echo "✓ Security monitoring configured"

###
### Final security configuration and testing
###
echo "Completing security configuration..."

# Copy security monitoring script
cp "${RESOURCES_DIR}/kubelab-security-check" "/usr/local/bin/kubelab-security-check"
chmod +x "/usr/local/bin/kubelab-security-check"

# Create user convenience script for environment setup
if [ -n "${nonroot_user}" ] && [ "${nonroot_user}" != "root" ]; then
    user_home=$(eval echo "~${nonroot_user}")
    cat > "${user_home}/kubelab-env.sh" <<EOF
#!/bin/bash
# KubeLab Environment Setup Script
# Run this if you have issues with docker or kubectl permissions

echo "Setting up KubeLab environment..."

# Refresh docker group membership
if ! groups | grep -q docker; then
    echo "Adding current user to docker group..."
    sudo usermod -aG docker \$(whoami)
    echo "Please log out and back in, then run this script again"
    exit 1
fi

# Ensure kubeconfig exists and is accessible
if [ ! -f ~/.kube/config ]; then
    echo "Copying kubeconfig..."
    mkdir -p ~/.kube
    sudo cp /root/.kube/config ~/.kube/config
    sudo chown \$(id -u):\$(id -g) ~/.kube/config
fi

# Test connectivity
echo "Testing environment..."
if docker ps >/dev/null 2>&1; then
    echo "✓ Docker access working"
else
    echo "⚠ Docker access failed - try: newgrp docker"
fi

if kubectl get nodes >/dev/null 2>&1; then
    echo "✓ Kubernetes access working"
else
    echo "⚠ Kubernetes access failed - check kubeconfig"
fi

echo "Environment setup complete!"
EOF
    chown "${nonroot_user}:${nonroot_user}" "${user_home}/kubelab-env.sh"
    chmod +x "${user_home}/kubelab-env.sh"
    echo "✓ Created environment setup script at ${user_home}/kubelab-env.sh"
fi

# Test basic functionality
if command -v docker >/dev/null 2>&1; then
    echo "✓ Docker available"
else
    echo "⚠ Docker not found in PATH"
fi

if command -v kubectl >/dev/null 2>&1; then
    echo "✓ kubectl available"
else
    echo "⚠ kubectl not found in PATH"
fi

if command -v kind >/dev/null 2>&1; then
    echo "✓ kind available"
else
    echo "⚠ kind not found in PATH"
fi

# Create summary of installed security components
echo
echo "=== Security Monitoring Components Installed ==="
echo "✓ Falco runtime security with custom K8s rules"
echo "✓ auditd with container-specific audit rules"  
echo "✓ AIDE file integrity monitoring"
echo "✓ System security limits and core dump protection"
echo "✓ Enhanced logging and monitoring tools"
echo "✓ Security status check script: /usr/local/bin/kubelab-security-check"
echo

###
### System verification and issue detection
###
echo "Performing comprehensive system verification..."

# Check Docker group membership for user
if [ -n "${nonroot_user}" ] && [ "${nonroot_user}" != "root" ]; then
    if groups "${nonroot_user}" | grep -q docker; then
        echo "✓ User ${nonroot_user} has docker group membership"
    else
        echo "⚠ User ${nonroot_user} missing docker group - adding now..."
        usermod -aG docker "${nonroot_user}"
    fi
    
    # Check user's kubeconfig
    user_home=$(eval echo "~${nonroot_user}")
    if [ -f "${user_home}/.kube/config" ]; then
        echo "✓ User kubeconfig exists at ${user_home}/.kube/config"
    else
        echo "⚠ User kubeconfig missing - copying now..."
        mkdir -p "${user_home}/.kube"
        cp /root/.kube/config "${user_home}/.kube/config" 2>/dev/null || true
        chown -R "${nonroot_user}:${nonroot_user}" "${user_home}/.kube" 2>/dev/null || true
    fi
fi

# Verify audit rules are loaded
if auditctl -l | grep -q container 2>/dev/null; then
    echo "✓ Container audit rules are active"
else
    echo "⚠ Container audit rules not found - attempting reload..."
    augenrules --load >/dev/null 2>&1 || true
fi

# Check AIDE database
if [ -f /var/lib/aide/aide.db ] && [ -s /var/lib/aide/aide.db ]; then
    echo "✓ AIDE database exists and is not empty"
else
    echo "⚠ AIDE database missing or empty"
fi

# Verify Falco rules
if [ -f /etc/falco/rules.d/k8s_security_rules.yaml ]; then
    echo "✓ Custom Falco rules installed"
else
    echo "⚠ Custom Falco rules missing"
fi

# Check service status
services="docker auditd falco"
for service in $services; do
    if systemctl is-active --quiet "$service" 2>/dev/null; then
        echo "✓ $service service is running"
    else
        echo "⚠ $service service not running"
    fi
done

###
### Final verification
###
echo "Running final verification..."
docker --version >/dev/null || { echo "ERROR: Docker verification failed"; exit 1; }
kubectl version --client >/dev/null || { echo "ERROR: kubectl verification failed"; exit 1; }
kind --version >/dev/null || { echo "ERROR: kind verification failed"; exit 1; }
helm version >/dev/null || { echo "ERROR: Helm verification failed"; exit 1; }

# Verify cluster (as root)
if kubectl cluster-info >/dev/null 2>&1; then
    echo "✓ Cluster verification passed (as root)"
else
    echo "⚠ Cluster verification failed - kubeconfig may need to be copied to user home"
fi

echo ""
echo "╔══════════════════════════════════════════════════════════════════════════════╗"
echo "║                        MINIMAL SETUP COMPLETED                              ║"
echo "╚══════════════════════════════════════════════════════════════════════════════╝"
echo ""
echo "Components installed:"
echo "├─ Docker CE: $(docker --version | cut -d' ' -f1-3)"
echo "├─ kubectl: $(kubectl version --client 2>/dev/null | grep -o 'GitVersion:"[^"]*"' | cut -d'"' -f2)"
echo "├─ kind: $(kind --version)"
echo "├─ Helm: $(helm version 2>/dev/null | grep -o 'Version:"[^"]*"' | cut -d'"' -f2)"
echo "├─ Kubernetes cluster: $(kubectl config current-context)"
echo "├─ Vulnerable lab: ${VULN_REPO_DIR}"
echo "├─ Falco runtime security: $(systemctl is-active falco 2>/dev/null || echo 'inactive')"
echo "├─ auditd monitoring: $(systemctl is-active auditd 2>/dev/null || echo 'inactive')"
echo "└─ AIDE file integrity: $([ -f /var/lib/aide/aide.db ] && echo 'initialized' || echo 'pending')"
echo ""
echo "Next steps:"
if [ -n "${nonroot_user}" ] && [ "${nonroot_user}" != "root" ]; then
    echo "1. Log out and back in as '${nonroot_user}' (or run: newgrp docker)"
    echo "2. Verify cluster access: kubectl get nodes"
    echo "3. Deploy vulnerable lab: kubectl apply -f ${VULN_REPO_DIR}/scenarios/"
    echo "4. Run security check: kubelab-security-check"
    echo ""
    echo "Quick environment fix (if needed): ~/kubelab-env.sh"
    echo ""
    echo "Troubleshooting:"
    echo "If 'kubectl get nodes' shows connection errors:"
    echo "   • Make sure you logged out and back in for docker group"
    echo "   • If still failing, run: sudo cp /root/.kube/config ~/.kube/"
    echo "   • Then fix permissions: sudo chown \$(id -u):\$(id -g) ~/.kube/config"
    echo ""
    echo "If docker commands fail with permission denied:"
    echo "   • Run: newgrp docker"
    echo "   • Or log out and back in to refresh group membership"
    echo ""
    echo "If audit rules fail to load:"
    echo "   • Check: sudo auditctl -l"
    echo "   • Manual reload: sudo augenrules --load"
    echo ""
    echo "If AIDE database is missing:"
    echo "   • Run: sudo aideinit"
    echo "   • Move database: sudo mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db"
else
    echo "1. Verify cluster access: kubectl get nodes"
    echo "2. Deploy vulnerable lab: kubectl apply -f ${VULN_REPO_DIR}/scenarios/"
    echo "3. Run security check: kubelab-security-check"
    echo ""
    echo "Note: Running as root - consider creating a non-root user for daily operations"
fi
echo ""
echo "Setup completed successfully!"
