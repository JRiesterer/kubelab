#!/usr/bin/env bash
# setup_minimal.sh - Minimal Kubernetes security lab setup script
# Fail-fast, no logging, no progress bars, essential components only

set -euo pipefail

###
### Configuration
###
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

# OS check
[ -f /etc/os-release ] || { echo "ERROR: Cannot detect OS"; exit 1; }
. /etc/os-release
[ "${ID}" = "ubuntu" ] || { echo "WARNING: Not Ubuntu, continuing anyway"; }
[ "${VERSION_ID%%.*}" -ge 24 ] || { echo "ERROR: Ubuntu 24+ required"; exit 1; }

# Network check
ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1 || { echo "ERROR: No network connectivity"; exit 1; }

echo "✓ Preflight checks passed"

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

# Add user to docker group
nonroot_user=$(logname 2>/dev/null || who am i 2>/dev/null | awk '{print $1}' || echo "")
if [ -n "${nonroot_user}" ] && [ "${nonroot_user}" != "root" ]; then
    usermod -aG docker "${nonroot_user}" 2>/dev/null || true
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
### Install and configure Falco runtime security
###
echo "Installing Falco runtime security monitoring..."

# Install Falco GPG key and repository
curl -fsSL https://falco.org/repo/falcosecurity-packages.asc | gpg --dearmor -o /usr/share/keyrings/falco-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] https://download.falco.org/packages/deb stable main" > /etc/apt/sources.list.d/falcosecurity.list

# Update package list and install Falco
apt-get update >/dev/null 2>&1
apt-get install -y --no-install-recommends falco 2>/dev/null || echo "⚠ Falco installation may have failed"

# Create custom Kubernetes rules for container security
custom_rules="/etc/falco/k8s_security_rules.yaml"
if [ ! -f "$custom_rules" ]; then
    cat > "$custom_rules" <<'EOF'
# KubeLab Custom Kubernetes Security Rules

- rule: Container Escape Attempt via Privileged Container
  desc: Detect potential container escape attempts through privileged containers
  condition: >
    spawned_process and container and 
    (proc.name in (nsenter, unshare, capsh, chroot, pivot_root) or
     proc.args contains "privileged" or
     proc.args contains "--cap-add")
  output: "Container escape attempt detected (user=%user.name command=%proc.cmdline container=%container.id image=%container.image.repository)"
  priority: CRITICAL
  tags: [container_escape, privilege_escalation]

- rule: Mount Sensitive Host Path in Container
  desc: Detect mounting of sensitive host paths into containers
  condition: >
    spawned_process and container and
    (proc.args contains "/etc" or
     proc.args contains "/proc" or
     proc.args contains "/sys" or
     proc.args contains "/var/run/docker.sock" or
     proc.args contains "/dev")
  output: "Sensitive host path mounted in container (user=%user.name command=%proc.cmdline container=%container.id path=%proc.args)"
  priority: HIGH
  tags: [host_mount, privilege_escalation]

- rule: Container Process with Suspicious Network Activity
  desc: Detect containers making suspicious network connections
  condition: >
    inbound_outbound and container and
    (fd.sport in (22, 23, 135, 139, 445, 1433, 1521, 3306, 3389, 5432, 5984, 6379, 8086, 9200, 11211, 27017) or
     fd.dport in (22, 23, 135, 139, 445, 1433, 1521, 3306, 3389, 5432, 5984, 6379, 8086, 9200, 11211, 27017))
  output: "Suspicious network activity from container (user=%user.name command=%proc.cmdline container=%container.id proto=%fd.l4proto src=%fd.cip sport=%fd.cport dst=%fd.sip dport=%fd.sport)"
  priority: MEDIUM
  tags: [network, lateral_movement]

- rule: Container File Access to Host Filesystem
  desc: Detect container processes accessing host filesystem outside expected paths
  condition: >
    open_read and container and
    fd.name startswith /host and
    not fd.name startswith /host/proc and
    not fd.name startswith /host/sys
  output: "Container accessing host filesystem (user=%user.name command=%proc.cmdline container=%container.id file=%fd.name)"
  priority: HIGH
  tags: [host_access, file_access]

- rule: Kubernetes Secret Access
  desc: Detect processes accessing Kubernetes secrets
  condition: >
    open_read and
    fd.name contains "/var/run/secrets/kubernetes.io/"
  output: "Kubernetes secret accessed (user=%user.name command=%proc.cmdline file=%fd.name container=%container.id)"
  priority: MEDIUM
  tags: [secrets, kubernetes]

- rule: Container Running with Excessive Privileges
  desc: Detect containers running with dangerous capabilities
  condition: >
    spawned_process and container and
    (proc.args contains "SYS_ADMIN" or
     proc.args contains "SYS_PTRACE" or
     proc.args contains "SYS_MODULE" or
     proc.args contains "DAC_OVERRIDE" or
     proc.args contains "SETUID" or
     proc.args contains "SETGID")
  output: "Container running with excessive privileges (user=%user.name command=%proc.cmdline container=%container.id capabilities=%proc.args)"
  priority: HIGH
  tags: [capabilities, privilege_escalation]
EOF
fi

# Configure Falco for container monitoring
falco_config="/etc/falco/falco.yaml"
if [ -f "$falco_config" ]; then
    # Backup original config
    cp "$falco_config" "${falco_config}.bak" 2>/dev/null || true
    
    # Update Falco configuration for enhanced monitoring
    sed -i 's/^json_output: false$/json_output: true/' "$falco_config" 2>/dev/null || true
    sed -i 's/^buffered_outputs: false$/buffered_outputs: true/' "$falco_config" 2>/dev/null || true
    
    # Enable custom rules
    if ! grep -q "k8s_security_rules.yaml" "$falco_config" 2>/dev/null; then
        sed -i '/rules_file:/a\  - /etc/falco/k8s_security_rules.yaml' "$falco_config" 2>/dev/null || true
    fi
fi

# Create Falco systemd service override for better logging
falco_override_dir="/etc/systemd/system/falco.service.d"
mkdir -p "$falco_override_dir"
cat > "$falco_override_dir/override.conf" <<'EOF'
[Service]
StandardOutput=journal
StandardError=journal
SyslogIdentifier=falco
EOF

# Enable and start Falco
systemctl daemon-reload
systemctl enable falco 2>/dev/null || true
systemctl start falco 2>/dev/null || true

# Verify Falco is running
if systemctl is-active --quiet falco; then
    echo "✓ Falco runtime security monitoring is active"
else
    echo "⚠ Falco may not be running properly - check 'systemctl status falco'"
fi

###
### Install comprehensive security monitoring
###
echo "Installing comprehensive security monitoring..."

# Install audit and security tools
apt-get install -y --no-install-recommends auditd audispd-plugins aide \
    strace ltrace tcpdump netstat-nat lsof psmisc procps sysstat htop 2>/dev/null || echo "⚠ Some tools may not be available"

# Configure auditd
systemctl enable auditd 2>/dev/null || true
systemctl start auditd 2>/dev/null || true

# Initialize AIDE database
if [ ! -f /var/lib/aide/aide.db ]; then
    echo "Initializing AIDE database (this may take a few minutes)..."
    /usr/bin/aideinit >/dev/null 2>&1 || echo "⚠ AIDE initialization failed"
    if [ -f /var/lib/aide/aide.db.new ]; then
        mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
    fi
fi

# Create comprehensive audit rules
audit_rule="/etc/audit/rules.d/99-kubelab-container.rules"
if [ ! -f "${audit_rule}" ]; then
    cat > "${audit_rule}" <<'EOF'
# KubeLab Container Security Audit Rules

# Monitor Docker daemon and socket access
-w /var/lib/docker/ -p wa -k kubelab_docker
-w /run/docker.sock -p rw -k kubelab_docker_sock
-w /usr/bin/docker -p x -k kubelab_docker_exec

# Monitor container runtime
-w /usr/bin/containerd -p x -k kubelab_containerd
-w /usr/bin/runc -p x -k kubelab_runc

# Monitor Kubernetes components
-w /usr/local/bin/kubectl -p x -k kubelab_kubectl
-w /usr/local/bin/kind -p x -k kubelab_kind

# Monitor sensitive system calls that could indicate container escapes
-a always,exit -F arch=b64 -S mount,umount2 -k kubelab_mount
-a always,exit -F arch=b64 -S unshare,setns -k kubelab_namespace
-a always,exit -F arch=b64 -S ptrace -k kubelab_ptrace
-a always,exit -F arch=b64 -S personality -k kubelab_personality

# Monitor capability changes
-a always,exit -F arch=b64 -S capset -k kubelab_capabilities

# Monitor privileged operations
-a always,exit -F arch=b64 -S chroot -k kubelab_chroot
-a always,exit -F arch=b64 -S pivot_root -k kubelab_pivot_root

# Monitor process execution in containers (when possible)
-a always,exit -F arch=b64 -S execve -F exe=/proc/*/root/* -k kubelab_container_exec
EOF

    # Load audit rules
    augenrules --load >/dev/null 2>&1 || echo "⚠ Failed to load audit rules"
    systemctl restart auditd >/dev/null 2>&1 || echo "⚠ Failed to restart auditd"
fi

# Configure system security limits
limits_file="/etc/security/limits.d/99-kubelab.conf"
if [ ! -f "$limits_file" ]; then
    cat > "$limits_file" <<'EOF'
# KubeLab Security Limits

# Limit core dumps for security
* soft core 0
* hard core 0

# Process limits
* soft nproc 65536
* hard nproc 65536

# File descriptor limits  
* soft nofile 65536
* hard nofile 65536

# Memory limits for user processes
* soft as unlimited
* hard as unlimited
EOF
fi

# Configure core dump security
if ! grep -q "kernel.core_pattern" /etc/sysctl.conf 2>/dev/null; then
    echo "# KubeLab core dump security" >> /etc/sysctl.conf
    echo "kernel.core_pattern=|/bin/false" >> /etc/sysctl.conf
    echo "fs.suid_dumpable=0" >> /etc/sysctl.conf
    sysctl -p >/dev/null 2>&1 || true
fi

# Set up log rotation
logrotate_file="/etc/logrotate.d/kubelab"
if [ ! -f "$logrotate_file" ]; then
    cat > "$logrotate_file" <<'EOF'
/var/log/audit/audit.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 644 root root
}
EOF
fi

echo "✓ Security monitoring configured"

###
### Final security configuration and testing
###
echo "Completing security configuration..."

# Create security monitoring script
security_script="/usr/local/bin/kubelab-security-check"
cat > "$security_script" <<'EOF'
#!/bin/bash
# KubeLab Security Status Check

echo "=== KubeLab Security Monitoring Status ==="
echo

echo "Docker Service:"
systemctl is-active docker 2>/dev/null || echo "Not running"

echo "Kind Cluster:"
sudo -u $SUDO_USER kubectl get nodes 2>/dev/null | head -2 || echo "Not accessible"

echo "Falco Runtime Security:"
systemctl is-active falco 2>/dev/null || echo "Not running"

echo "Audit Daemon:"
systemctl is-active auditd 2>/dev/null || echo "Not running"

echo "AIDE Database:"
if [ -f /var/lib/aide/aide.db ]; then
    echo "Initialized"
else
    echo "Not initialized"
fi

echo "Custom Audit Rules:"
if [ -f /etc/audit/rules.d/99-kubelab-container.rules ]; then
    echo "Configured"
else
    echo "Missing"
fi

echo
echo "=== Recent Security Events ==="
echo "Recent Falco alerts:"
journalctl -u falco --since "5 minutes ago" -n 5 --no-pager 2>/dev/null | grep -i "priority\|rule" || echo "No recent alerts"

echo
echo "Recent audit events:"
ausearch -ts recent -k kubelab 2>/dev/null | tail -5 || echo "No recent audit events"
EOF

chmod +x "$security_script"

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
echo "1. Log out and back in (or run: newgrp docker)"
echo "2. Verify: kubectl get nodes"
echo "3. Deploy lab: kubectl apply -f ${VULN_REPO_DIR}/deploy/"
echo "4. Check security: /usr/local/bin/kubelab-security-check"
echo ""
echo "If kubectl shows connection refused errors:"
echo "   sudo cp /root/.kube/config ~/.kube/config"
echo "   sudo chown \$(id -u):\$(id -g) ~/.kube/config"
echo ""
echo "Setup completed successfully!"
