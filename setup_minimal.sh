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
### Install Falco (optional - non-blocking)
###
echo "Installing Falco runtime security..."
if kubectl get ns falco >/dev/null 2>&1; then
    echo "✓ Falco already installed"
else
    helm repo add falcosecurity https://falcosecurity.github.io/charts 2>/dev/null || true
    helm repo update 2>/dev/null || true
    
    if helm install falco falcosecurity/falco \
        --namespace falco \
        --create-namespace \
        --set falco.driver.kind=ebpf \
        --wait --timeout=300s 2>/dev/null; then
        echo "✓ Falco installed"
    else
        echo "⚠ Falco installation failed (continuing without it)"
    fi
fi

###
### Install basic audit tools
###
echo "Installing audit tools..."
apt-get install -y --no-install-recommends auditd aide 2>/dev/null || echo "⚠ Some audit tools may not be available"
systemctl enable auditd 2>/dev/null || true
systemctl start auditd 2>/dev/null || true
echo "✓ Audit tools configured"

###
### Final verification
###
echo "Running final verification..."
docker --version >/dev/null || { echo "ERROR: Docker verification failed"; exit 1; }
kubectl version --client >/dev/null || { echo "ERROR: kubectl verification failed"; exit 1; }
kind --version >/dev/null || { echo "ERROR: kind verification failed"; exit 1; }
helm version >/dev/null || { echo "ERROR: Helm verification failed"; exit 1; }
kubectl cluster-info >/dev/null || { echo "ERROR: Cluster verification failed"; exit 1; }

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
echo "└─ Vulnerable lab: ${VULN_REPO_DIR}"
echo ""
echo "Next steps:"
echo "1. Log out and back in (or run: newgrp docker)"
echo "2. Verify: kubectl get nodes"
echo "3. Deploy lab: kubectl apply -f ${VULN_REPO_DIR}/deploy/"
echo ""
echo "Setup completed successfully!"
