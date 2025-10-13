#!/usr/bin/env bash
# setup.sh - Enhanced Kubernetes lab setup script for Ubuntu Server 24.04.3 LTS
# - Target: Ubuntu 24.04 LTS (should work on recent LTS versions)
# - Installs: Docker CE, kubectl, kind, Helm, Falco (via Helm), auditd, AIDE
# - Deploys: configurable vulnerable-lab repo (default: kube-goat / kubernetes-goat)
# - Features: Colored output, progress bars, comprehensive logging, zero user interaction
# - Safety: no secrets, no exploit code. Inspect before running.
#
# Usage:
#   git clone https://github.com/JRiesterer/kubelab.git
#   cd kubelab
#   sudo ./setup.sh
#
# IMPORTANT: Inspect and understand this script before executing. Run it from
# a clean snapshot so you can revert if needed.

set -euo pipefail
IFS=$'\n\t'

###
### Configuration (edit variables as needed; avoid secrets here)
###
readonly TARGET_OS="ubuntu"
readonly MIN_UBUNTU_MAJOR=24   # script checks basic compatibility
readonly INSTALL_DIR="/opt/kubelab"   # where we clone demo repos
readonly VULN_REPO_URL="https://github.com/madhuakula/kubernetes-goat.git"  # Kubernetes Goat vulnerable lab
# Alternative repositories if the above is not accessible:
# readonly VULN_REPO_URL="https://github.com/cncf/cnf-testbed.git"
# readonly VULN_REPO_URL="https://github.com/securekubernetes/securekubernetes.git"
readonly VULN_REPO_DIR="${INSTALL_DIR}/kubernetes-goat"
readonly KIND_VERSION="v0.26.0"
readonly KUBECTL_STABLE_URL="https://dl.k8s.io/release/stable.txt"
readonly HELM_GET_SCRIPT="https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3"
readonly DOCKER_GPG_URL="https://download.docker.com/linux/ubuntu/gpg"
readonly APT_RETRY_COUNT=5
readonly APT_RETRY_INTERVAL=5

# Log file configuration
readonly LOGFILE="$(pwd)/setup.log"
readonly SCRIPT_START_TIME=$(date +%s)

# Color definitions for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly WHITE='\033[1;37m'
readonly BOLD='\033[1m'
readonly NC='\033[0m' # No Color

# Progress tracking
readonly TOTAL_STEPS=12
CURRENT_STEP=0

###
### Helper functions
###

# Enhanced logging with color support
log() {
    local timestamp="$(date --iso-8601=seconds)"
    local message="$*"
    
    # Log to file (without colors)
    printf '%s %s\n' "$timestamp" "$message" >> "$LOGFILE"
    
    # Display to console (with colors)
    printf "${CYAN}[%s]${NC} %s\n" "$timestamp" "$message"
}

log_info() {
    local timestamp="$(date --iso-8601=seconds)"
    local message="$*"
    
    printf '%s INFO: %s\n' "$timestamp" "$message" >> "$LOGFILE"
    printf "ℹ %s\n" "$message"
}

log_success() {
    local timestamp="$(date --iso-8601=seconds)"
    local message="$*"
    
    printf '%s SUCCESS: %s\n' "$timestamp" "$message" >> "$LOGFILE"
    printf "✓ %s\n" "$message"
}

log_warning() {
    local timestamp="$(date --iso-8601=seconds)"
    local message="$*"
    
    printf '%s WARNING: %s\n' "$timestamp" "$message" >> "$LOGFILE"
    printf "⚠ %s\n" "$message"
}

log_error() {
    local timestamp="$(date --iso-8601=seconds)"
    local message="$*"
    
    printf '%s ERROR: %s\n' "$timestamp" "$message" >> "$LOGFILE"
    printf "✗ %s\n" "$message"
}

die() { 
    log_error "$*"
    printf "Script failed. Check ${LOGFILE} for details.\n"
    exit 1
}

# Progress bar function
show_progress() {
    local current=$1
    local total=$2
    local step_name="$3"
    local width=50
    local percentage=$((current * 100 / total))
    local completed=$((current * width / total))
    local remaining=$((width - completed))
    
    printf "\rProgress: ["
    printf "%*s" "$completed" "" | tr ' ' '='
    printf "%*s" "$remaining" "" | tr ' ' '-'
    printf "] %d%% - %s" "$percentage" "$step_name"
    
    if [ "$current" -eq "$total" ]; then
        printf "\n"
    fi
}

# Step wrapper function
step() {
    CURRENT_STEP=$((CURRENT_STEP + 1))
    local step_name="$1"
    show_progress "$CURRENT_STEP" "$TOTAL_STEPS" "$step_name"
    log_info "Step $CURRENT_STEP/$TOTAL_STEPS: $step_name"
}

# Enhanced run function with better logging
run() {
    log_info "Executing: $*"
    if "$@" >> "$LOGFILE" 2>&1; then
        log_success "Command completed: $*"
        return 0
    else
        local exit_code=$?
        log_error "Command failed with exit code $exit_code: $*"
        return $exit_code
    fi
}

# Retry function for network operations
retry_command() {
    local max_attempts="$1"
    local delay="$2"
    shift 2
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        if "$@"; then
            return 0
        fi
        log_warning "Attempt $attempt/$max_attempts failed: $*"
        if [ $attempt -lt $max_attempts ]; then
            log_info "Retrying in ${delay}s..."
            sleep "$delay"
        fi
        attempt=$((attempt + 1))
    done
    
    log_error "All $max_attempts attempts failed: $*"
    return 1
}

# Enhanced apt update with retry
apt_update_retry() {
    log_info "Updating package lists..."
    retry_command "$APT_RETRY_COUNT" "$APT_RETRY_INTERVAL" apt-get update -qq
}

# Git clone with non-interactive configuration
git_clone_noninteractive() {
    local repo_url="$1"
    local target_dir="$2"
    local depth="${3:-1}"
    
    log_info "Cloning repository: $repo_url"
    
    # Configure git for non-interactive use
    export GIT_TERMINAL_PROMPT=0
    export GIT_ASKPASS=/bin/true
    export SSH_ASKPASS=/bin/true
    
    # Use HTTPS and disable prompts
    local clone_url="$repo_url"
    if [[ "$clone_url" =~ ^git@ ]]; then
        # Convert SSH to HTTPS
        clone_url=$(echo "$clone_url" | sed 's|git@github.com:|https://github.com/|')
    fi
    
    # Ensure directory exists
    mkdir -p "$(dirname "$target_dir")"
    
    # Clone with specific options to avoid prompts
    git -c advice.detachedHead=false \
        -c init.defaultBranch=main \
        -c user.name="KubeLab Setup" \
        -c user.email="setup@kubelab.local" \
        clone --depth "$depth" --quiet --no-progress \
        "$clone_url" "$target_dir"
}

command_exists() { command -v "$1" >/dev/null 2>&1; }

# Banner function
print_banner() {
    printf "\n"
    printf "╔══════════════════════════════════════════════════════════════════════════════╗\n"
    printf "║                          Kubernetes Security Lab Setup                      ║\n"
    printf "║                         Ubuntu Server 24.04.3 LTS                          ║\n"
    printf "║                                                                              ║\n"
    printf "║  This script will install and configure a complete Kubernetes security      ║\n"
    printf "║  lab environment for evaluating container escape exploits and mitigations. ║\n"
    printf "╚══════════════════════════════════════════════════════════════════════════════╝\n"
    printf "\n"
}

###
### Main script starts here
###

# Print banner
print_banner

# Initialize logging
log_info "Kubernetes Security Lab Setup Starting"
log_info "Log file: $LOGFILE"
log_info "Target OS: $TARGET_OS $MIN_UBUNTU_MAJOR+"
log_info "Installation directory: $INSTALL_DIR"

# Enhanced trap for cleanup
cleanup() {
    local exit_code=$?
    local end_time=$(date +%s)
    local duration=$((end_time - SCRIPT_START_TIME))
    
    if [ $exit_code -eq 0 ]; then
        log_success "Script completed successfully in ${duration} seconds"
        printf "\n✓ Setup completed successfully!\n"
        printf "Check ${LOGFILE} for detailed logs.\n\n"
    else
        log_error "Script failed after ${duration} seconds with exit code $exit_code"
        printf "\n✗ Setup failed!\n"
        printf "Check ${LOGFILE} for error details.\n"
        printf "Last 20 lines of log:\n"
        tail -n 20 "$LOGFILE" 2>/dev/null || true
        printf "\n"
    fi
}

trap cleanup EXIT

###
### Basic preflight checks
###

step "Running preflight checks"

# Must be run as root
if [ "$(id -u)" -ne 0 ]; then
    die "This script must be run with sudo or as root. Run: sudo ./setup.sh"
fi

# OS check (basic)
if [ -f /etc/os-release ]; then
    # shellcheck source=/dev/null
    . /etc/os-release
    log_info "Detected OS: $PRETTY_NAME"
    
    if [[ "${ID}" != "${TARGET_OS}" ]]; then
        log_warning "Expected OS ID=${TARGET_OS}, detected ID=${ID}. Proceeding anyway."
    fi
    
    if [[ "${VERSION_ID%%.*}" -lt "${MIN_UBUNTU_MAJOR}" ]]; then
        die "Ubuntu version ${VERSION_ID} is older than required ${MIN_UBUNTU_MAJOR}. Aborting."
    fi
    
    log_success "OS compatibility check passed"
else
    die "/etc/os-release missing - can't detect OS. Exiting."
fi

# Check network connectivity
log_info "Testing network connectivity..."
if retry_command 3 2 ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1; then
    log_success "Network connectivity confirmed"
else
    die "No network connectivity detected. Ensure the VM has internet access."
fi

# Check available disk space (at least 10GB)
available_space=$(df / | tail -1 | awk '{print $4}')
required_space=$((10 * 1024 * 1024)) # 10GB in KB

if [ "$available_space" -lt "$required_space" ]; then
    log_warning "Available disk space: $((available_space / 1024 / 1024))GB. Recommended: 10GB+"
else
    log_success "Sufficient disk space available: $((available_space / 1024 / 1024))GB"
fi

###
### Install base packages
###

step "Installing base packages"

log_info "Updating package lists and installing base packages..."
apt_update_retry

run apt-get install -y --no-install-recommends \
    ca-certificates curl wget gnupg lsb-release software-properties-common \
    apt-transport-https git sudo unzip net-tools build-essential

log_success "Base packages installed successfully"

###
### Docker CE installation (idempotent)
###

step "Installing Docker CE"

install_docker() {
    if command_exists docker; then
        local docker_version
        docker_version=$(docker --version 2>/dev/null || echo "unknown")
        log_success "Docker already installed: $docker_version"
        return 0
    fi

    log_info "Installing Docker CE..."
    
    # Create directory for GPG keys
    run mkdir -p /etc/apt/keyrings
    
    # Add Docker's official GPG key
    log_info "Adding Docker GPG key..."
    if ! curl -fsSL "${DOCKER_GPG_URL}" | gpg --dearmor -o /etc/apt/keyrings/docker.gpg 2>>"$LOGFILE"; then
        die "Failed to add Docker GPG key"
    fi
    
    # Set proper permissions
    run chmod a+r /etc/apt/keyrings/docker.gpg
    
    # Add Docker repository
    log_info "Adding Docker repository..."
    local arch
    arch=$(dpkg --print-architecture)
    local codename
    codename=$(lsb_release -cs)
    
    echo "deb [arch=${arch} signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu ${codename} stable" | \
        tee /etc/apt/sources.list.d/docker.list > /dev/null

    # Update package lists
    apt_update_retry
    
    # Install Docker packages
    log_info "Installing Docker packages..."
    run apt-get install -y --no-install-recommends \
        docker-ce docker-ce-cli containerd.io docker-compose-plugin
    
    # Enable and start Docker service
    log_info "Enabling and starting Docker service..."
    run systemctl enable docker
    run systemctl start docker
    
    # Verify Docker installation
    if docker --version >>"$LOGFILE" 2>&1; then
        log_success "Docker installed and started successfully"
    else
        die "Docker installation verification failed"
    fi
}

install_docker

# Add non-root user to docker group
log_info "Configuring Docker group membership..."
nonroot_user=$(logname 2>/dev/null || who am i 2>/dev/null | awk '{print $1}' || echo "")

if [ -n "${nonroot_user}" ] && [ "${nonroot_user}" != "root" ]; then
    if getent group docker >/dev/null 2>&1; then
        log_info "Adding user '${nonroot_user}' to docker group..."
        if usermod -aG docker "${nonroot_user}" 2>>"$LOGFILE"; then
            log_success "User '${nonroot_user}' added to docker group"
            log_warning "User must log out and back in for docker group membership to take effect"
        else
            log_warning "Failed to add user to docker group. Manual configuration may be required."
        fi
    fi
else
    log_warning "No non-root user detected for docker group configuration"
fi

###
### kubectl installation (idempotent)
###

step "Installing kubectl"

install_kubectl() {
    if command_exists kubectl; then
        local kubectl_version
        kubectl_version=$(kubectl version --client 2>/dev/null | grep -o 'GitVersion:"[^"]*"' | cut -d'"' -f2 || echo "unknown")
        log_success "kubectl already installed: $kubectl_version"
        return 0
    fi
    
    log_info "Installing kubectl..."
    
    # Get latest stable version
    log_info "Fetching latest stable kubectl version..."
    local stable_version
    if ! stable_version=$(curl -fsSL "${KUBECTL_STABLE_URL}" 2>>"$LOGFILE"); then
        die "Failed to fetch stable kubectl version"
    fi
    
    log_info "Latest stable version: $stable_version"
    
    # Download kubectl binary
    log_info "Downloading kubectl binary..."
    local kubectl_url="https://dl.k8s.io/release/${stable_version}/bin/linux/amd64/kubectl"
    if ! curl -fsSLo /tmp/kubectl "$kubectl_url" 2>>"$LOGFILE"; then
        die "Failed to download kubectl"
    fi
    
    # Install kubectl
    run chmod +x /tmp/kubectl
    run mv /tmp/kubectl /usr/local/bin/kubectl
    
    # Verify installation
    if kubectl version --client >>"$LOGFILE" 2>&1; then
        log_success "kubectl installed successfully"
    else
        die "kubectl installation verification failed"
    fi
}

install_kubectl

###
### kind installation (idempotent)
###

step "Installing kind"

install_kind() {
    if command_exists kind; then
        local kind_version
        kind_version=$(kind --version 2>/dev/null || echo "unknown")
        log_success "kind already installed: $kind_version"
        return 0
    fi
    
    log_info "Installing kind (${KIND_VERSION})..."
    
    # Download kind binary
    local kind_url="https://kind.sigs.k8s.io/dl/${KIND_VERSION}/kind-linux-amd64"
    if ! curl -fsSLo /tmp/kind "$kind_url" 2>>"$LOGFILE"; then
        die "Failed to download kind"
    fi
    
    # Install kind
    run chmod +x /tmp/kind
    run mv /tmp/kind /usr/local/bin/kind
    
    # Verify installation
    if kind --version >>"$LOGFILE" 2>&1; then
        log_success "kind installed successfully"
    else
        die "kind installation verification failed"
    fi
}

install_kind

###
### Helm installation (idempotent)
###

step "Installing Helm"

install_helm() {
    if command_exists helm; then
        local helm_version
        helm_version=$(helm version 2>/dev/null | grep -o 'Version:"[^"]*"' | cut -d'"' -f2 || echo "unknown")
        log_success "Helm already installed: $helm_version"
        return 0
    fi
    
    log_info "Installing Helm..."
    
    # Download and run Helm installation script
    if ! curl -fsSL "${HELM_GET_SCRIPT}" | bash >>"$LOGFILE" 2>&1; then
        die "Helm installation failed"
    fi
    
    # Verify installation
    if helm version >>"$LOGFILE" 2>&1; then
        log_success "Helm installed successfully"
    else
        die "Helm installation verification failed"
    fi
}

install_helm

###
### Create kind cluster (idempotent, safe)
###

step "Creating Kubernetes cluster"

create_kind_cluster() {
    # Check if kubectl is available and configured
    if command_exists kubectl; then
        local current_ctx
        current_ctx=$(kubectl config current-context 2>/dev/null || echo "none")
        
        if [[ "${current_ctx}" == kind-* ]]; then
            log_success "Existing kind cluster detected: $current_ctx"
            
            # Verify cluster is actually accessible
            if kubectl cluster-info >>"$LOGFILE" 2>&1; then
                log_success "Kind cluster is accessible and ready"
                return 0
            else
                log_warning "Kind cluster context exists but cluster is not accessible, recreating..."
            fi
        fi
    fi

    log_info "Creating single-node kind cluster..."
    
    # Ensure installation directory exists
    run mkdir -p "${INSTALL_DIR}"
    
    # Create kind configuration
    log_info "Creating kind cluster configuration..."
    cat > /tmp/kind-config.yaml <<'EOF'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    kubeadmConfigPatches:
    - |
      kind: InitConfiguration
      nodeRegistration:
        kubeletExtraArgs:
          node-labels: "ingress-ready=true"
    extraPortMappings:
    - containerPort: 80
      hostPort: 80
      protocol: TCP
    - containerPort: 443
      hostPort: 443
      protocol: TCP
EOF

    # Create the cluster
    log_info "Creating kind cluster (this may take several minutes)..."
    if run kind create cluster --config /tmp/kind-config.yaml --wait 300s; then
        log_success "Kind cluster created successfully"
        
        # Copy kubeconfig to user's home directory
        if [ -n "${nonroot_user}" ] && [ "${nonroot_user}" != "root" ]; then
            user_home=$(eval echo "~${nonroot_user}")
            if [ -d "${user_home}" ]; then
                log_info "Setting up kubeconfig for user '${nonroot_user}'..."
                if run mkdir -p "${user_home}/.kube"; then
                    if run cp /root/.kube/config "${user_home}/.kube/config"; then
                        if run chown -R "${nonroot_user}:${nonroot_user}" "${user_home}/.kube"; then
                            log_success "Kubeconfig configured for user '${nonroot_user}'"
                        else
                            log_warning "Failed to set kubeconfig ownership"
                        fi
                    else
                        log_warning "Failed to copy kubeconfig"
                    fi
                else
                    log_warning "Failed to create .kube directory"
                fi
            fi
        fi
    else
        die "Failed to create kind cluster"
    fi
    
    # Verify cluster is ready
    log_info "Verifying cluster status..."
    local retries=30
    while [ $retries -gt 0 ]; do
        if kubectl cluster-info >>"$LOGFILE" 2>&1 && kubectl get nodes >>"$LOGFILE" 2>&1; then
            log_success "Kubernetes cluster is ready and accessible"
            return 0
        fi
        retries=$((retries - 1))
        log_info "Waiting for cluster to be ready... ($retries attempts remaining)"
        sleep 10
    done
    
    die "Cluster creation succeeded but cluster is not accessible"
}

create_kind_cluster

###
### Deploy vulnerable-lab repository
###

step "Setting up vulnerable lab repository"

deploy_vuln_repo() {
    local repo_exists=false
    
    if [ -d "${VULN_REPO_DIR}" ]; then
        log_info "Vulnerable lab repo directory exists: ${VULN_REPO_DIR}"
        
        if [ -d "${VULN_REPO_DIR}/.git" ]; then
            log_info "Existing git repository found, attempting to update..."
            repo_exists=true
            
            # Configure git for the existing repo
            git -C "${VULN_REPO_DIR}" config --local advice.detachedHead false 2>>"$LOGFILE" || true
            git -C "${VULN_REPO_DIR}" config --local user.name "KubeLab Setup" 2>>"$LOGFILE" || true
            git -C "${VULN_REPO_DIR}" config --local user.email "setup@kubelab.local" 2>>"$LOGFILE" || true
            
            # Try to update the repository
            if git -C "${VULN_REPO_DIR}" pull --ff-only >>"$LOGFILE" 2>&1; then
                log_success "Repository updated successfully"
            else
                log_warning "Failed to update repository, will use existing version"
            fi
        else
            log_warning "Directory exists but is not a git repository, removing and re-cloning..."
            run rm -rf "${VULN_REPO_DIR}"
        fi
    fi
    
    if [ "$repo_exists" = false ]; then
        log_info "Cloning vulnerable lab repository..."
        if git_clone_noninteractive "${VULN_REPO_URL}" "${VULN_REPO_DIR}" 1; then
            log_success "Repository cloned successfully"
        else
            die "Failed to clone vulnerable lab repository"
        fi
    fi

    # List available manifests for reference
    log_info "Scanning for Kubernetes manifests..."
    local manifest_count=0
    
    for manifest_dir in "${VULN_REPO_DIR}/deploy" "${VULN_REPO_DIR}/manifests" "${VULN_REPO_DIR}/k8s"; do
        if [ -d "$manifest_dir" ]; then
            local found_manifests
            found_manifests=$(find "$manifest_dir" -maxdepth 2 -type f \( -name '*.yaml' -o -name '*.yml' \) 2>/dev/null | wc -l)
            if [ "$found_manifests" -gt 0 ]; then
                log_info "Found $found_manifests manifest files in $manifest_dir"
                manifest_count=$((manifest_count + found_manifests))
            fi
        fi
    done
    
    if [ "$manifest_count" -gt 0 ]; then
        log_success "Found $manifest_count total Kubernetes manifest files"
        log_warning "Review manifests before applying: ls -la ${VULN_REPO_DIR}/deploy/ ${VULN_REPO_DIR}/manifests/ ${VULN_REPO_DIR}/k8s/ 2>/dev/null"
    else
        log_info "No standard manifest directories found. Check repository documentation for deployment instructions."
    fi
}

deploy_vuln_repo

###
### Falco installation via Helm
###

step "Installing Falco security monitoring"

install_falco() {
    # Check if Falco is already installed
    if kubectl get ns falco >>"$LOGFILE" 2>&1; then
        log_success "Falco namespace already exists, checking installation..."
        
        local falco_pods
        falco_pods=$(kubectl get pods -n falco -l app.kubernetes.io/name=falco --no-headers 2>/dev/null | wc -l)
        
        if [ "$falco_pods" -gt 0 ]; then
            log_success "Falco is already installed and running"
            return 0
        else
            log_warning "Falco namespace exists but no pods found, reinstalling..."
        fi
    fi

    if ! command_exists helm; then
        log_error "Helm not available, skipping Falco installation"
        return 1
    fi

    log_info "Installing Falco via Helm..."
    
    # Add Falco Helm repository
    log_info "Adding Falco Helm repository..."
    if run helm repo add falcosecurity https://falcosecurity.github.io/charts; then
        log_success "Falco Helm repository added"
    else
        log_error "Failed to add Falco Helm repository"
        return 1
    fi
    
    # Update Helm repositories
    if run helm repo update; then
        log_success "Helm repositories updated"
    else
        log_warning "Failed to update Helm repositories, continuing anyway"
    fi
    
    # Install Falco with appropriate configuration for kind
    log_info "Installing Falco (this may take a few minutes)..."
    
    if run helm install falco falcosecurity/falco \
        --namespace falco \
        --create-namespace \
        --set falco.driver.kind=ebpf \
        --set falco.driver.ebpf.leastPrivileged=true \
        --wait --timeout=300s; then
        log_success "Falco installed successfully"
        
        # Verify Falco is running
        log_info "Verifying Falco installation..."
        local retries=10
        while [ $retries -gt 0 ]; do
            local running_pods
            running_pods=$(kubectl get pods -n falco -l app.kubernetes.io/name=falco --field-selector=status.phase=Running --no-headers 2>/dev/null | wc -l)
            
            if [ "$running_pods" -gt 0 ]; then
                log_success "Falco is running successfully"
                return 0
            fi
            
            retries=$((retries - 1))
            log_info "Waiting for Falco pods to be ready... ($retries attempts remaining)"
            sleep 10
        done
        
        log_warning "Falco installed but pods may not be ready yet. Check with: kubectl get pods -n falco"
    else
        log_warning "Falco installation failed. This may be due to kernel compatibility issues."
        log_info "Check kernel modules: lsmod | grep falco"
        log_info "Manual installation may be required for some kernel configurations"
    fi
}

install_falco

###
### Host-level security tools installation
###

step "Installing host security tools (auditd & AIDE)"

setup_host_audit_and_fim() {
    log_info "Installing auditd and AIDE for host-level security monitoring..."
    
    # Install packages
    if run apt-get install -y --no-install-recommends auditd audispd-plugins aide; then
        log_success "Security packages installed successfully"
    else
        die "Failed to install security packages"
    fi
    
    # Configure and start auditd
    log_info "Configuring auditd service..."
    if run systemctl enable auditd; then
        log_success "auditd service enabled"
    else
        log_warning "Failed to enable auditd service"
    fi
    
    if run systemctl start auditd; then
        log_success "auditd service started"
    else
        log_warning "Failed to start auditd service"
    fi
    
    # Configure AIDE (File Integrity Monitoring)
    log_info "Setting up AIDE file integrity monitoring..."
    
    if [ ! -f /var/lib/aide/aide.db ]; then
        log_info "Initializing AIDE database (this may take several minutes)..."
        
        # Initialize AIDE database
        if /usr/bin/aideinit >>"$LOGFILE" 2>&1; then
            log_success "AIDE database initialized"
            
            # Move the new database to the expected location
            if [ -f /var/lib/aide/aide.db.new ]; then
                if run mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db; then
                    log_success "AIDE database activated"
                else
                    log_warning "Failed to move AIDE database"
                fi
            fi
        else
            log_warning "AIDE initialization failed - check kernel modules and filesystem support"
        fi
    else
        log_success "AIDE database already exists"
    fi

    # Create audit rules for container security monitoring
    log_info "Creating audit rules for container monitoring..."
    local audit_rule="/etc/audit/rules.d/99-kubelab-container.rules"
    
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

        log_success "Audit rules created: $audit_rule"
        
        # Load the new audit rules
        log_info "Loading audit rules..."
        if augenrules --load >>"$LOGFILE" 2>&1; then
            log_success "Audit rules loaded successfully"
        else
            log_warning "Failed to load audit rules - check auditd configuration"
        fi
        
        # Restart auditd to ensure rules are active
        if systemctl restart auditd >>"$LOGFILE" 2>&1; then
            log_success "auditd restarted with new rules"
        else
            log_warning "Failed to restart auditd"
        fi
    else
        log_success "Audit rules already exist: $audit_rule"
    fi
    
    # Verify audit rules are loaded
    log_info "Verifying audit configuration..."
    local active_rules
    active_rules=$(auditctl -l 2>/dev/null | grep -c kubelab || echo "0")
    
    if [ "$active_rules" -gt 0 ]; then
        log_success "Found $active_rules active KubeLab audit rules"
    else
        log_warning "No KubeLab audit rules found active - manual verification may be needed"
    fi
}

setup_host_audit_and_fim

###
### Additional security tools and configurations
###

step "Configuring additional security features"

setup_additional_security() {
    log_info "Configuring additional security features..."
    
    # Install additional useful tools for security analysis
    log_info "Installing additional security analysis tools..."
    local security_tools=(
        "strace"         # System call tracing
        "ltrace"         # Library call tracing  
        "tcpdump"        # Network packet capture
        "netstat-nat"    # Network statistics
        "lsof"          # List open files
        "psmisc"        # Process utilities (pstree, killall, etc.)
        "procps"        # Process monitoring tools
        "sysstat"       # System performance tools
        "htop"          # Interactive process viewer
    )
    
    if run apt-get install -y --no-install-recommends "${security_tools[@]}"; then
        log_success "Additional security tools installed"
    else
        log_warning "Some security tools may not have been installed correctly"
    fi
    
    # Configure system limits for better container security
    log_info "Configuring system security limits..."
    local limits_file="/etc/security/limits.d/99-kubelab.conf"
    
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
        log_success "System security limits configured: $limits_file"
    else
        log_success "System security limits already configured"
    fi
    
    # Enable core dump restrictions
    log_info "Configuring core dump security..."
    if ! grep -q "kernel.core_pattern" /etc/sysctl.conf 2>/dev/null; then
        echo "# KubeLab core dump security" >> /etc/sysctl.conf
        echo "kernel.core_pattern=|/bin/false" >> /etc/sysctl.conf
        echo "fs.suid_dumpable=0" >> /etc/sysctl.conf
        sysctl -p >>"$LOGFILE" 2>&1 || log_warning "Failed to apply sysctl settings"
        log_success "Core dump security configured"
    else
        log_success "Core dump security already configured"
    fi
    
    # Set up log rotation for our custom log file
    log_info "Configuring log rotation..."
    local logrotate_file="/etc/logrotate.d/kubelab"
    
    if [ ! -f "$logrotate_file" ]; then
        cat > "$logrotate_file" <<EOF
$LOGFILE {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 644 root root
}
EOF
        log_success "Log rotation configured for KubeLab logs"
    else
        log_success "Log rotation already configured"
    fi
}

setup_additional_security

###
### Final verification and cleanup
###

step "Running final verification"

final_verification() {
    log_info "Running final system verification..."
    
    local verification_failed=false
    
    # Verify Docker
    if command_exists docker && docker --version >>"$LOGFILE" 2>&1; then
        log_success "Docker verification passed"
    else
        log_error "Docker verification failed"
        verification_failed=true
    fi
    
    # Verify kubectl
    if command_exists kubectl && kubectl version --client >>"$LOGFILE" 2>&1; then
        log_success "kubectl verification passed"
    else
        log_error "kubectl verification failed"
        verification_failed=true
    fi
    
    # Verify kind
    if command_exists kind && kind --version >>"$LOGFILE" 2>&1; then
        log_success "kind verification passed"
    else
        log_error "kind verification failed"
        verification_failed=true
    fi
    
    # Verify Helm
    if command_exists helm && helm version >>"$LOGFILE" 2>&1; then
        log_success "Helm verification passed"
    else
        log_error "Helm verification failed"
        verification_failed=true
    fi
    
    # Verify Kubernetes cluster
    if kubectl cluster-info >>"$LOGFILE" 2>&1; then
        log_success "Kubernetes cluster verification passed"
        
        # Get cluster info for the log
        log_info "Cluster information:"
        kubectl get nodes -o wide >>"$LOGFILE" 2>&1 || true
        kubectl get pods --all-namespaces >>"$LOGFILE" 2>&1 || true
    else
        log_error "Kubernetes cluster verification failed"
        verification_failed=true
    fi
    
    # Verify vulnerable lab repository
    if [ -d "${VULN_REPO_DIR}" ] && [ -d "${VULN_REPO_DIR}/.git" ]; then
        log_success "Vulnerable lab repository verification passed"
    else
        log_error "Vulnerable lab repository verification failed"
        verification_failed=true
    fi
    
    # Verify auditd
    if systemctl is-active auditd >>"$LOGFILE" 2>&1; then
        log_success "auditd service verification passed"
    else
        log_warning "auditd service verification failed"
    fi
    
    # Check Falco status
    local falco_pods
    falco_pods=$(kubectl get pods -n falco --no-headers 2>/dev/null | wc -l)
    if [ "$falco_pods" -gt 0 ]; then
        log_success "Falco deployment verification passed ($falco_pods pods)"
    else
        log_warning "Falco deployment verification failed (no pods found)"
    fi
    
    if [ "$verification_failed" = true ]; then
        log_error "Some components failed verification - check logs for details"
        return 1
    else
        log_success "All critical components verified successfully"
        return 0
    fi
}

final_verification

###
### Success summary and next steps
###

log_success "Kubernetes Security Lab setup completed successfully!"

# Generate compact summary report
printf "\n"
printf "╔══════════════════════════════════════════════════════════════════════════════╗\n"
printf "║                           SETUP COMPLETED SUCCESSFULLY                      ║\n"
printf "╚══════════════════════════════════════════════════════════════════════════════╝\n"
printf "\n"

printf "Installation Summary:\n"
printf "├─ ✓ Docker CE: %s\n" "$(docker --version 2>/dev/null | cut -d' ' -f1-3 || echo "Check failed")"
printf "├─ ✓ kubectl: %s\n" "$(kubectl version --client 2>/dev/null | grep -o 'GitVersion:"[^"]*"' | cut -d'"' -f2 || echo "Check failed")"
printf "├─ ✓ kind: %s\n" "$(kind --version 2>/dev/null || echo "Check failed")"
printf "├─ ✓ Helm: %s\n" "$(helm version 2>/dev/null | grep -o 'Version:"[^"]*"' | cut -d'"' -f2 || echo "Check failed")"
printf "├─ ✓ Kubernetes Cluster: %s\n" "$(kubectl config current-context 2>/dev/null || echo "No context")"
printf "├─ ✓ Falco Security: %s pods deployed\n" "$(kubectl get pods -n falco --no-headers 2>/dev/null | wc -l)"
printf "├─ ✓ Vulnerable Lab Repo: %s\n" "${VULN_REPO_DIR}"
printf "├─ ✓ auditd: %s\n" "$(systemctl is-active auditd 2>/dev/null || echo "inactive")"
printf "└─ ✓ AIDE: %s\n" "$([ -f /var/lib/aide/aide.db ] && echo "configured" || echo "check manual setup")"

printf "\nImportant Next Steps:\n"
printf "\n1. Restart Terminal Session:\n"
printf "   # Log out and back in to refresh docker group membership\n"
printf "   # Or run: newgrp docker\n"

printf "\n2. Verify Cluster Access:\n"
printf "   kubectl cluster-info\n"
printf "   kubectl get nodes\n"
printf "   kubectl get pods --all-namespaces\n"
printf "\n   If kubectl shows connection refused errors:\n"
printf "   sudo cp /root/.kube/config ~/.kube/config\n"
printf "   sudo chown \$(id -u):\$(id -g) ~/.kube/config\n"
printf "   kubectl get pods --all-namespaces\n"

printf "\n3. Deploy Vulnerable Applications:\n"
printf "   # IMPORTANT: Review manifests before applying!\n"
printf "   ls -la %s/deploy/ %s/manifests/ 2>/dev/null\n" "${VULN_REPO_DIR}" "${VULN_REPO_DIR}"
printf "   \n"
printf "   # After review, deploy:\n"
printf "   kubectl apply -f %s/deploy/  # (adjust path as needed)\n" "${VULN_REPO_DIR}"

printf "\n4. Monitor Security Events:\n"
printf "   # View Falco security alerts:\n"
printf "   kubectl logs -n falco -l app.kubernetes.io/name=falco -f\n"
printf "   \n"
printf "   # View audit logs:\n"
printf "   ausearch -k kubelab_docker\n"
printf "   tail -f /var/log/audit/audit.log | grep kubelab\n"

printf "\n5. Create System Snapshot:\n"
printf "   # Take a VM snapshot now for easy reset between exercises\n"
printf "   # Name suggestion: kubelab_ready_$(date +%%Y%%m%%d)\n"

printf "\nLog Files:\n"
printf "├─ Setup Log: %s\n" "${LOGFILE}"
printf "├─ Audit Log: /var/log/audit/audit.log\n"
printf "└─ Container Logs: kubectl logs -n <namespace> <pod>\n"

printf "\nSecurity Reminder:\n"
printf "This environment contains intentionally vulnerable applications.\n"
printf "Only use this in isolated lab environments. Never expose to production networks.\n"
printf "\n"

# Log final completion time
end_time=$(date +%s)
duration=$((end_time - SCRIPT_START_TIME))
log_success "Total setup time: ${duration} seconds"

exit 0
