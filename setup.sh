#!/usr/bin/env bash
# provision.sh - generic, idempotent provisioning for Kubernetes lab (Ubuntu)
# - Target: Ubuntu 24.04 LTS (should work on recent LTS versions)
# - Installs: Docker CE, kubectl, kind, Helm, Falco (via Helm), auditd, AIDE (optional)
# - Deploys: configurable vulnerable-lab repo (default: kube-goat / kubernetes-goat)
# - Safety: no secrets, no exploit code. Inspect before running.
#
# Usage:
#   git clone https://github.com/JRiesterer/kubelab.git
#   cd kubelab
#   sudo ./provision.sh 2>&1 | tee /var/log/provision.log
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
readonly VULN_REPO_URL="https://github.com/kubernetes/goat.git"  # change if you prefer
readonly VULN_REPO_DIR="${INSTALL_DIR}/kube-goat"
readonly KIND_VERSION="v0.26.0"
readonly KUBECTL_STABLE_URL="https://dl.k8s.io/release/stable.txt"
readonly HELM_GET_SCRIPT="https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3"
readonly DOCKER_GPG_URL="https://download.docker.com/linux/ubuntu/gpg"
readonly DOCKER_AWKARCH_CMD='dpkg --print-architecture'
readonly APT_RETRY_COUNT=5
readonly APT_RETRY_INTERVAL=5

LOGFILE="/var/log/provision_kubelab.log"

###
### Helper functions
###
log() { printf '%s %s\n' "$(date --iso-8601=seconds)" "$*"; }
die() { log "ERROR: $*"; exit 1; }

run() {
  log "+ $*"
  "$@"
}

apt_update_retry() {
  local i=0
  until sudo apt-get update -y; do
    ((i++))
    if (( i >= APT_RETRY_COUNT )); then
      die "apt-get update failed after ${APT_RETRY_COUNT} attempts"
    fi
    log "apt-get update failed; retrying in ${APT_RETRY_INTERVAL}s... ($i)"
    sleep "${APT_RETRY_INTERVAL}"
  done
}

command_exists() { command -v "$1" >/dev/null 2>&1; }

###
### Basic preflight checks
###
trap 'log "Script aborted or failed. See ${LOGFILE}"; tail -n 100 ${LOGFILE} || true' EXIT

log "Provisioning started"
mkdir -p "$(dirname "${LOGFILE}")"
touch "${LOGFILE}"
exec > >(tee -a "${LOGFILE}") 2>&1

# Must be run as root (script uses sudo internally but many installs need root)
if [ "$(id -u)" -ne 0 ]; then
  die "This script must be run with sudo or as root. Run: sudo ./provision.sh"
fi

# OS check (basic)
if [ -f /etc/os-release ]; then
  . /etc/os-release
  if [[ "${ID}" != "${TARGET_OS}" ]]; then
    log "Warning: expected OS ID=${TARGET_OS}, detected ID=${ID}. Proceeding anyway."
  fi
  if [[ "${VERSION_ID%%.*}" -lt "${MIN_UBUNTU_MAJOR}" ]]; then
    die "Ubuntu version ${VERSION_ID} is older than required ${MIN_UBUNTU_MAJOR}. Aborting."
  fi
else
  die "/etc/os-release missing - can't detect OS. Exiting."
fi

# Check network connectivity (we need internet for installs)
if ! ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1; then
  die "No network connectivity detected. Ensure the VM has internet access for provisioning."
fi

###
### Install base packages
###
log "Installing base packages..."
apt_update_retry
run apt-get install -y --no-install-recommends \
  ca-certificates curl wget gnupg lsb-release software-properties-common \
  apt-transport-https git sudo unzip net-tools

###
### Docker CE installation (idempotent)
###
install_docker() {
  if command_exists docker; then
    log "Docker appears to be installed ($(docker --version)). Skipping Docker install."
    return
  fi

  log "Installing Docker CE..."
  run mkdir -p /etc/apt/keyrings
  run curl -fsSL "${DOCKER_GPG_URL}" | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  # Build sources.list line safely
  arch=$(dpkg --print-architecture)
  echo \
    "deb [arch=${arch} signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
    $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null

  apt_update_retry
  run apt-get install -y --no-install-recommends docker-ce docker-ce-cli containerd.io docker-compose-plugin
  run systemctl enable --now docker
  log "Docker installed and started."
}

install_docker

# Ensure the ubuntu user (or first non-root) is added to docker group if present
# We avoid hardcoding usernames; try to detect a sensible non-root user
nonroot_user=$(logname 2>/dev/null || true)
if [ -n "${nonroot_user}" ] && [ "${nonroot_user}" != "root" ]; then
  if getent group docker >/dev/null 2>&1; then
    log "Adding user '${nonroot_user}' to docker group (if not already)."
    usermod -aG docker "${nonroot_user}" || log "usermod returned non-zero; check user membership manually."
  fi
else
  log "No non-root user detected to add to docker group automatically."
fi

###
### kubectl installation (idempotent)
###
install_kubectl() {
  if command_exists kubectl; then
    log "kubectl already installed: $(kubectl version --client --short 2>/dev/null || echo 'unknown')"
    return
  fi
  log "Installing kubectl..."
  stable=$(curl -fsSL "${KUBECTL_STABLE_URL}")
  run curl -fsSLo /usr/local/bin/kubectl "https://dl.k8s.io/release/${stable}/bin/linux/amd64/kubectl"
  run chmod +x /usr/local/bin/kubectl
  log "kubectl installed to /usr/local/bin/kubectl"
}

install_kubectl

###
### Helm installation (idempotent)
###
install_helm() {
  if command_exists helm; then
    log "helm already installed ($(helm version --short 2>/dev/null || echo 'unknown'))."
    return
  fi
  log "Installing Helm..."
  run curl -fsSL "${HELM_GET_SCRIPT}" | bash
  log "helm installed."
}

install_helm

###
### kind installation (idempotent)
###
install_kind() {
  if command_exists kind; then
    log "kind already installed ($(kind --version 2>/dev/null || echo 'unknown'))."
    return
  fi
  log "Installing kind (${KIND_VERSION})..."
  run curl -Lo /usr/local/bin/kind "https://kind.sigs.k8s.io/dl/${KIND_VERSION}/kind-linux-amd64"
  run chmod +x /usr/local/bin/kind
  log "kind installed."
}

install_kind

###
### Create kind cluster (idempotent, safe)
###
create_kind_cluster() {
  if command_exists kubectl && kubectl config current-context >/dev/null 2>&1; then
    # detect if a kind cluster is already present in the current context
    current_ctx=$(kubectl config current-context)
    if [[ "${current_ctx}" == kind-* ]]; then
      log "Detected existing kind cluster context (${current_ctx}). Skipping cluster creation."
      return
    fi
  fi

  log "Creating a single-node kind cluster..."
  mkdir -p "${INSTALL_DIR}"
  cat > /tmp/kind-config.yaml <<'EOF'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
EOF

  run kind create cluster --config /tmp/kind-config.yaml
  log "kind cluster created."
}

create_kind_cluster

###
### Deploy vulnerable-lab repository (configurable)
###
deploy_vuln_repo() {
  if [ -d "${VULN_REPO_DIR}" ]; then
    log "Vulnerable lab repo already cloned at ${VULN_REPO_DIR}. Attempting to update (git pull)."
    git -C "${VULN_REPO_DIR}" pull --ff-only || log "git pull failed; repo left as-is."
  else
    log "Cloning vulnerable lab repo from ${VULN_REPO_URL} to ${VULN_REPO_DIR}..."
    run git clone --depth 1 "${VULN_REPO_URL}" "${VULN_REPO_DIR}"
  fi

  # Best practice: do not automatically run arbitrary manifests without inspection.
  # We provide a safe helper to show what manifests would be applied and let user choose.
  if command_exists kubectl; then
    log "Listing manifests in ${VULN_REPO_DIR}/deploy (if present)."
    if [ -d "${VULN_REPO_DIR}/deploy" ]; then
      find "${VULN_REPO_DIR}/deploy" -maxdepth 2 -type f -name '*.yaml' -print || true
      log "To apply these manifests, run: 'kubectl apply -f ${VULN_REPO_DIR}/deploy/' (only after you inspect them)."
    else
      log "No 'deploy' directory found. Inspect the repo to see example deploy instructions."
    fi
  else
    log "kubectl not available to list or apply manifests; skipping deployment."
  fi
}

deploy_vuln_repo

###
### Falco install (via helm) - best-effort idempotent
###
install_falco() {
  # We avoid forcing Falco install on unsupported kernels here. Helm install is attempted, errors are reported.
  if kubectl get ns falco >/dev/null 2>&1; then
    log "Falco namespace already exists - skipping helm install (assume Falco installed)."
    return
  fi

  if ! command_exists helm; then
    log "helm not installed; skipping Falco deployment."
    return
  fi

  log "Installing Falco via Helm (falcosecurity/falco)..."
  run helm repo add falcosecurity https://falcosecurity.github.io/charts
  run helm repo update
  # Install with default values into namespace 'falco'
  run helm install falco falcosecurity/falco --namespace falco --create-namespace || {
    log "helm install falco returned non-zero. Check kernel compatibility / helm charts and install manually if needed."
  }
  log "Falco helm install attempted. Check 'kubectl -n falco get pods' to verify."
}

install_falco

###
### auditd + AIDE for host-level logging & basic FIM
###
setup_host_audit_and_fim() {
  log "Installing auditd and AIDE for host-level logging and basic file integrity monitoring..."
  run apt-get install -y --no-install-recommends auditd audispd-plugins aide
  run systemctl enable --now auditd
  # Initialize AIDE database if not present
  if [ ! -f /var/lib/aide/aide.db.gz ]; then
    log "Initializing AIDE database (this may take a moment)..."
    run /usr/bin/aideinit || log "aideinit returned nonzero; consult AIDE logs."
    if [ -f /var/lib/aide/aide.db.new ]; then
      run mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
    fi
  else
    log "AIDE DB already present; skipping init."
  fi

  # Add a conservative audit rule to watch docker artifacts (non-invasive)
  audit_rule="/etc/audit/rules.d/99-kubelab-docker.rules"
  if [ ! -f "${audit_rule}" ]; then
    cat > "${audit_rule}" <<'EOF'
-w /var/lib/docker/ -p wa -k kubelab_docker
-w /run/docker.sock -p rw -k kubelab_docker_sock
EOF
    log "Created audit rule ${audit_rule}. Loading rules..."
    run augenrules --load || log "augenrules failed to load; verify auditd installation."
  else
    log "Audit rule ${audit_rule} already exists; skipping."
  fi
}

setup_host_audit_and_fim

###
### Final notes and wrap-up
###
log "Provisioning finished. Summary / next steps:"
cat <<'EOF'
- Inspect /var/log/provision_kubelab.log for full run details.
- If you were added to the docker group, log out and back in (or run `newgrp docker`) to refresh group membership.
- To create/apply vulnerable-lab manifests: inspect the cloned repo in ${VULN_REPO_DIR} and apply with kubectl after review:
    kubectl apply -f ${VULN_REPO_DIR}/deploy/
- Falco may require additional kernel support (bpf) - if the Helm install fails, consult Falco docs and kernel compatibility.
- Kubernetes API auditing requires setting apiserver flags (audit-policy-file, audit-log-path). For kind, this needs additional config; refer to kind docs for apiserver manifest customization.
- After verifying everything, take a VM snapshot (name it e.g., kubelab_ready) before running any exercises.
EOF

log "Provisioning script completed successfully."
# Clear the trap to avoid tailing logs at exit
trap - EXIT
exit 0
