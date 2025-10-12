# Kubernetes Security Lab Setup

An enhanced, fully automated setup script for creating a Kubernetes security lab environment on Ubuntu Server 24.04.3 LTS. This lab is designed for evaluating container escape exploits and security mitigations in a controlled environment.

## 🎯 Features

### Enhanced User Experience
- **🌈 Colored output** with clear status indicators (✓ success, ⚠ warning, ✗ error, ℹ info)
- **📊 Progress bar** showing installation progress with step-by-step tracking
- **📝 Comprehensive logging** to `setup.log` with timestamps and detailed information
- **🤖 Zero user interaction** - fully automated installation with no prompts

### Robust Installation
- **🔄 Retry mechanisms** for network operations with exponential backoff
- **✅ Idempotent operations** - safe to run multiple times
- **🛡️ Enhanced error handling** with detailed failure reporting
- **📦 Complete dependency management** with verification steps

### Security Tools Included
- **Docker CE** - Container runtime
- **kubectl** - Kubernetes command-line tool
- **kind** - Kubernetes in Docker for local clusters
- **Helm** - Kubernetes package manager
- **Falco** - Runtime security monitoring
- **auditd** - Linux audit framework with custom rules
- **AIDE** - File integrity monitoring
- **Additional security tools** - strace, tcpdump, lsof, htop, etc.

### Git Clone Improvements
The script includes special handling for git operations to eliminate user prompts:

- **Non-interactive configuration** - Sets `GIT_TERMINAL_PROMPT=0` and appropriate askpass handlers
- **SSH to HTTPS conversion** - Automatically converts SSH URLs to HTTPS for public repos
- **Credential handling** - Configures git to never prompt for credentials
- **Timeout protection** - Prevents hanging on network issues

## 🚀 Quick Start

```bash
# Clone the repository
git clone https://github.com/JRiesterer/kubelab.git
cd kubelab

# Make the script executable
chmod +x setup.sh

# Run the setup (requires sudo)
sudo ./setup.sh
```

## 📋 System Requirements

- **OS**: Ubuntu Server 24.04.3 LTS (or compatible)
- **Memory**: 4GB RAM minimum, 8GB recommended
- **Storage**: 20GB free space minimum
- **Network**: Internet connectivity required for downloads
- **Privileges**: Root/sudo access required

## 📊 Installation Progress

The script provides real-time progress indication:

```
Progress: [==============------] 70% - Installing Falco security monitoring
```

Steps include:
1. Preflight checks (OS, network, disk space)
2. Base package installation
3. Docker CE installation
4. kubectl installation
5. kind installation
6. Helm installation
7. Kubernetes cluster creation
8. Vulnerable lab repository setup
9. Falco security monitoring
10. Host security tools (auditd & AIDE)

## 🔧 Configuration

Key configuration variables (edit in `setup.sh` as needed):

```bash
readonly TARGET_OS="ubuntu"
readonly MIN_UBUNTU_MAJOR=24
readonly INSTALL_DIR="/opt/kubelab"
readonly VULN_REPO_URL="https://github.com/kubernetes/goat.git"
readonly KIND_VERSION="v0.26.0"
```

## 📝 Logging

All operations are logged to `setup.log` in the current directory with:
- Timestamps for all operations
- Color-coded console output
- Detailed error information
- Command execution traces
- Verification results

Example log format:
```
2024-10-12T10:30:45-04:00 INFO: Step 3/10: Installing Docker CE
2024-10-12T10:30:45-04:00 SUCCESS: Docker installed successfully
```

## 🔍 Git Clone Enhancements

The script handles git operations without user interaction through:

### Environment Configuration
```bash
export GIT_TERMINAL_PROMPT=0
export GIT_ASKPASS=/bin/true
export SSH_ASKPASS=/bin/true
```

### Non-Interactive Clone
```bash
git -c advice.detachedHead=false \
    -c init.defaultBranch=main \
    -c user.name="KubeLab Setup" \
    -c user.email="setup@kubelab.local" \
    clone --depth 1 --quiet --no-progress \
    "$clone_url" "$target_dir"
```

### SSH to HTTPS Conversion
Automatically converts URLs like:
- `git@github.com:user/repo.git` → `https://github.com/user/repo.git`

## 🛡️ Security Features

### Audit Rules
Custom audit rules monitor:
- Docker daemon and socket access
- Container runtime operations
- Kubernetes component execution
- Privileged system calls
- Capability changes
- Container escape indicators

### File Integrity Monitoring
- AIDE database initialization
- Baseline file system state
- Change detection capabilities

### Runtime Security
- Falco deployment with eBPF driver
- Real-time threat detection
- Custom rule sets for container security

## 📚 Post-Installation

After successful setup:

1. **Verify Installation**:
   ```bash
   kubectl cluster-info
   kubectl get nodes
   docker --version
   ```

2. **Deploy Vulnerable Applications**:
   ```bash
   # Review manifests first!
   ls -la /opt/kubelab/kube-goat/deploy/
   kubectl apply -f /opt/kubelab/kube-goat/deploy/
   ```

3. **Monitor Security Events**:
   ```bash
   # Falco alerts
   kubectl logs -n falco -l app.kubernetes.io/name=falco -f
   
   # Audit logs
   ausearch -k kubelab_docker
   tail -f /var/log/audit/audit.log | grep kubelab
   ```

4. **Create VM Snapshot**:
   Take a snapshot for easy reset between exercises.

## 🧪 Testing

A test script is included to verify git clone functionality:

```bash
chmod +x test_git_clone.sh
./test_git_clone.sh
```

## ⚠️ Security Warning

This environment contains intentionally vulnerable applications. Use only in isolated lab environments. Never expose to production networks.

## 📞 Support

- Check `setup.log` for detailed error information
- Verify system requirements are met
- Ensure network connectivity for downloads
- Review Ubuntu version compatibility

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Test your changes thoroughly
4. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

**Happy Security Testing! 🛡️**