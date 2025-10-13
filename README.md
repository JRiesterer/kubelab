# Kubernetes Security Lab Setup

An automated setup script for creating a Kubernetes security lab environment on Ubuntu Server 24.04.3 LTS. This lab is designed for evaluating container escape exploits and security mitigations in a controlled environment.

## Features

### Enhanced User Experience
- Colored output with clear status indicators
- Progress bar showing installation progress
- Comprehensive logging to `setup.log` with timestamps
- Zero user interaction - fully automated installation

### Robust Installation
- Retry mechanisms for network operations
- Idempotent operations - safe to run multiple times
- Enhanced error handling with detailed failure reporting
- Complete dependency management with verification

### Security Tools Included
- Docker CE - Container runtime
- kubectl - Kubernetes command-line tool
- kind - Kubernetes in Docker for local clusters
- Helm - Kubernetes package manager
- Falco - Runtime security monitoring
- auditd - Linux audit framework with custom rules
- AIDE - File integrity monitoring
- Additional security tools - strace, tcpdump, lsof, htop, etc.

### Git Clone Improvements
The script includes special handling for git operations to eliminate user prompts:

- Non-interactive configuration - Sets environment variables to prevent prompts
- SSH to HTTPS conversion - Automatically converts SSH URLs to HTTPS for public repos
- Credential handling - Configures git to never prompt for credentials
- Timeout protection - Prevents hanging on network issues

## Quick Start

## Quick Start

```bash
# Clone the repository
git clone https://github.com/JRiesterer/kubelab.git
cd kubelab

# Make the script executable
chmod +x setup.sh

# Run the setup (requires sudo)
sudo ./setup.sh
```

## System Requirements

- OS: Ubuntu Server 24.04.3 LTS (or compatible)
- Memory: 4GB RAM minimum, 8GB recommended
- Storage: 20GB free space minimum
- Network: Internet connectivity required for downloads
- Privileges: Root/sudo access required

## Installation Process

The setup script provides a streamlined, fail-fast installation:
- Essential components only with comprehensive security monitoring
- Direct error output to console for immediate feedback
- Fast execution with minimal overhead
- Comprehensive security tools and monitoring

## Installation Steps

The script installs and configures:
1. Preflight checks (OS, network, requirements)
2. Base package installation and updates
3. Docker CE installation and configuration
4. kubectl installation and verification
5. kind installation and cluster creation
6. Helm installation
7. Kubernetes cluster creation
8. Vulnerable lab repository setup
9. Falco security monitoring
10. Host security tools (auditd & AIDE)
11. Additional security configuration
12. Final verification

### Minimal Setup (setup_minimal.sh)
The minimal script performs these essential steps:
1. Preflight checks (OS, network, root access)
2. Base packages installation
3. Docker CE installation
4. kubectl installation
5. kind installation  
6. Helm installation
7. Kind cluster creation
8. Vulnerable lab repository clone
9. Falco installation (best effort)
10. Basic audit tools
11. Final verification

## Configuration
6. Helm installation and verification
7. Vulnerable lab repository cloning (Kubernetes Goat)
8. Falco runtime security monitoring setup
9. Comprehensive security monitoring (auditd, AIDE)
10. Kind cluster creation and verification
11. Final configuration and testing

## Security Monitoring Components

The setup includes comprehensive security monitoring:

### Falco Runtime Security
- Custom Kubernetes security rules for container escape detection
- Real-time monitoring of suspicious container activities
- Integration with system logs via journald

### Audit Framework (auditd)
- Container-specific audit rules
- System call monitoring for privilege escalation
- Docker and Kubernetes component monitoring

### File Integrity Monitoring (AIDE)
- Database initialization for system file monitoring
- Detection of unauthorized file changes

### Security Tools
- strace, ltrace - System call tracing
- tcpdump - Network monitoring
- lsof, htop, psmisc - Process monitoring
- Custom security status checking script

## Configuration Files

All configuration files are organized in the `resources/` directory:
- `k8s_security_rules.yaml` - Falco custom security rules
- `99-kubelab-container.rules` - Auditd container monitoring rules
- `99-kubelab.conf` - System security limits
- `kubelab-logrotate` - Log rotation configuration
- `kubelab-security-check` - Security monitoring script

## Security Features

### Audit Rules
Custom audit rules monitor:
- Docker daemon and socket access
- Container runtime operations
- Kubernetes component execution
- Privileged system calls
- Capability changes
- Container escape indicators

## Post-Installation

After successful setup:

1. **Verify Installation**:
   ```bash
   kubectl cluster-info
   kubectl get nodes
   docker --version
   /usr/local/bin/kubelab-security-check
   ```

2. **Deploy Vulnerable Applications**:
   ```bash
   # Review manifests first!
   ls -la /opt/kubelab/kubernetes-goat/scenarios/
   kubectl apply -f /opt/kubelab/kubernetes-goat/scenarios/
   ```

3. **Monitor Security Events**:
   ```bash
   # Falco alerts (if using host install)
   journalctl -u falco -f
   
   # Audit logs
   ausearch -k kubelab_docker
   tail -f /var/log/audit/audit.log | grep kubelab
   ```

4. **Security Status Check**:
   ```bash
   # Run the included security monitoring script
   /usr/local/bin/kubelab-security-check
   ```

5. **Create VM Snapshot**:
   Take a snapshot for easy reset between exercises.

## Troubleshooting

Common issues and solutions:

### kubectl Connection Refused
If kubectl shows connection errors after setup:
```bash
sudo cp /root/.kube/config ~/.kube/config
sudo chown $(id -u):$(id -g) ~/.kube/config
```

### Docker Permission Issues
Log out and back in, or run:
```bash
newgrp docker
```

### Resource Directory Missing
Ensure you have the complete repository with the `resources/` directory:
```bash
ls -la resources/
```

## Configuration

Key configuration variables (edit in `setup.sh` as needed):

```bash
readonly INSTALL_DIR="/opt/kubelab"
readonly VULN_REPO_URL="https://github.com/madhuakula/kubernetes-goat.git"
readonly KIND_VERSION="v0.26.0"
```

## Security Warning

This environment contains intentionally vulnerable applications designed for security research and training. Use only in isolated lab environments. Never expose to production networks or the internet.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Test your changes thoroughly
4. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.