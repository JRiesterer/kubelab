# KubeLab Resources Directory

This directory contains configuration files used by the KubeLab setup scripts.

## Files:

### Falco Configuration
- `k8s_security_rules.yaml` - Custom Falco rules for container security monitoring
- `falco-override.conf` - Systemd service override for Falco logging

### Audit Configuration  
- `99-kubelab-container.rules` - Auditd rules for container security monitoring

### System Security
- `99-kubelab.conf` - System security limits configuration
- `kubelab-logrotate` - Log rotation configuration for audit logs

### Monitoring Scripts
- `kubelab-security-check` - Security status monitoring script

## Usage:

These files are automatically copied to their appropriate locations by the setup script:

- `setup.sh` - Main setup script uses all files for comprehensive security setup

## File Destinations:

- `/etc/falco/k8s_security_rules.yaml` ← `k8s_security_rules.yaml`
- `/etc/systemd/system/falco.service.d/override.conf` ← `falco-override.conf`
- `/etc/audit/rules.d/99-kubelab-container.rules` ← `99-kubelab-container.rules`
- `/etc/security/limits.d/99-kubelab.conf` ← `99-kubelab.conf`
- `/etc/logrotate.d/kubelab` ← `kubelab-logrotate`
- `/usr/local/bin/kubelab-security-check` ← `kubelab-security-check`
