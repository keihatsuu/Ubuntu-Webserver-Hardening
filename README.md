# Defense in Depth Automation

`Defense-in-depth-automation.sh` is a Bash script created for an Ubuntu web server hardening lab. It automates several security configuration tasks used to reduce attack surface and apply a defense-in-depth approach.

## What the Script Does

- Installs and updates required security packages
- Changes the SSH port from `22` to `2222`
- Disables SSH root login
- Disables SSH password authentication
- Validates SSH configuration before restarting the service
- Configures UFW with default-deny incoming traffic and default-allow outgoing traffic
- Allows SSH through UFW on port `2222`
- Installs and enables unattended upgrades
- Disables IPv6 except for the loopback interface
- Enables IP spoofing protection with reverse-path filtering
- Disables ICMP redirect acceptance and sending
- Hardens `/run/shm` with `noexec`, `nosuid`, and `nodev`
- Sets Apache `ServerTokens` to `Prod`
- Sets Apache `ServerSignature` to `Off`
- Validates Apache configuration before restarting Apache
- Blocks unnecessary filesystem modules:
  - `cramfs`
  - `freevxfs`
  - `jffs2`
  - `hfs`
  - `hfsplus`
  - `udf`
- Installs and enables Fail2Ban
- Installs and configures Auditd
- Monitors `/etc/passwd` changes using the audit key `password_changes`
- Enables daily Chkrootkit scans
- Performs verification checks after hardening

## Lab Validation

This script was tested in the course lab environment using an instructor-provided validation script.

The final configuration reached:

```text
100% COMPLETION
```

## Usage

Make the script executable:

```bash
chmod +x Defense-in-depth-automation.sh
```

Run it with root privileges:

```bash
sudo ./Defense-in-depth-automation.sh
```

## Warning

This script changes SSH, firewall, kernel, filesystem, and Apache settings.

It is intended for a lab or virtual-machine environment. Test it before using it on a production system because incorrect SSH or firewall configuration can cause loss of remote access.

## Purpose

The goal of this project is to demonstrate how multiple security controls can be combined to harden a Linux web server instead of relying on a single layer of protection.
