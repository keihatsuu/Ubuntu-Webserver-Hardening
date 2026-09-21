# Website Hardening

`website-hardening.sh` combines the Week 2 Defense in Depth and Week 3 Malicious Software hardening exercises into one Bash script for the course's Ubuntu web server VM.

It configures SSH, UFW, system protections, Apache, PHP, ModSecurity, and AppArmor. It also creates backups and performs verification checks. This is an educational lab project, not a general-purpose production hardening tool.

## Disclaimer

**Use this script at your own risk. It is provided AS IS, without warranties or guarantees of any kind. To the fullest extent permitted by applicable law, I am not responsible or liable for any damages, failures, data loss, downtime, loss of access, security incidents, or other losses resulting from the use, misuse, or modification of this script.**

You are responsible for reviewing the code, obtaining authorization, keeping recoverable backups, and verifying that it is appropriate for your environment. Run it only on systems you own or are explicitly authorized to administer. Take a VM snapshot before use.

The script makes privileged changes that can interrupt services or prevent remote access. It does not guarantee that a system is secure, that an incident has been fully remediated, or that a grading rubric or compliance standard has been satisfied. This student project is not an official tool endorsed by an instructor, institution, or upstream software project.

## Features

### Week 2 — Defense in Depth

- Installs the required SSH and security packages from the VM's configured repositories.
- Changes the SSH port to `2222`, disables root login and password/challenge-response authentication, and enables public-key authentication.
- Validates SSH configuration and checks the effective global port, root-login, and password-authentication settings before restarting SSH.
- Configures UFW to deny incoming traffic by default and allow outgoing traffic, with exceptions for TCP ports `2222`, `80`, and `443`.
- Enables unattended upgrades.
- Configures IPv6 disabling except for loopback, reverse-path filtering, and ICMP redirect protections.
- Protects shared memory with `noexec`, `nosuid`, and `nodev`.
- Configures Apache version and signature hiding.
- Blocks loading of `cramfs`, `freevxfs`, `jffs2`, `hfs`, `hfsplus`, and `udf`, and attempts to unload them if already loaded.
- Enables Fail2Ban's SSH jail on port `2222`.
- Enables Auditd and adds an `/etc/passwd` watch using the `password_changes` key.
- Enables daily Chkrootkit scanning through the packaged daily cron job.

### Week 3 — Malicious Software Hardening

- Hardens Apache's PHP 7.4 configuration and PHP 7.2 configuration if present, retaining existing disabled functions.
- Disables the ten additional functions listed by the lab:

```text
exec, passthru, shell_exec, system, proc_open, popen,
curl_exec, curl_multi_exec, parse_ini_file, show_source
```

- Disables uploads and PHP version exposure; sets `open_basedir` to `/var/www/html:/tmp`.
- Sets website ownership to `root:root` and removes group/other write access from non-symlink items on the website filesystem.
- Makes the existing lab file `b374k.php` immutable and denies its URL through Apache.
- Enables Apache's `headers`, `rewrite`, and `security2` modules.
- Sets the assignment's `X-Content-Type-Options`, `X-Frame-Options`, and `X-XSS-Protection` headers.
- Installs the packaged ModSecurity and OWASP Core Rule Set and enables blocking with `SecRuleEngine On`.
- Configures protected `/tmp` storage.
- Installs and enforces the Apache AppArmor profile developed during the manual lab.

## Requirements

The script is designed for the specific course image:

| Requirement | Expected value |
| --- | --- |
| Operating system | Ubuntu 20.04 VM with systemd and APT |
| Web server | Apache with mod_php 7.4 |
| Website | `/var/www/html/index.html` and `/var/www/html/Week3.html` |
| Existing lab artifact | `/var/www/html/b374k.php`, a regular file rather than a symlink |
| PHP configuration | `/etc/php/7.4/apache2/php.ini` |
| AppArmor | Enabled in the kernel with Ubuntu's standard abstractions |
| Execution | Root privileges from the VM console |
| Existing tools | Bash, Python 3, tar, procps, util-linux, and filesystem attribute tools |
| Connectivity | Access to the configured package repositories |

The software versions reflect the course image and are not recommendations for a new deployment. The script does not install or download the lab web shell. Do not add that file or the instructor's lab manual and confirmation scripts to this repository without appropriate permission.

## Usage

1. Take a VMware snapshot and save open work.
2. Review the script, particularly the SSH, firewall, mount, and AppArmor changes.
3. Open a terminal **inside the VM console**. Do not run this over SSH.
4. Copy `website-hardening.sh` into the VM and open its directory.
5. Check syntax:

```bash
bash -n website-hardening.sh
```

If the check succeeds without output, run:

```bash
sudo bash website-hardening.sh
```

Bash is required; do not run it with `sh`. Preserve Unix line endings when saving the script.

For future remote access, configure and verify a non-root user's SSH key before running. The script does not create keys or authorized-key entries. Subsequent SSH connections use port `2222` and key authentication. The script rejects detected SSH sessions, but environment detection is not a substitute for using the VM console.

Existing conditional SSH `Match` blocks require manual review and cause the script to stop. Included SSH configuration files can also produce conflicts, such as additional listening ports; effective-setting validation stops the script before restarting SSH in that case.

## Mount changes and reboot

For `/tmp`, the script updates an existing mount entry or adds a 512 MB tmpfs with `noexec,nosuid,nodev,mode=1777`. It does not mount over the running desktop session's `/tmp`. If protections are not active, it prints **REBOOT REQUIRED**. Save your work and reboot, then check:

```bash
findmnt -T /tmp
ls -ld /tmp
findmnt -T /run/shm
```

An existing `/run/shm` symlink is preserved. The script protects its resolved target, `/dev/shm`, instead. If `/run/shm` is already a real mount, it protects that mount. Existing shared-memory mounts are remounted with the protection options; new mounts are deferred until reboot. This can differ from a class checker that insists on a literal `/run/shm` entry.

The absent `/dev/fd0` floppy entry is commented out if present. There is no automatic reboot. A successful exit does not mean deferred mount changes have taken effect.

## Verification

The script checks or displays:

- SSH listening on port `2222`, UFW rules, and security-service status.
- The Fail2Ban SSH jail, Auditd password-change watch, and daily Chkrootkit setting.
- Shared-memory mount information and selected kernel settings.
- The kernel's Apache AppArmor profile and running-process enforcement labels.
- HTTP 200 for the homepage and `Week3.html`.
- HTTP 403 for the lab web shell and the local WAF test request.
- Apache response headers, website ownership, and absence of items writable by `www-data`.
- Whether `/tmp` protection options are active.

Some checks display information for review rather than asserting every value. In particular, inspect the printed security headers and kernel settings. To attribute the WAF test's 403 response to ModSecurity, inspect its audit log or `/var/log/apache2/error.log`.

## Backups and recovery

Each run creates a restricted `/root/website-hardening-backup.XXXXXXXX` directory containing a configuration/website archive, the run log, initial Apache status, and the lab file's original attributes.

Most errors stop execution. **Earlier changes are not automatically rolled back.** If Apache fails to restart under enforcement, the script attempts to restore complain mode and restart Apache, then exits with failure. That is an incomplete hardening result requiring investigation.

Use the VM snapshot for complete recovery. The archive alone does not undo package installations, kernel state, firewall state, or extended attributes. Backups may contain secrets and the lab web shell; keep them private and out of GitHub.

## Testing status and known limitations

- The original Week 2 script was reported as reaching **100% completion** in the instructor's lab validation.
- The manual Week 3 workflow verified the security headers, protected mounts, web-shell denial, WAF blocking, and AppArmor enforcement.
- The unchanged Week 3 checker reported **6/7** because its AppArmor text search did not match the installed `aa-status` output, despite verified enforcement.
- Local fixture tests cover the combined script's embedded configuration-editing routines across repeated runs.
- **The combined script has not been tested end to end in the VM.** Its historical component results are not a test result for this merged version. Perform the Bash syntax check and test on a recoverable VM snapshot.

The confirmation scripts are not modified or executed by this automation. The supplied Week 3 checker targets PHP 7.2, searches for `apache2 (enforce)` in an incompatible `aa-status` format, and calculates percentages using division before multiplication. Those checker behaviors remain unchanged.

This is not a universal server profile. The AppArmor policy is scoped to the lab's static HTML site and may block other PHP applications or web assets. Repeated runs replace that main profile, normalize selected Apache directives, create new backups, and restart services. UFW rules already present are retained; the script does not reset the firewall to an exclusive three-port policy.

Making a malicious file immutable is a course exercise, not malware eradication. It does not remove persistence or investigate compromise. The immutable attribute does not itself block execution, and PHP function restrictions and `noexec` are not comprehensive execution barriers. Real incident response requires additional investigation and remediation.

## Purpose

This repository demonstrates how several security controls can work together to harden a lab web server, and how to verify the actual configuration when a grading script's assumptions differ from the installed environment.
