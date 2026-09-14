#!/bin/bash
# Defense in Depth compliance script
# Revised to match the lab requirements and the settings that pass
# Instructor-provided validation script.

set -u

if [ "$EUID" -ne 0 ]; then
    echo "Please run as root: sudo $0"
    exit 1
fi

SSH_PORT=2222
SSHD_CONFIG="/etc/ssh/sshd_config"
APACHE_SECURITY="/etc/apache2/conf-available/security.conf"
SYSCTL_HARDENING="/etc/sysctl.d/99-week2-hardening.conf"
AUDIT_RULE="/etc/audit/rules.d/password_changes.rules"

echo "============================================================"
echo "                 Webserver Hardening"
echo "============================================================"

# 1. Install/update required packages
echo "[*] Installing/updating required packages..."
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y \
    openssh-server unattended-upgrades ufw fail2ban auditd chkrootkit

# 2. Prepare UFW BEFORE changing/restarting SSH
echo "[*] Preparing UFW..."
ufw default deny incoming
ufw default allow outgoing
ufw allow "${SSH_PORT}/tcp"

# 3. OpenSSH hardening
echo "[*] Hardening OpenSSH..."

set_sshd_option() {
    local key="$1"
    local value="$2"
    if grep -Eq "^[[:space:]#]*${key}[[:space:]]+" "$SSHD_CONFIG"; then
        sed -Ei "s|^[[:space:]#]*${key}[[:space:]]+.*|${key} ${value}|" "$SSHD_CONFIG"
    else
        echo "${key} ${value}" >> "$SSHD_CONFIG"
    fi
}
set_sshd_option "Port" "$SSH_PORT"
set_sshd_option "PermitRootLogin" "no"
set_sshd_option "PasswordAuthentication" "no"
if sshd -t; then
    systemctl restart ssh
    echo "[+] SSH configured: port $SSH_PORT, root login disabled, password auth disabled."
else
    echo "[!] SSH configuration test failed. SSH was NOT restarted."
    exit 1
fi

# 4. Unattended upgrades
echo "[*] Configuring unattended upgrades..."
cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
# The supplied VM may have this service masked.
systemctl unmask unattended-upgrades 2>/dev/null || true
systemctl enable unattended-upgrades
systemctl restart unattended-upgrades || systemctl start unattended-upgrades

# 5. IPv6 + kernel/network hardening
echo "[*] Applying IPv6 and network hardening..."

cat > "$SYSCTL_HARDENING" <<'EOF'
# Disable IPv6 except loopback
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 0

# IP spoofing / redirect protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
EOF

sysctl --system >/dev/null

# 6. Secure /run/shm
echo "[*] Securing /run/shm..."
# The confirmation script looks for /run/shm followed by noexec then nosuid.
# Remove any old/incorrect /run/shm fstab entry and add one canonical entry.
cp -a /etc/fstab /etc/fstab.week2.bak
sed -i '\|[[:space:]]/run/shm[[:space:]]|d' /etc/fstab
echo 'tmpfs /run/shm tmpfs defaults,noexec,nosuid,nodev 0 0' >> /etc/fstab
# On this Ubuntu lab image, /run/shm may initially be a symlink to /dev/shm.
# The course validator expects /run/shm itself to be a mount point.
if [ -L /run/shm ]; then
    rm -f /run/shm
    mkdir -p /run/shm
else
    mkdir -p /run/shm
fi
if mountpoint -q /run/shm; then
    mount -o remount,noexec,nosuid,nodev /run/shm
else
    mount /run/shm
fi

# 7. Apache hardening
echo "[*] Hardening Apache..."

if command -v apache2 >/dev/null 2>&1 && [ -f "$APACHE_SECURITY" ]; then
    if grep -Eq '^[[:space:]#]*ServerTokens[[:space:]]+' "$APACHE_SECURITY"; then
        sed -Ei 's|^[[:space:]#]*ServerTokens[[:space:]]+.*|ServerTokens Prod|' "$APACHE_SECURITY"
    else
        echo 'ServerTokens Prod' >> "$APACHE_SECURITY"
    fi
    if grep -Eq '^[[:space:]#]*ServerSignature[[:space:]]+' "$APACHE_SECURITY"; then
        sed -Ei 's|^[[:space:]#]*ServerSignature[[:space:]]+.*|ServerSignature Off|' "$APACHE_SECURITY"
    else
        echo 'ServerSignature Off' >> "$APACHE_SECURITY"
    fi
    a2enconf security >/dev/null 2>&1 || true
    if apache2ctl configtest; then
        systemctl restart apache2
        echo "[+] Apache hardened."
    else
        echo "[!] Apache configuration test failed. Apache was NOT restarted."
        exit 1
    fi
else
    echo "[!] Apache/security.conf not found; skipping Apache section."
fi

# 8. Disable unnecessary filesystems
echo "[*] Disabling unnecessary filesystem modules..."

FILESYSTEMS=(cramfs freevxfs jffs2 hfs hfsplus udf)

for fs in "${FILESYSTEMS[@]}"; do
    cat > "/etc/modprobe.d/${fs}.conf" <<EOF
install ${fs} /bin/true
blacklist ${fs}
EOF
    modprobe -r "$fs" 2>/dev/null || true
done

# 9. Fail2Ban
echo "[*] Enabling Fail2Ban..."
systemctl enable --now fail2ban

# 10. Auditd rule for /etc/passwd
echo "[*] Configuring Auditd password_changes rule..."
cat > "$AUDIT_RULE" <<'EOF'
-w /etc/passwd -p wa -k password_changes
EOF
systemctl enable auditd >/dev/null 2>&1 || true
augenrules --load >/dev/null 2>&1 || true
systemctl restart auditd 2>/dev/null || true

# 11. Chkrootkit daily scans
echo "[*] Enabling daily chkrootkit scans..."

if [ -f /etc/chkrootkit.conf ]; then
    if grep -q '^RUN_DAILY=' /etc/chkrootkit.conf; then
        sed -i 's/^RUN_DAILY=.*/RUN_DAILY="true"/' /etc/chkrootkit.conf
    else
        echo 'RUN_DAILY="true"' >> /etc/chkrootkit.conf
    fi
else
    echo "[!] /etc/chkrootkit.conf not found."
fi

# 12. Enable UFW after SSH rule is in place
echo "[*] Enabling UFW..."
ufw --force enable

echo ""
echo "============================================================"
echo "Hardening complete."
echo "============================================================"
echo ""
echo "Quick verification:"
echo "  SSH:"
ss -tlnp 2>/dev/null | grep ":${SSH_PORT} " || true

echo ""
echo "  /run/shm fstab entry:"
grep '/run/shm' /etc/fstab || true

echo ""
echo "  /run/shm live mount:"
findmnt /run/shm || true

echo ""
echo "  Apache:"
grep -E '^[[:space:]]*(ServerTokens|ServerSignature)' "$APACHE_SECURITY" 2>/dev/null || true

echo ""
echo "  Unattended upgrades:"
systemctl is-enabled unattended-upgrades 2>/dev/null || true
systemctl is-active unattended-upgrades 2>/dev/null || true

echo ""
echo "  Fail2Ban:"
systemctl is-active fail2ban 2>/dev/null || true

echo ""
echo "  Audit rule:"
auditctl -l 2>/dev/null | grep password_changes || true

echo ""
echo "  Chkrootkit:"
grep '^RUN_DAILY=' /etc/chkrootkit.conf 2>/dev/null || true

echo ""
echo "  UFW:"
ufw status verbose || true

echo ""
echo "Run the course validator with:"
echo "  cd /var/www/Client_Scripts"
echo "  sudo ./Week2_Confirmation_Script.sh"
