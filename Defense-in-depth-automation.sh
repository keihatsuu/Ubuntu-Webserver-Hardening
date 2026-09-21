#!/usr/bin/env bash
# Combined Week 2 and Week 3 lab hardening: Ubuntu 20.04, mod_php 7.4.
# Educational use only. Provided AS IS, without warranty.
# To the fullest extent permitted by applicable law, the author is not liable
# for damages, data loss, downtime, access failures, or other losses from use.
# Run from the VMware console. Review README.md and take a snapshot first.
# Does NOT alter or impersonate the instructor's confirmation script.
# Run: sudo bash website-hardening.sh
set -Eeuo pipefail
umask 022
[[ $EUID -eq 0 ]] || { echo 'Run with sudo bash website-hardening.sh'; exit 1; }
if [[ -n ${SSH_CONNECTION:-} || -n ${SSH_CLIENT:-} ]]; then
    echo 'Run from the VM console: this script changes SSH authentication and firewall settings.'
    exit 1
fi
command -v python3 >/dev/null || { echo 'Python 3 is required.'; exit 1; }
[[ -f /etc/php/7.4/apache2/php.ini && -f /etc/apache2/apache2.conf ]] || {
    echo 'This script requires the Ubuntu lab Apache/PHP 7.4 layout.'; exit 1;
}
[[ $(readlink -f /var/www/html) == /var/www/html ]] || {
    echo 'Unexpected website path; stopping.'; exit 1;
}
[[ -f /var/www/html/b374k.php && ! -L /var/www/html/b374k.php ]] || {
    echo 'Expected lab file /var/www/html/b374k.php is missing or a symlink.'; exit 1;
}
BACKUP=$(mktemp -d /root/website-hardening-backup.XXXXXXXX)
chmod 700 "$BACKUP"
export BACKUP
exec > >(tee "$BACKUP/run.log") 2>&1
echo "Backups and run log: $BACKUP"
trap 'rc=$?; echo "STOPPED (exit $rc), line $LINENO. Review $BACKUP/run.log and backups. Changes are not automatically rolled back."; exit "$rc"' ERR

paths=(etc/php etc/apache2 etc/fstab etc/apparmor.d var/www/html)
for extra in etc/ssh etc/ufw etc/default/ufw etc/apt/apt.conf.d etc/sysctl.d etc/modprobe.d etc/fail2ban etc/audit etc/chkrootkit.conf; do
    [[ ! -e /$extra ]] || paths+=("$extra")
done
[[ ! -d /etc/modsecurity ]] || paths+=(etc/modsecurity)
tar -czpf "$BACKUP/before.tar.gz" -C / "${paths[@]}"
lsattr /var/www/html/b374k.php > "$BACKUP/shell-attributes.txt"
systemctl is-active apache2 > "$BACKUP/apache-before.txt" || true
# Packages come from the VM repositories, including their compatible CRS.
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y \
    libapache2-mod-security2 modsecurity-crs apparmor-utils apparmor-profiles \
    openssh-server unattended-upgrades ufw fail2ban auditd chkrootkit cron curl
[[ -r /etc/modsecurity/modsecurity.conf-recommended ]]
[[ -r /usr/share/modsecurity-crs/owasp-crs.load ]]

# Week 2: prepare firewall access before changing SSH.
ufw default deny incoming
ufw default allow outgoing
ufw allow 2222/tcp
ufw allow 80/tcp
ufw allow 443/tcp

# Set global SSH options without rewriting conditional Match blocks.
python3 <<'PY'
from pathlib import Path
import re
p = Path('/etc/ssh/sshd_config')
t = p.read_text()
if re.search(r'^[ \t]*Match[ \t]+', t, re.M | re.I):
    raise SystemExit('Conditional SSH Match blocks require manual review before this lab automation.')
start, end = '# BEGIN COMBINED LAB SSH', '# END COMBINED LAB SSH'
t = re.sub(re.escape(start)+r'.*?'+re.escape(end)+r'\n?', '', t, flags=re.S)
lines = []; in_match = False
keys = {'port', 'permitrootlogin', 'passwordauthentication', 'kbdinteractiveauthentication', 'challengeresponseauthentication', 'pubkeyauthentication'}
for line in t.splitlines():
    words = line.split()
    if words and words[0].lower() == 'match': in_match = True
    if not in_match and words and words[0].lower() in keys: continue
    lines.append(line)
settings = '''Port 2222
PermitRootLogin no
PasswordAuthentication no
ChallengeResponseAuthentication no
PubkeyAuthentication yes'''
p.write_text(start+'\n'+settings+'\n'+end+'\n'+'\n'.join(lines)+'\n')
PY
/usr/sbin/sshd -t
SSH_EFFECTIVE=$(/usr/sbin/sshd -T)
[[ $(printf '%s\n' "$SSH_EFFECTIVE" | awk '$1=="port" {print $2}') == 2222 ]]
printf '%s\n' "$SSH_EFFECTIVE" | grep -Fx 'permitrootlogin no'
printf '%s\n' "$SSH_EFFECTIVE" | grep -Fx 'passwordauthentication no'
systemctl restart ssh

cat > /etc/apt/apt.conf.d/20auto-upgrades <<'AUTO'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
AUTO
systemctl unmask unattended-upgrades
systemctl enable --now unattended-upgrades

cat > /etc/sysctl.d/99-week2-hardening.conf <<'SYSCTL'
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
SYSCTL
sysctl --system

# Preserve /run/shm symlinks; protect their real mount instead.
SHM_TARGET=$(readlink -f /run/shm)
case "$SHM_TARGET" in /run/shm|/dev/shm) ;; *) echo 'Unexpected shared-memory path.'; exit 1;; esac
export SHM_TARGET
python3 <<'PY'
from pathlib import Path
import os
p = Path('/etc/fstab'); target = os.environ['SHM_TARGET']
lines = []
for line in p.read_text().splitlines():
    words = line.split()
    if words and not line.lstrip().startswith('#') and len(words)>1 and words[1] in ('/run/shm','/dev/shm'):
        if len(words)<3 or words[2] != 'tmpfs':
            raise SystemExit('Non-tmpfs shared-memory entry requires manual review.')
        continue
    lines.append(line)
lines.append(f'tmpfs {target} tmpfs defaults,noexec,nosuid,nodev,mode=1777 0 0')
p.write_text('\n'.join(lines)+'\n')
PY
if mountpoint -q "$SHM_TARGET"; then
    mount -o remount,noexec,nosuid,nodev "$SHM_TARGET"
else
    echo "REBOOT REQUIRED: shared-memory mount $SHM_TARGET configured for next boot."
fi

# Keep the Week 2 Apache security file consistent with Week 3's main settings.
python3 <<'PY'
from pathlib import Path
import re
p = Path('/etc/apache2/conf-available/security.conf')
t = p.read_text() if p.exists() else ''
for key, value in (('ServerTokens','Prod'), ('ServerSignature','Off')):
    t = re.sub(rf'^[ \t]*{key}[ \t]+.*$', '', t, flags=re.M)
    t = t.rstrip()+f'\n{key} {value}\n'
p.write_text(t)
PY
a2enconf security

for fs in cramfs freevxfs jffs2 hfs hfsplus udf; do
    printf 'install %s /bin/true\nblacklist %s\n' "$fs" "$fs" > "/etc/modprobe.d/$fs.conf"
    if grep -q "^$fs " /proc/modules; then
        if ! modprobe -r "$fs"; then
            echo "WARNING: $fs remains loaded; investigate its users before reboot."
        fi
    fi
done

mkdir -p /etc/fail2ban/jail.d
cat > /etc/fail2ban/jail.d/week2-sshd.local <<'JAIL'
[sshd]
enabled = true
port = 2222
JAIL
fail2ban-client -t
systemctl enable fail2ban
systemctl restart fail2ban

cat > /etc/audit/rules.d/password_changes.rules <<'AUDIT'
-w /etc/passwd -p wa -k password_changes
AUDIT
systemctl enable --now auditd
if ! augenrules --load; then
    echo 'Audit rules could not be loaded; check whether audit configuration is immutable.'
    exit 1
fi
auditctl -l | grep -F password_changes

python3 <<'PY'
from pathlib import Path
import re
p = Path('/etc/chkrootkit.conf')
t = p.read_text() if p.exists() else ''
t = re.sub(r'^[ \t]*RUN_DAILY=.*$', '', t, flags=re.M)
p.write_text(t.rstrip()+'\nRUN_DAILY="true"\n')
PY
[[ -x /etc/cron.daily/chkrootkit ]]
systemctl enable --now cron
ufw --force enable


# Preserve existing function restrictions; harden legacy 7.2 as well if present.
# The legacy file is checked by the instructor but is not the active PHP version.
python3 <<'PY'
import pathlib, re
required = 'exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source'.split(',')
for version in ('7.4', '7.2'):
    p = pathlib.Path('/etc/php') / version / 'apache2/php.ini'
    if not p.exists():
        continue
    text = p.read_text()
    existing = []
    for value in re.findall(r'^\s*disable_functions\s*=\s*([^\n]*)', text, re.M):
        existing += value.split(';', 1)[0].strip().strip('"').split(',')
    functions = list(dict.fromkeys(required + [v.strip() for v in existing if v.strip()]))
    values = dict(disable_functions=','.join(functions),
                  open_basedir='/var/www/html:/tmp', file_uploads='Off', expose_php='Off')
    for key, value in values.items():
        pattern = rf'^\s*;?\s*{key}\s*=.*$'
        text = re.sub(pattern, '', text, flags=re.M)
        text = text.rstrip() + f'\n{key} = {value}\n'
    p.write_text(text)
    print('Hardened', p)
PY

# Avoid changing the already-immutable shell on repeat runs.
if lsattr /var/www/html/b374k.php | awk '{print $1}' | grep -q i; then
    [[ $(stat -c '%U:%G' /var/www/html/b374k.php) == root:root ]]
    [[ -z $(find /var/www/html/b374k.php -perm /022 -print) ]]
else
    chown root:root /var/www/html/b374k.php
    chmod go-w /var/www/html/b374k.php
    chattr +i /var/www/html/b374k.php
fi
find /var/www/html -xdev ! -path /var/www/html/b374k.php ! -type l -exec chown root:root {} +
find /var/www/html -xdev ! -path /var/www/html/b374k.php ! -type l -exec chmod go-w {} +

a2enmod headers rewrite security2
python3 <<'PY'
from pathlib import Path
import re
p = Path('/etc/apache2/apache2.conf')
t = p.read_text()
begin, end = '# BEGIN WEEK3 AUTOMATED HARDENING', '# END WEEK3 AUTOMATED HARDENING'
t = re.sub(re.escape(begin)+r'.*?'+re.escape(end)+r'\n?', '', t, flags=re.S)
# Normalize the exact directives used by our earlier manual workflow.
t = re.sub(r'^\s*(?:ServerTokens|ServerSignature)\s+.*$', '', t, flags=re.M)
t = re.sub(r'^\s*Header\s+(?:always\s+)?set\s+(?:X-Content-Type-Options|X-Frame-Options|X-XSS-Protection)\s+.*$', '', t, flags=re.M)
p.write_text(t.rstrip() + '\n\n' + begin + '''
ServerTokens Prod
ServerSignature Off
Header always set X-Content-Type-Options "nosniff"
Header always set X-Frame-Options "SAMEORIGIN"
Header always set X-XSS-Protection "1; mode=block"
<Directory "/var/www/html">
    <Files "b374k.php">
        Require all denied
    </Files>
</Directory>
''' + end + '\n')
p = Path('/etc/modsecurity/modsecurity.conf')
if not p.exists():
    p.write_text(Path('/etc/modsecurity/modsecurity.conf-recommended').read_text())
t = re.sub(r'^\s*SecRuleEngine\s+.*$', 'SecRuleEngine On', p.read_text(), flags=re.M)
if not re.search(r'^SecRuleEngine On$', t, re.M):
    t += '\nSecRuleEngine On\n'
p.write_text(t)
# Ubuntu's packaged security2.conf loads /etc/modsecurity/*.conf and CRS *.load.
# Do not clone a second rule set or add duplicate rule includes.
p = Path('/etc/fstab')
lines = p.read_text().splitlines()
found = False
out = []
for line in lines:
    fields = line.split()
    if fields and not line.lstrip().startswith('#'):
        if fields[0] == '/dev/fd0' and not Path('/dev/fd0').exists():
            line = '# Disabled absent lab floppy: ' + line
        elif len(fields) >= 4 and fields[1] == '/tmp':
            if found:
                raise SystemExit('Multiple active /tmp entries: resolve before rerunning.')
            found = True
            options = [v for v in fields[3].split(',') if v not in ('exec','suid','dev','noexec','nosuid','nodev')]
            options += ['noexec','nosuid','nodev']
            if fields[2] == 'tmpfs':
                options = [v for v in options if not v.startswith('mode=')]
                options.append('mode=1777')
            fields[3] = ','.join(options)
            line = '\t'.join(fields)
    out.append(line)
if not found:
    out.append('tmpfs /tmp tmpfs defaults,noexec,nosuid,nodev,mode=1777,size=512M 0 0')
p.write_text('\n'.join(out) + '\n')
PY
findmnt --verify --verbose
systemctl daemon-reload

# Use the profile tested in this lab. Backups are outside /etc/apparmor.d.
cat > /etc/apparmor.d/usr.sbin.apache2 <<'PROFILE'
# Week 3 lab Apache profile. Scoped to the lab's static HTML website.
#include <tunables/global>
/usr/sbin/apache2 {
    #include <abstractions/base>
    #include <abstractions/nameservice>
    capability kill,
    capability net_bind_service,
    capability setgid,
    capability setuid,
    signal (send, receive) peer=/usr/sbin/apache2,
    /usr/sbin/apache2 mr,
    /var/log/apache2/access.log w,
    /var/log/apache2/modsec_audit.log w,
    /var/www/html/**.html r,
    owner /etc/mime.types r,
    owner /etc/modsecurity/ r,
    owner /etc/phpmyadmin/apache.conf r,
    owner /etc/ssl/openssl.cnf r,
    owner /etc/{apache2,modsecurity,php}/** r,
    owner /run/apache2/apache2.pid rw,
    owner /tmp/.ZendSem.* rwk,
    owner /usr/share/modsecurity-crs/ r,
    owner /usr/share/modsecurity-crs/owasp-crs.load r,
    owner /usr/share/modsecurity-crs/rules/ r,
    owner /usr/share/modsecurity-crs/rules/* r,
    owner /var/log/apache2/error.log w,
    owner /var/log/apache2/other_vhosts_access.log w,
}
PROFILE
apparmor_parser -Q /etc/apparmor.d/usr.sbin.apache2
apache2ctl configtest
systemctl enable apparmor
apparmor_parser -r /etc/apparmor.d/usr.sbin.apache2
aa-enforce /usr/sbin/apache2
if ! systemctl restart apache2; then
    echo 'Apache failed under enforcement. Restoring complain mode for troubleshooting.'
    aa-complain /usr/sbin/apache2
    systemctl restart apache2 || true
    echo "Hardening incomplete. Review journalctl -u apache2 and $BACKUP/run.log."
    exit 1
fi

echo '--- Week 2 verification ---'
ss -tlnp | grep ':2222 '
ufw status verbose
systemctl is-active ssh unattended-upgrades fail2ban auditd cron
fail2ban-client status sshd
auditctl -l | grep -F password_changes
grep '^RUN_DAILY=' /etc/chkrootkit.conf
findmnt -T /run/shm
sysctl net.ipv6.conf.lo.disable_ipv6 net.ipv4.conf.all.rp_filter
echo '--- Week 3 verification ---' 
grep -Fx '/usr/sbin/apache2 (enforce)' /sys/kernel/security/apparmor/profiles
for pid in $(pgrep -x apache2); do
    printf 'Apache PID %s: ' "$pid"
    label=$(cat "/proc/$pid/attr/current")
    echo "$label"
    [[ $label == '/usr/sbin/apache2 (enforce)' ]]
done
for page in / /Week3.html /b374k.php; do
    code=$(curl --max-time 15 -sS -o /dev/null -w '%{http_code}' "http://127.0.0.1$page")
    echo "$page: HTTP $code"
    expected=200
    [[ $page != /b374k.php ]] || expected=403
    [[ $code == "$expected" ]]
done
code=$(curl --max-time 15 -sS -o /dev/null -w '%{http_code}' --get \
    --data-urlencode 'week3test=<script>alert(1)</script>' http://127.0.0.1/)
echo "WAF test: HTTP $code (expected 403)"
[[ $code == 403 ]]
curl --max-time 15 -sSI http://127.0.0.1/
[[ $(stat -c '%U:%G' /var/www/html) == root:root ]]
[[ -z $(runuser -u www-data -- find /var/www/html -writable -print) ]]
lsattr /var/www/html/b374k.php

if findmnt -rn -M /tmp -o OPTIONS | grep -qE '(^|,)noexec(,|$)' &&
   findmnt -rn -M /tmp -o OPTIONS | grep -qE '(^|,)nosuid(,|$)' &&
   findmnt -rn -M /tmp -o OPTIONS | grep -qE '(^|,)nodev(,|$)'; then
    echo '/tmp protections are active.'
else
    echo 'REBOOT REQUIRED: /tmp protections are configured in fstab but not fully active.'
    echo 'Save your work, reboot the VM, then verify with: findmnt -T /tmp'
fi
echo 'Configuration applied; review the verification output above.'
echo 'Instructor confirmation script was not modified or run.'
echo 'Its AppArmor text-match and percentage bugs remain; an official 7/7 is not guaranteed.'
echo "Backups and log: $BACKUP"
