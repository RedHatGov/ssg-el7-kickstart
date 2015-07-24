#!/bin/sh
# This script was written by Frank Caviggia, Red Hat Consulting
# Last update was 23 July 2015
# This script is NOT SUPPORTED by Red Hat Global Support Services.
# Please contact Rick Tavares for more information.
#
# Script: ssg-suplemental.sh (system-hardening)
# Description: RHEL 7 Hardening Supplemental to SSG
# License: GPL (see COPYING)
# Copyright: Red Hat Consulting, March 2015
# Author: Frank Caviggia <fcaviggi (at) redhat.com>

########################################
# DISA STIG PAM Configurations
########################################
cat <<EOF > /etc/pam.d/system-auth-local
#%PAM-1.0
auth required pam_env.so
auth required pam_lastlog.so inactive=35
auth required pam_faillock.so preauth silent audit deny=3 even_deny_root root_unlock_time=900 unlock_time=604800 fail_interval=900
auth sufficient pam_unix.so try_first_pass
auth [default=die] pam_faillock.so authfail audit deny=3 even_deny_root root_unlock_time=900 unlock_time=604800 fail_interval=900
auth sufficient pam_faillock.so authsucc audit deny=3 even_deny_root root_unlock_time=900 unlock_time=604800 fail_interval=900
auth requisite pam_succeed_if.so uid >= 500 quiet
auth required pam_deny.so

account required pam_faillock.so
account required pam_unix.so
account required pam_lastlog.so inactive=35
account sufficient pam_localuser.so
account sufficient pam_succeed_if.so uid < 500 quiet
account required pam_permit.so

# Password Quality now set in /etc/security/pwquality.conf
password sufficient pam_unix.so sha512 shadow try_first_pass use_authtok remember=24
password required pam_deny.so

session required pam_lastlog.so showfailed
session optional pam_keyinit.so revoke
session required pam_limits.so
session [success=1 default=ignore] pam_succeed_if.so service in crond quiet use_uid
session required pam_unix.so
EOF
ln -sf /etc/pam.d/system-auth-local /etc/pam.d/system-auth
cp -f /etc/pam.d/system-auth-local /etc/system-auth-ac

cat <<EOF > /etc/pam.d/password-auth-local
#%PAM-1.0
auth required pam_env.so
auth required pam_lastlog.so inactive=35
auth required pam_faillock.so preauth silent audit deny=3 even_deny_root root_unlock_time=900 unlock_time=604800 fail_interval=900
auth sufficient pam_unix.so try_first_pass
auth [default=die] pam_faillock.so authfail audit deny=3 even_deny_root root_unlock_time=900 unlock_time=604800 fail_interval=900
auth sufficient pam_faillock.so authsucc audit deny=3 even_deny_root root_unlock_time=900 unlock_time=604800 fail_interval=900
auth requisite pam_succeed_if.so uid >= 500 quiet
auth required pam_deny.so

account required pam_faillock.so
account required pam_unix.so
account required pam_lastlog.so inactive=35
account sufficient pam_localuser.so
account sufficient pam_succeed_if.so uid < 500 quiet
account required pam_permit.so

# Password Quality now set in /etc/security/pwquality.conf
password sufficient pam_unix.so sha512 shadow try_first_pass use_authtok remember=24
password required pam_deny.so

session required pam_lastlog.so showfailed
session optional pam_keyinit.so revoke
session required pam_limits.so
session [success=1 default=ignore] pam_succeed_if.so service in crond quiet use_uid
session required pam_unix.so
EOF
ln -sf /etc/pam.d/password-auth-local /etc/pam.d/password-auth
cp -f /etc/pam.d/password-auth-local /etc/pam.d/password-auth-ac

cat <<EOF > /etc/pam.d/gnome-screensaver
%PAM-1.0
auth [success=done ignore=ignore default=bad] pam_selinux_permit.so
auth required pam_env.so
auth required pam_lastlog.so
auth required pam_faillock.so preauth silent audit deny=3 even_deny_root root_unlock_time=900 unlock_time=604800 fail_interval=900
auth sufficient pam_unix.so try_first_pass
auth [default=die] pam_faillock.so authfail audit deny=3 even_deny_root root_unlock_time=900 unlock_time=604800 fail_interval=900
auth sufficient pam_faillock.so authsucc audit deny=3 even_deny_root root_unlock_time=900 unlock_time=604800 fail_interval=900
auth requisite pam_succeed_if.so uid >= 500 quiet
auth required pam_deny.so
auth optional pam_gnome_keyring.so

account required pam_faillock.so
account required pam_unix.so
account required pam_lastlog.so
account sufficient pam_localuser.so
account sufficient pam_succeed_if.so uid < 500 quiet
account required pam_permit.so

# Password Quality now set in /etc/security/pwquality.conf
password sufficient pam_unix.so sha512 shadow try_first_pass use_authtok remember=24
password required pam_deny.so

session required pam_lastlog.so showfailed
session optional pam_keyinit.so revoke
session required pam_limits.so
session [success=1 default=ignore] pam_succeed_if.so service in crond quiet use_uid
session required pam_unix.so
EOF

########################################
# STIG Audit Configuration
########################################
cat <<EOF > /etc/audit/rules.d/audit.rules
# DISA STIG Audit Rules
## Add keys to the audit rules below using the -k option to allow for more 
## organized and quicker searches with the ausearch tool.  See auditctl(8) 
## and ausearch(8) for more information.

# Remove any existing rules
-D

# Increase kernel buffer size
-b 16384

# Failure of auditd causes a kernel panic
-f 2

###########################
## DISA STIG Audit Rules ##
###########################

# Watch syslog configuration
-w /etc/rsyslog.conf
-w /etc/rsyslog.d/

# Watch PAM and authentication configuration
-w /etc/pam.d/
-w /etc/nsswitch.conf

# Watch system log files
-w /var/log/messages
-w /var/log/audit/audit.log
-w /var/log/audit/audit[1-4].log

# Watch audit configuration files
-w /etc/audit/auditd.conf -p wa
-w /etc/audit/audit.rules -p wa

# Watch login configuration
-w /etc/login.defs
-w /etc/securetty
-w /etc/resolv.conf

# Watch cron and at
-w /etc/at.allow
-w /etc/at.deny
-w /var/spool/at/
-w /etc/crontab
-w /etc/anacrontab
-w /etc/cron.allow
-w /etc/cron.deny
-w /etc/cron.d/
-w /etc/cron.hourly/
-w /etc/cron.weekly/
-w /etc/cron.monthly/

# Watch shell configuration
-w /etc/profile.d/
-w /etc/profile
-w /etc/shells
-w /etc/bashrc
-w /etc/csh.cshrc
-w /etc/csh.login

# Watch kernel configuration
-w /etc/sysctl.conf
-w /etc/modprobe.conf

# Watch linked libraries
-w /etc/ld.so.conf -p wa
-w /etc/ld.so.conf.d/ -p wa

# Watch init configuration
-w /etc/rc.d/init.d/
-w /etc/sysconfig/
-w /etc/inittab -p wa
-w /etc/rc.local
-w /usr/lib/systemd/
-w /etc/systemd/

# Watch filesystem and NFS exports
-w /etc/fstab
-w /etc/exports

# Watch xinetd configuration
-w /etc/xinetd.conf
-w /etc/xinetd.d/

# Watch Grub2 configuration
-w /etc/grub2.cfg
-w /etc/grub.d/

# Watch TCP_WRAPPERS configuration
-w /etc/hosts.allow
-w /etc/hosts.deny

# Watch sshd configuration
-w /etc/ssh/sshd_config

# Audit system events
-a always,exit -F arch=b32 -S acct -S reboot -S sched_setparam -S sched_setscheduler -S setrlimit -S swapon 
-a always,exit -F arch=b64 -S acct -S reboot -S sched_setparam -S sched_setscheduler -S setrlimit -S swapon 

# Audit any link creation
-a always,exit -F arch=b32 -S link -S symlink
-a always,exit -F arch=b64 -S link -S symlink

##############################
## NIST 800-53 Requirements ##
##############################

#2.6.2.4.1 Records Events that Modify Date and Time Information
-a always,exit -F arch=b32 -S adjtimex -S stime -S settimeofday -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change

#2.6.2.4.2 Record Events that Modify User/Group Information
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
-w /etc/sudoers

#2.6.2.4.3 Record Events that Modify the Systems Network Environment
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k audit_network_modifications
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k audit_network_modifications
-w /etc/issue -p wa -k audit_network_modifications
-w /etc/issue.net -p wa -k audit_network_modifications
-w /etc/hosts -p wa -k audit_network_modifications
-w /etc/sysconfig/network -p wa -k audit_network_modifications

#2.6.2.4.4 Record Events that Modify the System Mandatory Access Controls
-w /etc/selinux/ -p wa -k MAC-policy

#2.6.2.4.5 Ensure auditd Collects Logon and Logout Events
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins

#2.6.2.4.6 Ensure auditd Collects Process and Session Initiation Information
-w /var/run/utmp -p wa -k session
-w /var/log/btmp -p wa -k session
-w /var/log/wtmp -p wa -k session

#2.6.2.4.7 Ensure auditd Collects Discretionary Access Control Permission Modification Events
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod

#2.6.2.4.8 Ensure auditd Collects Unauthorized Access Attempts to Files (unsuccessful)
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access

#2.6.2.4.9 Ensure auditd Collects Information on the Use of Privileged Commands
-a always,exit -F path=/bin/ping -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/bin/umount -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/bin/mount -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/bin/su -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/bin/chgrp -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/bin/ping6 -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/sbin/pam_timestamp_check -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/sbin/unix_chkpwd -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/sbin/pwck -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/suexec -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/useradd -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/userdel -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/newusers -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/groupadd -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/groupdel -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/groupmod -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/semangae -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/usernetctl -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/ccreds_validate -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/userhelper -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/libexec/openssh/ssh-keysign -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/Xorg -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/rlogin -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/sudoedit -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/at -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/rsh -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/gpasswd -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/kgrantpty -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/crontab -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/staprun -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/rcp -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/chfn -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/chage -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/setfacl -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/chacl -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/newgrp -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/newrole -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged

#2.6.2.4.10 Ensure auditd Collects Information on Exporting to Media (successful)
-a always,exit -F arch=b32 -S mount -F auid>=500 -F auid!=4294967295 -k export
-a always,exit -F arch=b64 -S mount -F auid>=500 -F auid!=4294967295 -k export

#2.6.2.4.11 Ensure auditd Collects Files Deletion Events by User (successful and unsuccessful)
-a always,exit -F arch=b32 -S unlink -S rmdir -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete
-a always,exit -F arch=b64 -S unlink -S rmdir -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete

#2.6.2.4.12 Ensure auditd Collects System Administrator Actions
-w /etc/sudoers -p wa -k actions

#2.6.2.4.13 Make the auditd Configuration Immutable
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b32 -S init_module -S delete_module -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules

#2.6.2.4.14 Make the auditd Configuration Immutable
-e 2
EOF

########################################
# Make SELinux Configuration Immutable
########################################
chattr +i /etc/selinux/config

########################################
# Disable Control-Alt-Delete
########################################
ln -sf /dev/null /etc/systemd/system/ctrl-alt-del.target

########################################
# Set Runlevel 3 Target
########################################
systemctl enable multi-user.target --force
ln -sf /usr/lib/systemd/system/multi-user.target /etc/systemd/system/default.target

########################################
# Limit Root Login to Console
########################################
cat <<EOF > /etc/securetty
console
tty1
EOF

########################################
# Disable Interactive Shell (Timeout)
########################################
cat <<EOF > /etc/profile.d/autologout.sh
#!/bin/sh
TMOUT=900
readonly TMOUT
export TMOUT
EOF
cat <<EOF > /etc/profile.d/autologout.csh
#!/bin/csh
set autologout=15
set -r autologout
EOF
chown root:root /etc/profile.d/autologout.sh
chown root:root /etc/profile.d/autologout.csh
chmod 755 /etc/profile.d/autologout.sh
chmod 755 /etc/profile.d/autologout.csh

########################################
# Vlock Alias (Cosole Screen Lock)
########################################
cat <<EOF > /etc/profile.d/vlock-alias.sh
#!/bin/sh
alias vlock='clear;vlock -a'
EOF
cat <<EOF > /etc/profile.d/vlock-alias.csh
#!/bin/csh
alias vlock 'clear;vlock -a'
EOF
chown root:root /etc/profile.d/vlock-alias.sh
chown root:root /etc/profile.d/vlock-alias.csh
chmod 755 /etc/profile.d/vlock-alias.sh
chmod 755 /etc/profile.d/vlock-alias.csh

########################################
# Wheel Group Require (sudo)
########################################
sed -i -re '/pam_wheel.so use_uid/s/^#//' /etc/pam.d/su
sed -i 's/^#\s*\(%wheel\s*ALL=(ALL)\s*ALL\)/\1/' /etc/sudoers
echo -e "\n## Set timeout for authentiation (5 Minutes)\nDefaults:ALL timestamp_timeout=5\n" >> /etc/sudoers

########################################
# Set Removeable Media to noexec
#   CCE-27196-5
########################################
for DEVICE in $(/bin/lsblk | grep sr | awk '{ print $1 }'); do
	mkdir -p /media/$DEVICE
	echo -e "/dev/$DEVICE\t\t/media/$DEVICE\t\tiso9660\tdefaults,ro,noexec,noauto\t0 0" >> /etc/fstab
done
for DEVICE in $(cd /dev;ls *cd* *dvd*); do
	mkdir -p /media/$DEVICE
	echo -e "/dev/$DEVICE\t\t/media/$DEVICE\t\tiso9660\tdefaults,ro,noexec,noauto\t0 0" >> /etc/fstab
done

########################################
# SSHD Hardening
########################################
echo "MACs hmac-sha2-512,hmac-sha2-256,hmac-sha1" >> /etc/ssh/sshd_config
echo "AllowGroups sshusers" >> /etc/ssh/sshd_config
echo "MaxAuthTries 3" >> /etc/ssh/sshd_config
if [ $(grep -c sshusers /etc/group) -eq 0 ]; then
	/usr/sbin/groupadd sshusers &> /dev/null
fi

########################################
# TCP_WRAPPERS
########################################
cat <<EOF >> /etc/hosts.allow
# LOCALHOST (ALL TRAFFIC ALLOWED) DO NOT REMOVE FOLLOWING LINE
ALL: 127.0.0.1 [::1]
# Allow SSH (you can limit this further using IP addresses - e.g. 192.168.0.*)
sshd: ALL
EOF
cat <<EOF >> /etc/hosts.deny
# Deny All by Default
ALL: ALL
EOF

########################################
# Filesystem Attributes
#  CCE-26499-4,CCE-26720-3,CCE-26762-5,
#  CCE-26778-1,CCE-26622-1,CCE-26486-1.
#  CCE-27196-5
########################################
FSTAB=/etc/fstab
SED=`which sed`

if [ $(grep " \/sys " ${FSTAB} | grep -c "nosuid") -eq 0 ]; then
	MNT_OPTS=$(grep " \/sys " ${FSTAB} | awk '{print $4}')
	${SED} -i "s/\( \/sys.*${MNT_OPTS}\)/\1,nodev,nosuid/" ${FSTAB}
fi
if [ $(grep " \/boot " ${FSTAB} | grep -c "nosuid") -eq 0 ]; then
	MNT_OPTS=$(grep " \/boot " ${FSTAB} | awk '{print $4}')
	${SED} -i "s/\( \/boot.*${MNT_OPTS}\)/\1,nodev,nosuid/" ${FSTAB}
fi
if [ $(grep " \/usr " ${FSTAB} | grep -c "nodev") -eq 0 ]; then
	MNT_OPTS=$(grep " \/usr " ${FSTAB} | awk '{print $4}')
	${SED} -i "s/\( \/usr .*${MNT_OPTS}\)/\1,nodev,nosuid/" ${FSTAB}
fi
if [ $(grep " \/home " ${FSTAB} | grep -c "nodev") -eq 0 ]; then
	MNT_OPTS=$(grep " \/home " ${FSTAB} | awk '{print $4}')
	${SED} -i "s/\( \/home .*${MNT_OPTS}\)/\1,nodev,nosuid/" ${FSTAB}
fi
if [ $(grep " \/export\/home " ${FSTAB} | grep -c "nodev") -eq 0 ]; then
	MNT_OPTS=$(grep " \/export\/home " ${FSTAB} | awk '{print $4}')
	${SED} -i "s/\( \/export\/home .*${MNT_OPTS}\)/\1,nodev,nosuid/" ${FSTAB}
fi
if [ $(grep " \/usr\/local " ${FSTAB} | grep -c "nodev") -eq 0 ]; then
	MNT_OPTS=$(grep " \/usr\/local " ${FSTAB} | awk '{print $4}')
	${SED} -i "s/\( \/usr\/local.*${MNT_OPTS}\)/\1,nodev,nosuid/" ${FSTAB}
fi
if [ $(grep " \/dev\/shm " ${FSTAB} | grep -c "nodev") -eq 0 ]; then
	MNT_OPTS=$(grep " \/dev\/shm " ${FSTAB} | awk '{print $4}')
	${SED} -i "s/\( \/dev\/shm.*${MNT_OPTS}\)/\1,nodev,noexec,nosuid/" ${FSTAB}
fi
if [ $(grep " \/tmp " ${FSTAB} | grep -c "nodev") -eq 0 ]; then
	MNT_OPTS=$(grep " \/tmp " ${FSTAB} | awk '{print $4}')
	${SED} -i "s/\( \/tmp.*${MNT_OPTS}\)/\1,nodev,noexec,nosuid/" ${FSTAB}
fi
if [ $(grep " \/var\/tmp " ${FSTAB} | grep -c "nodev") -eq 0 ]; then
	MNT_OPTS=$(grep " \/var\/tmp " ${FSTAB} | awk '{print $4}')
	${SED} -i "s/\( \/var\/tmp.*${MNT_OPTS}\)/\1,nodev,noexec,nosuid/" ${FSTAB}
fi
if [ $(grep " \/var\/log " ${FSTAB} | grep -c "nodev") -eq 0 ]; then
	MNT_OPTS=$(grep " \/var\/tmp " ${FSTAB} | awk '{print $4}')
	${SED} -i "s/\( \/var\/tmp.*${MNT_OPTS}\)/\1,nodev,noexec,nosuid/" ${FSTAB}
fi
if [ $(grep " \/var\/log\/audit " ${FSTAB} | grep -c "nodev") -eq 0 ]; then
	MNT_OPTS=$(grep " \/var\/log\/audit " ${FSTAB} | awk '{print $4}')
	${SED} -i "s/\( \/var\/log\/audit.*${MNT_OPTS}\)/\1,nodev,noexec,nosuid/" ${FSTAB}
fi
if [ $(grep " \/var " ${FSTAB} | grep -c "nodev") -eq 0 ]; then
	MNT_OPTS=$(grep " \/var " ${FSTAB} | awk '{print $4}')
	${SED} -i "s/\( \/var.*${MNT_OPTS}\)/\1,nodev,nosuid/" ${FSTAB}
fi

########################################
# File Ownership 
########################################
find / -nouser -print | xargs chown root
find / -nogroup -print | xargs chown :root
cat <<EOF > /etc/cron.daily/unowned_files
#!/bin/sh
# Fix user and group ownership of files without user
find / -nouser -print | xargs chown root
find / -nogroup -print | xargs chown :root
EOF
chown root:root /etc/cron.daily/unowned_files
chmod 0700 /etc/cron.daily/unowned_files

########################################
# AIDE Initialization
########################################
if [ ! -e /var/lib/aide/aide.db.gz ]; then
	echo "Initializing AIDE database, this step may take quite a while!"
	/usr/sbin/aide --init &> /dev/null
	echo "AIDE database initialization complete."
	cp /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
fi
cat <<EOF > /etc/cron.weekly/aide-report
#!/bin/sh
# Generate Weekly AIDE Report
`/usr/sbin/aide --check > /var/log/aide/reports/$(hostname)-aide-report-$(date +%Y%m%d).txt`
EOF
chown root:root /etc/cron.weekly/aide-report
chmod 555 /etc/cron.weekly/aide-report
mkdir -p /var/log/aide/reports
chmod 700 /var/log/aide/reports
