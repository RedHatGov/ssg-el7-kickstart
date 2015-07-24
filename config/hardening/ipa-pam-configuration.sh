#!/bin/sh
# This script was written by Frank Caviggia, Red Hat Consulting
# Last update was 8 June 2015
# This script is NOT SUPPORTED by Red Hat Global Support Services.
# Please contact Rick Tavares for more information.
#
# Script: ipa-pam-configuration.sh (system-hardening)
# Description: RHEL 7 Hardening Supplemental to SSG, configures PAM with sssd if system is registered with IdM.
# License: GPL
# Copyright: Red Hat Consulting, March 2015
# Author: Frank Caviggia <fcaviggi (at) redhat.com>

# Backup originial configuration
if [ ! -e /etc/pam.d/system-auth-local.orig ]; then
  cp /etc/pam.d/system-auth-local /etc/pam.d/system-auth-local.orig
fi
if [ ! -e /etc/pam.d/password-auth-local.orig ]; then
  cp /etc/pam.d/password-auth-local /etc/pam.d/password-auth-local.orig
fi
if [ ! -e /etc/pam.d/gnome-screensaver.orig ]; then
  cp /etc/pam.d/gnome-screensaver /etc/pam.d/gnome-screensaver.orig
fi

# Deploy Configuruation
cat <<EOF > /etc/pam.d/system-auth-local
#%PAM-1.0
auth required pam_env.so
auth required pam_lastlog.so inactive=35
auth required pam_faillock.so preauth silent audit deny=3 even_deny_root root_unlock_time=900 unlock_time=604800 fail_interval=900
auth sufficient pam_unix.so try_first_pass
auth [default=die] pam_faillock.so authfail audit deny=3 even_deny_root root_unlock_time=900 unlock_time=604800 fail_interval=900
auth sufficient pam_faillock.so authsucc audit deny=3 even_deny_root root_unlock_time=900 unlock_time=604800 fail_interval=900
auth requisite pam_succeed_if.so uid >= 500 quiet
auth sufficient pam_sss.so use_first_pass
auth required pam_deny.so

account required pam_faillock.so
account required pam_unix.so
account required pam_lastlog.so inactive=35
account sufficient pam_localuser.so
account sufficient pam_succeed_if.so uid < 500 quiet
account [default=bad success=ok user_unknown=ignore] pam_sss.so
account required pam_permit.so

#password required pam_passwdqc.so min=disabled,disabled,16,12,8 random=42
password required pam_cracklib.so retry=3 minlen=14 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1 difok=3 maxrepeat=3
password sufficient pam_unix.so sha512 shadow try_first_pass use_authtok remember=24
password sufficient pam_sss.so use_authtok
password required pam_deny.so

session required pam_lastlog.so showfailed
session optional pam_keyinit.so revoke
session required pam_limits.so
session optional pam_oddjob_mkhomedir.so umask=0077
session [success=1 default=ignore] pam_succeed_if.so service in crond quiet use_uid
session required pam_unix.so
session optional pam_sss.so
EOF
ln -sf /etc/pam.d/system-auth-local /etc/pam.d/system-auth


cat <<EOF > /etc/pam.d/password-auth-local
#%PAM-1.0
auth required pam_env.so
auth required pam_lastlog.so inactive=35
auth required pam_faillock.so preauth silent audit deny=3 even_deny_root root_unlock_time=900 unlock_time=604800 fail_interval=900
auth sufficient pam_unix.so try_first_pass
auth [default=die] pam_faillock.so authfail audit deny=3 even_deny_root root_unlock_time=900 unlock_time=604800 fail_interval=900
auth sufficient pam_faillock.so authsucc audit deny=3 even_deny_root root_unlock_time=900 unlock_time=604800 fail_interval=900
auth requisite pam_succeed_if.so uid >= 500 quiet
auth sufficient pam_sss.so use_first_pass
auth required pam_deny.so

account required pam_faillock.so
account required pam_unix.so
account required pam_lastlog.so inactive=35
account sufficient pam_localuser.so
account sufficient pam_succeed_if.so uid < 500 quiet
account [default=bad success=ok user_unknown=ignore] pam_sss.so
account required pam_permit.so

#password required pam_passwdqc.so min=disabled,disabled,16,12,8 random=42
password required pam_cracklib.so retry=3 minlen=14 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1 difok=3 maxrepeat=3
password sufficient pam_unix.so sha512 shadow try_first_pass use_authtok remember=24
password sufficient pam_sss.so use_authtok
password required pam_deny.so

session required pam_lastlog.so showfailed
session optional pam_keyinit.so revoke
session required pam_limits.so
session optional pam_oddjob_mkhomedir.so umask=0077
session [success=1 default=ignore] pam_succeed_if.so service in crond quiet use_uid
session required pam_unix.so
session optional pam_sss.so
EOF
ln -sf /etc/pam.d/password-auth-local /etc/pam.d/password-auth

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
auth sufficient pam_sss.so use_first_pass
auth required pam_deny.so
auth optional pam_gnome_keyring.so

account required pam_faillock.so
account required pam_unix.so
account required pam_lastlog.so
account sufficient pam_localuser.so
account sufficient pam_succeed_if.so uid < 500 quiet
account [default=bad success=ok user_unknown=ignore] pam_sss.so
account required pam_permit.so

#password required pam_passwdqc.so min=disabled,disabled,16,12,8 random=42
password required pam_cracklib.so retry=3 minlen=14 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1 difok=3 maxrepeat=3
password sufficient pam_unix.so sha512 shadow try_first_pass use_authtok remember=24
password sufficient pam_sss.so use_authtok
password required pam_deny.so

session required pam_lastlog.so showfailed
session optional pam_keyinit.so revoke
session required pam_limits.so
session [success=1 default=ignore] pam_succeed_if.so service in crond quiet use_uid
session required pam_unix.so
session optional pam_sss.so
EOF

exit 0
