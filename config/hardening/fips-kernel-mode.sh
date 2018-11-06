#!/bin/sh
# This script was written by Frank Caviggia, Red Hat Consulting
# Last update was 08 April 2017
# This script is NOT SUPPORTED by Red Hat Global Support Services.
#
# Script: fips-kernel-mode.sh (system-hardening)
# Description: RHEL 7 Hardening - Configures kernel to FIPS mode
# License: Apache License, Version 2.0
# Copyright: Red Hat Consulting, March 2015
# Author: Frank Caviggia (fcaviggia@gmail.com)

########################################
# FIPS 140-2 Kernel Mode
########################################
rpm -q prelink && sed -i '/^PRELINKING/s,yes,no,' /etc/sysconfig/prelink
rpm -q prelink && prelink -ua
dracut -f
BOOT="UUID=$(findmnt -no uuid /boot)"
/sbin/grubby --update-kernel=ALL --args="boot=${BOOT} fips=1"
/usr/bin/sed -i "s/quiet/quiet boot=${BOOT} fips=1/" /etc/default/grub
