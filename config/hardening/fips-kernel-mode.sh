#!/bin/sh
# This script was written by Frank Caviggia, Red Hat Consulting
# Last update was 19 March 2015
# This script is NOT SUPPORTED by Red Hat Global Support Services.
# Please contact Rick Tavares for more information.
#
# Script: fips-kernel-mode.sh (system-hardening)
# Description: RHEL 7 Hardening - Configures kernel to FIPS mode
# License: GPL (see COPYING)
# Copyright: Red Hat Consulting, March 2015
# Author: Frank Caviggia <fcaviggi (at) redhat.com>

########################################
# FIPS 140-2 Kernel Mode
########################################
sed -i 's/PRELINKING=yes/PRELINKING=no/g' /etc/sysconfig/prelink
prelink -u -a
dracut -f
if [ -e /sys/firmware/efi ]; then
	BOOT=`df /boot/efi | tail -1 | awk '{print $1 }'`
else
	BOOT=`df /boot | tail -1 | awk '{ print $1 }'`
fi
/sbin/grubby --update-kernel=ALL --args="boot=${BOOT} fips=1"
