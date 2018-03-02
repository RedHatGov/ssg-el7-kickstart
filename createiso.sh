#!/bin/sh
###############################################################################
# HARDENED RHEL DVD CREATOR
#
# This script was written by Frank Caviggia, Red Hat Consulting
# Last update was 23 July 2015
# This script is NOT SUPPORTED by Red Hat Global Support Services.
#
# Author: Frank Caviggia (fcaviggia@gmail.com)
# Copyright: Red Hat, (c) 2014
# Version: 1.2
# License: Apache License, Version 2.0
# Description: Kickstart Installation of RHEL 7 with DISA STIG 
###############################################################################

# GLOBAL VARIABLES
DIR=`pwd`

# USAGE STATEMENT
function usage() {
cat << EOF
usage: $0 rhel-server-7.X-x86_64-dvd.iso

SCAP Security Guide RHEL Kickstart RHEL 7.1+

Customizes a RHEL 7.1+ x86_64 Server or Workstation DVD to install
with the following hardening:

  - SCAP Security Guide (SSG) for Red Hat Enterprise Linux
  - Classification Banner (Graphical Desktop)

EOF
}

while getopts ":vhq" OPTION; do
	case $OPTION in
		h)
			usage
			exit 0
			;;
		?)
			echo "ERROR: Invalid Option Provided!"
			echo
			usage
			exit 1
			;;
	esac
done

# Check for root user
if [[ $EUID -ne 0 ]]; then
	if [ -z "$QUIET" ]; then
		echo
		tput setaf 1;echo -e "\033[1mPlease re-run this script as root!\033[0m";tput sgr0
	fi
	exit 1
fi

# Check for required packages
rpm -q genisoimage &> /dev/null
if [ $? -ne 0 ]; then
	yum install -y genisoimage
fi

rpm -q syslinux &> /dev/null
if [ $? -ne 0 ]; then
	yum install -y syslinux 
fi

rpm -q isomd5sum &> /dev/null
if [ $? -ne 0 ]; then
	yum install -y isomd5sum
fi

# Determine if DVD is Bootable
`file $1 | grep -q -e "9660.*boot" -e "x86 boot" -e "DOS/MBR boot"`
if [[ $? -eq 0 ]]; then
	echo "Mounting RHEL DVD Image..."
	mkdir -p /rhel
	mkdir $DIR/rhel-dvd
	mount -o loop $1 /rhel
	echo "Done."
	# Tests DVD for RHEL 7.4+
	if [ -e /rhel/.discinfo ]; then
		RHEL_VERSION=$(grep "Red Hat" /rhel/.discinfo | awk -F ' ' '{ print $5 }')
		MAJOR=$(echo $RHEL_VERSION | awk -F '.' '{ print $1 }')
		MINOR=$(echo $RHEL_VERSION | awk -F '.' -F ' ' '{ print $2 }')
		if [[ $MAJOR -ne 7 ]]; then
			echo "ERROR: Image is not RHEL 7.4+"
			umount /rhel
			rm -rf /rhel
			exit 1
		fi
		if [[ $MINOR -ge 4 ]]; then
			echo "ERROR: Image is not RHEL 7.4+"
			umount /rhel
			rm -rf /rhel
			exit 1
		fi
	else
		echo "ERROR: Image is not RHEL"
		exit 1
	fi

	echo -n "Copying RHEL DVD Image..."
	cp -a /rhel/* $DIR/rhel-dvd/
	cp -a /rhel/.discinfo $DIR/rhel-dvd/
	echo " Done."
	umount /rhel
	rm -rf /rhel
else
	echo "ERROR: ISO image is not bootable."
	exit 1
fi

echo -n "Modifying RHEL DVD Image..."
# Set RHEL Version in ISO Linux
sed -i "s/7.X/$RHEL_VERSION/g" $DIR/config/isolinux/isolinux.cfg
sed -i "s/7.X/$RHEL_VERSION/g" $DIR/config/EFI/BOOT/grub.cfg
cp -a $DIR/config/* $DIR/rhel-dvd/
if [[ $MINOR -ge 3 ]]; then
	rm -f $DIR/rhel-dvd/hardening/openscap*rpm 
fi
sed -i "s/$RHEL_VERSION/7.X/g" $DIR/config/isolinux/isolinux.cfg
sed -i "s/$RHEL_VERSION/7.X/g" $DIR/config/EFI/BOOT/grub.cfg
echo " Done."
echo "Remastering RHEL DVD Image..."
cd $DIR/rhel-dvd
chmod u+w isolinux/isolinux.bin
find . -name TRANS.TBL -exec rm '{}' \; 
/usr/bin/mkisofs -J -T -V "RHEL-$RHEL_VERSION Server.x86_64" -o $DIR/ssg-rhel-$RHEL_VERSION.iso -b isolinux/isolinux.bin -c isolinux/boot.cat -no-emul-boot -boot-load-size 4 -boot-info-table -eltorito-alt-boot -e images/efiboot.img -no-emul-boot -R -m TRANS.TBL .
cd $DIR
rm -rf $DIR/rhel-dvd
echo "Done."

echo "Signing RHEL DVD Image..."
/usr/bin/isohybrid --uefi $DIR/ssg-rhel-$RHEL_VERSION.iso &> /dev/null
/usr/bin/implantisomd5 $DIR/ssg-rhel-$RHEL_VERSION.iso
echo "Done."

echo "DVD Created. [ssg-rhel-$RHEL_VERSION.iso]"

exit 0
