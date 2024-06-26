#!/usr/bin/env bash
# Description: Installation Script of the CID
# Copyright (C) 2012-2023 Eduardo Moraes <emoraes25@gmail.com>
# This file is part of CID (Closed In Directory).
#
# CID is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# CID is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with CID.  If not, see <http://www.gnu.org/licenses/>.
#------------------------------------------------------------------------#


# ************************************************************************************************ #
# WARNING: Do not run this script if you have not already installed the application's requirements!
# To see the requirements see the session REQUIREMENTS in the README file.
# ************************************************************************************************ #


# Checking root privileges
[ "$(id -u)" -ne 0 ] && echo -e "Permission denied!\nRun: sudo $0" >&2 && exit 1


# Starting script
echo 'Starting script...' ; sleep 1


# Accessing directory from installation files
cd "${0%/*}" || exit


# Checking and importing control files
[ ! -s scripts/vars.bash ] && echo -e "'scripts/vars.bash' file not found!" >&2 && exit 1


# Checking Variables
# shellcheck source=/dev/null
[ -s /usr/share/cid/scripts/vars.bash ] && . /usr/share/cid/scripts/vars.bash >/dev/null 2>&1

oldversion=${VERSION:-$(if command -v cid >/dev/null 2>&1; then echo 1; else echo '0.0.0'; fi)}

if [ ${#oldversion} -ne 5 ] && [ "${oldversion}" != "9.1" ]; then
	echo -e "This script is incompatible with the installed version of the program!\nFirst uninstall the current version, or upgrade it to version '9.1' in\norder to install the version of this package." >&2
	exit 1
fi

# shellcheck disable=SC2086
VAR='VERSION BINDIR SBINDIR APPSDIR MAN8DIR MAN1DIR CONFDIR BASHCOMPDIR DOCDIR TEMPDIR SHAREDIR SCRIPTDIR MODELDIR ICONDIR VARLIBDIR LOGDIR DBDIR BACKUPDIR RESTOREDIR' && unset $VAR FQDN

# shellcheck source=/dev/null
. scripts/vars.bash >/dev/null 2>&1

for var in $VAR; do
	[ -z "${!var}" ] && echo -e "'${var}' parameter not found in scripts/vars.bash file!" >&2 && exit 1
done


# Function: Flag - If "yes" then continue, otherwise exit
function Flag () {
	case $flag in
		y|Y) ;;
		*) echo 'Aborted!' ; exit 2 ;;
	esac
}


# Function: Manage_ProgramFiles - This controls the backup, restore or removal of program files
function Manage_ProgramFiles () {
	local FILE
	
	if [ "$2" ]; then
		FILE="$2"
	else
		FILE="${SHAREDIR}/cid.bash
${SHAREDIR}/cid_gtk.bash
${SCRIPTDIR}/change_pass.bash
${SCRIPTDIR}/logon_commonUser.bash
${SCRIPTDIR}/mkhomedir.bash
${SCRIPTDIR}/functions.bash
${SCRIPTDIR}/pre_logon.bash
${SCRIPTDIR}/logon_superUser.bash
${SCRIPTDIR}/umount_netlogon.bash
${SCRIPTDIR}/logger.bash
${SCRIPTDIR}/manager_systemGroups.bash
${SCRIPTDIR}/setquota.bash
${SCRIPTDIR}/vars.bash
${MODELDIR}/scripts_cid/logon_root.sh
${MODELDIR}/scripts_cid/logon.sh
${MODELDIR}/scripts_cid/shares.xml
${MODELDIR}/logon_root.sh
${MODELDIR}/logon.sh
${MODELDIR}/shares.xml
${ICONDIR}/cid-cp.png
${ICONDIR}/cid.png
${SBINDIR}/cid
${SBINDIR}/cid-gtk
${BINDIR}/cid-change-pass
${BINDIR}/cid-change-pass-gtk
${APPSDIR}/cid-gtk.desktop
${APPSDIR}/cid-change-pass-gtk.desktop
${POLKITDIR}/org.freedesktop.cid.policy
${POLKITDIR}/org.freedesktop.policykit.cid-gtk.policy
${CONFDIR}/cid.conf.example
${BASHCOMPDIR}/cid
${DOCDIR}/usermanual.html
${DOCDIR}/COPYING
${DOCDIR}/README
${DOCDIR}/README.md
${MAN8DIR}/cid.8.gz
${MAN8DIR}/cid-gtk.8.gz
${MAN1DIR}/cid-change-pass.1.gz
${MAN1DIR}/cid-change-pass-gtk.1.gz
/etc/bash_completion.d/cid"
fi

	case $1 in
		0)
			echo -e "\nRemoving program files...\n" ; sleep 1

			for file in $FILE; do
				[ -f "$file" ] && rm -v "$file"
			done

			local DIR="$DOCDIR $CONFDIR $TEMPDIR $LOGDIR $VARLIBDIR $SHAREDIR"

			for dir in $DIR; do
				bool=true

				for subdir in $(find "$dir" -type d | sort -r); do
					if [ "$(find "$subdir" -type f)" ]; then
						bool=false
					else
						rmdir -v "$subdir"
					fi
				done

				[ "$bool" = "false" ] && echo -e "\n'${dir}' directory can not be removed because it is not empty!\n" >&2
				sleep 1
			done
		;;
		1)
			echo -e "\nCreating backup of the program files of the installed version..." ; sleep 1

			for file in $FILE; do
				[ -f "$file" ] && mv -fv "$file" "${file}.tmp"
			done

			BKP=1
		;;
		2)
			echo -e "\nRestoring backup of program files from the installed version..." ; sleep 1

			for file in $FILE; do
				[ -f "${file}.tmp" ] && mv -fv "${file}.tmp" "$file"
			done

			unset BKP
		;;
		3)
			echo -e "\nClearing backup of the program files from the previous version..." ; sleep 1

			for file in $FILE; do
				[ -f "${file}.tmp" ] && rm -v "${file}.tmp"
			done

			unset BKP
		;;
	esac
}


# Running uninstallation
if [ "$1" = "uninstall" ]; then
	echo -e "\nRunning uninstallation..." ; sleep 1
	[ "$oldversion" = "0.0.0" ] && echo -e "\nNo installed versions found!" >&2 && exit 1
	echo && echo -n "Do you really want to delete the installed files from this program? [N/y] " && read -r flag && Flag
	Manage_ProgramFiles 0 ; status=$?
	echo -e "\nUninstall complete!\n" && exit $status
fi


# Checking arguments
[ $# -gt 0 ] && echo "'$*' argument invalid!" >&2 && exit 1


# Checking dependencies
echo -e "\nChecking dependencies..." ; sleep 1

unset ARG ; ARG='bash awk cut find diff grep sed gzip umount hostname gpasswd sudo setfacl setfattr systemctl xhost pkexec zenity ip ping request-key klist wbinfo smbd net smbspool mount.cifs pmvarrun cupsd lpadmin'

for arg in $ARG; do
	[ "$(command -v "${arg}" 2>/dev/null)" ] || ARG[1]=${ARG[1]:+${ARG[1]} }$arg
done

if [ -n "${ARG[1]}" ]; then
	echo -e "\nThe programs below were not found, and CID depends on them
to function properly. IT IS EXTREMELY RECOMMENDED THAT YOU CHECK THE
PACKAGES RESPONSIBLE FOR PROVIDING THESE PROGRAMS (See Requirements),
AND INSTALL THEM BEFORE PROCEEDING WITH THIS INSTALLATION!\n"

	for arg in ${ARG[1]}; do
		echo "  \`$arg\` not found"
	done

	echo && echo -n "Do you want to continue with the CID installation anyway? [N/y] " && read -r flag && Flag
fi


# Checking versions
[ "${oldversion}" = "9.1" ] && oldversion=0.0.1

if [ "$oldversion" \> "$VERSION" ]; then
	echo -e "\nThe installed version is newer than the package version!"
	echo -n "Do you want to install anyway? [N/y] " && read -r flag && Flag
	Manage_ProgramFiles 1
elif [ "$oldversion" = "$VERSION" ]; then
	echo -e "\nThe same version of the package is already installed!"
	echo -n "Do you want to reinstall the package? [N/y] " && read -r flag && Flag
elif [ "$oldversion" != "0.0.0" ]; then
	Manage_ProgramFiles 1
fi


# Installing program files
echo -e "\nInstalling program files..." ; sleep 1

function Check_Install () {
	if [ ! -f "$1" ]; then
		echo -e "\nAn error has occurred!\n'${1##*/}' file not found!\nUndoing changes..." >&2 ; sleep 1
		[ -n "${FILE[1]}" ] && Manage_ProgramFiles 0 "${FILE[1]}" && unset FILE
		[ ${BKP:-0} -eq 1 ] && Manage_ProgramFiles 2
		echo -e "\nAborted!" >&2 ; exit 1
	fi
}

FILE[0]="${MODELDIR}/logon_root.sh
${MODELDIR}/logon.sh
${MODELDIR}/shares.xml
${SCRIPTDIR}/change_pass.bash
${SCRIPTDIR}/logon_commonUser.bash
${SCRIPTDIR}/mkhomedir.bash
${SCRIPTDIR}/functions.bash
${SCRIPTDIR}/pre_logon.bash
${SCRIPTDIR}/logon_superUser.bash
${SCRIPTDIR}/umount_netlogon.bash
${SCRIPTDIR}/logger.bash
${SCRIPTDIR}/manager_systemGroups.bash
${SCRIPTDIR}/setquota.bash
${SCRIPTDIR}/vars.bash
${ICONDIR}/cid-cp.png
${ICONDIR}/cid.png
${SHAREDIR}/cid.bash
${SHAREDIR}/cid_gtk.bash
${SBINDIR}/cid-gtk
${CONFDIR}/cid.conf.example
${BASHCOMPDIR}/cid
${DOCDIR}/COPYING
${DOCDIR}/README.md
${APPSDIR}/cid-gtk.desktop
${APPSDIR}/cid-change-pass-gtk.desktop
${POLKITDIR}/org.freedesktop.cid.policy
${MAN8DIR}/cid.8
${MAN8DIR}/cid-gtk.8
${MAN1DIR}/cid-change-pass.1
${MAN1DIR}/cid-change-pass-gtk.1"

for file in ${FILE[0]}; do
	[ ! -d "${file%/*}" ] && echo && mkdir -pv "${file%/*}" && echo

	find . -type f -name "${file##*/}" -exec cp -fv {} "$file" \;
	Check_Install "$file"

	if [ "${file%/*}" = "$SBINDIR" ] || [ "${file##*.}" = "sh" ] || [ "${file##*.}" = "bash" ]; then
		chmod +x "$file"
	fi
	
	if [ "${file##*.}" = "1" ] || [ "${file##*.}" = "8" ]; then
		gzip -fv "$file" 2>&1 && FILE[1]=${FILE[1]:+${FILE[1]} }${file}.gz
		continue
	fi

	FILE[1]=${FILE[1]:+${FILE[1]} }$file
done

FILE[0]="${SBINDIR}/cid:${SHAREDIR}/cid.bash
${BINDIR}/cid-change-pass:${SCRIPTDIR}/change_pass.bash
${BINDIR}/cid-change-pass-gtk:${SCRIPTDIR}/change_pass.bash"

for file in ${FILE[0]}; do
	lnk=${file%%:*}
	[ ! -d "${lnk%/*}" ] && echo && mkdir -pv "${lnk%/*}" && echo
	sleep 1 ; ln -sfv "${file##*:}" "$lnk"
	Check_Install "$lnk"
	FILE[1]=${FILE[1]:+${FILE[1]} }$lnk
done

echo -e "\nCreating other work directories..." && sleep 1
VAR='LOGDIR DBDIR BACKUPDIR RESTOREDIR'

for var in $VAR; do
	[ ! -d "${!var}" ] && mkdir -pv "${!var}"
done

[ ${BKP:-0} -eq 1 ] && Manage_ProgramFiles 3


#Final adjustments
[ -f "${CONFDIR}/cid.conf" ] || cp -f "${CONFDIR}/cid.conf.example" "${CONFDIR}/cid.conf"

if [ -n "$FQDN" ]; then
	echo -e "\nReconfiguring files..."

	"${SCRIPTDIR}/functions.bash" update
fi

#Fix cifs-utils bug
if [ "$(command -v getcifsacl)" ] && [ ! -f /etc/cifs-utils/idmap-plugin ]; then
	for file in /usr/lib/x86_64-linux-gnu/cifs-utils/idmapwb.so /usr/lib/cifs-utils/idmapwb.so; do
		if [ -f "$file" ]; then
			[ -d /etc/cifs-utils ] || mkdir /etc/cifs-utils
			ln -s "$file" /etc/cifs-utils/idmap-plugin
			break
		fi
	done
fi

echo -e "\nInstallation complete!"

exit 0