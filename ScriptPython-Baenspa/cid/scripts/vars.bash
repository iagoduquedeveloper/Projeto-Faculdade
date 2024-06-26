#!/usr/bin/env bash
# Description: Variables File
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


# Current Version
export VERSION=1.2.5


# Base Directories
export CONFDIR=/etc/cid
export TEMPDIR=/tmp/.cid
export BINDIR=/usr/bin
export SBINDIR=/usr/sbin
export POLKITDIR=/usr/share/polkit-1/actions
export APPSDIR=/usr/share/applications
export BASHCOMPDIR=/usr/share/bash-completion/completions
export MAN8DIR=/usr/share/man/man8
export MAN1DIR=/usr/share/man/man1
export DOCDIR=/usr/share/doc/cid-base
export SHAREDIR=/usr/share/cid
export SCRIPTDIR=${SHAREDIR}/scripts
export MODELDIR=${SHAREDIR}/templates
export ICONDIR=${SHAREDIR}/icons
export LOGDIR=/var/log/cid
export VARLIBDIR=/var/lib/cid
export DBDIR=${VARLIBDIR}/databases
export BACKUPDIR=${VARLIBDIR}/backups/ori
export RESTOREDIR=${VARLIBDIR}/backups/mod


# Imported variables
unset IFS

HOSTNAME=${HOSTNAME:=$(hostname)} && HOSTNAME=${HOSTNAME%%.*}

ARG='logsize defaultuserid id_range_size max_num_domains profiledir sudodir systemddir prtdrvdir netlogon osfile pwdfile grpfile gsdwfile nssfile hostfile sudofile krbfile ntpfile cupsfile mountfile ldmfile smbfile keytabfile pam_auth pam_account pam_password pam_session excl_localgroups localgroups wbd_userprofile wbd_usershell krb_principal_names fallntpsrv qttltime add_pam_authmod pam_mod_dir'

for arg in $ARG; do
	unset "$arg" "${arg^^}"
done

# shellcheck source=/dev/null
[ -s "${DBDIR}/station.db" ] && . "${DBDIR}/station.db"

if [ ! -s "${DBDIR}/station.db" ] || [ "$1" = "reload" ]; then
	# shellcheck source=/dev/null
	[ -s "${CONFDIR}/cid.conf" ] && . "${CONFDIR}/cid.conf"

	ARG='logsize defaultuserid id_range_size max_num_domains'

	for arg in $ARG; do
		if [ -n "${!arg}" ] && ! echo "${!arg}" | grep -Eq "[^0-9]"; then true; else continue; fi
		[[ "$arg" =~ (id_range_size|max_num_domains) && ${!arg} -eq 0 ]] && declare "$arg"=1
		export "${arg^^}"="${!arg}"
	done

	DIR='profiledir sudodir systemddir'

	for dir in $DIR; do
		if [ -d "${!dir}" ]; then
			if [ "${!dir:(-1)}" = '/' ]; then
				export "${dir^^}"="${!dir%/}"
			else
				export "${dir^^}"="${!dir}"
			fi
		fi
	done

	[ -n "$PRTDRVDIR" ] && export OLDPRTDRVDIR=$PRTDRVDIR

	# shellcheck disable=SC2154
	[ "${prtdrvdir:0:1}" = '/' ] && PRTDRVDIR=$prtdrvdir ; [ "${PRTDRVDIR:(-1)}" = '/' ] && PRTDRVDIR=${PRTDRVDIR%/}

	# shellcheck disable=SC2154
	[ "${netlogon:0:1}" = '/' ] && NETLOGON=$netlogon ; [ "${NETLOGON:(-1)}" = '/' ] && NETLOGON=${NETLOGON%/}

	FILE='osfile pwdfile grpfile gsdwfile nssfile hostfile krbfile ntpfile mountfile ldmfile smbfile keytabfile'

	for file in $FILE; do
		[ -f "${!file}" ] && export "${file^^}"="${!file}"
	done

	ARG='pam_auth pam_account pam_password pam_session'

	for arg in $ARG; do
		unset PAM

		for file in ${!arg}; do
			[ -f "${!file}" ] && PAM=${PAM:+$PAM }${file}
		done

		[ -n "$PAM" ] && export "${arg^^}=$PAM"
	done

	ARG='excl_localgroups localgroups wbd_userprofile wbd_usershell add_pam_authmod pam_mod_dir'

	for arg in $ARG; do
		export "${arg^^}"="${!arg}"
	done

	# shellcheck disable=SC2154
	if [ "$krb_principal_names" ]; then
		ARG="${krb_principal_names,,}" && ARG="$(echo "$ARG" | sed 's/[[:blank:]]/\n/g' | sort -u | grep -Ex "^(/?[[:alnum:]]+|[[:alnum:]]+/[[:alnum:]]+)$" | grep -Evx "^/${HOSTNAME}")"

		unset KRB_PRINCIPAL_NAMES

		for arg in $ARG; do
    		if [[ $arg =~ .+/.+ ]]; then
				# shellcheck disable=SC2143,SC2166
        		[ "$(echo "$ARG" | sed 's/[[:blank:]]/\n/g' | grep -x "${arg%/*}")" -a "$(echo "$ARG" | sed 's/[[:blank:]]/\n/g' | grep -x "/${arg#*/}")" ] || [ "$(echo "$ARG" | sed 's/[[:blank:]]/\n/g' | grep -x "${arg%/*}")" -a "${arg#*/}" = "$HOSTNAME" ] && continue
    		fi

	    	KRB_PRINCIPAL_NAMES="${KRB_PRINCIPAL_NAMES:+${KRB_PRINCIPAL_NAMES} }$arg"
		done
	fi

	# shellcheck disable=SC2154
	if [ "$fallntpsrv" ]; then
		for str in $fallntpsrv; do
			if ping -q -W 1 -c 1 "$str" >/dev/null 2>&1; then
				FALLNTPSRV=${FALLNTPSRV:+$FALLNTPSRV }$str
			fi
		done
	fi

	if [ "$qttltime" ]; then
		lst="${qttltime:(-1)}"
		qttltime="${qttltime:0:$((${#qttltime}-1))}"

		if echo "$lst" | grep -Eq "[^0-9]"; then
			if echo "$lst" | grep -Eiq "(m|h|d|w)" && ! echo "$qttltime" | grep -Eq "[^0-9]"; then
				QTTLTIME=${qttltime}${lst,,}
			fi
		else
			if ! echo "$qttltime" | grep -Eq "[^0-9]"; then
				QTTLTIME=${qttltime}$lst
			fi
		fi
	fi
fi

LOGSIZE=${LOGSIZE:=1000}
DEFAULTUSERID=${DEFAULTUSERID:=1000}
ID_RANGE_SIZE=${ID_RANGE_SIZE:=100000}
MAX_NUM_DOMAINS=${MAX_NUM_DOMAINS:=10}
PROFILEDIR=${PROFILEDIR:=/etc/profile.d}
SUDODIR=${SUDODIR:=/etc/sudoers.d}
NETLOGON=${NETLOGON:=/mnt/cid/.netlogon}
OSFILE=${OSFILE:=/etc/os-release}
PWDFILE=${PWDFILE:=/etc/passwd}
GRPFILE=${GRPFILE:=/etc/group}
GSDWFILE=${GSDWFILE:=/etc/gshadow}
NSSFILE=${NSSFILE:=/etc/nsswitch.conf}
HOSTFILE=${HOSTFILE:=/etc/hosts}
KRBFILE=${KRBFILE:=/etc/krb5.conf}
MOUNTFILE=${MOUNTFILE:=/etc/security/pam_mount.conf.xml}
NTPFILE=${NTPFILE:=/etc/systemd/timesyncd.conf}
LDMFILE=${LDMFILE:=/etc/lightdm/lightdm.conf}
SMBFILE=${SMBFILE:=$(smbd -b 2>/dev/null | grep -w 'CONFIGFILE' | tr -d '[:blank:]' | cut -d ':' -f 2)}
SMBFILE=${SMBFILE:=/etc/samba/smb.conf}
KEYTABFILE=${KEYTABFILE:=/etc/krb5.keytab}

if [ -z "$SYSTEMDDIR" ]; then
	DIR='/etc/systemd/system /usr/lib/systemd/system /lib/systemd/system'

	for dir in $DIR; do
		[ -d "$dir" ] && SYSTEMDDIR="$dir" && break
	done
fi

if [ -z "$PRTDRVDIR" ]; then
	PRTDRVDIR=$(smbd -b 2>/dev/null | grep -w 'STATEDIR' | tr -d '[:blank:]' | cut -d ':' -f 2)
	[ "${PRTDRVDIR:(-1)}" = '/' ] && PRTDRVDIR=${PRTDRVDIR%/}
	PRTDRVDIR=${PRTDRVDIR:=/var/lib/samba}/printers
fi

[ "${PRTDRVDIR:0:1}" = '/' ] || PRTDRVDIR=/var/lib/samba/printers

ARG='PAM_AUTH PAM_ACCOUNT PAM_PASSWORD PAM_SESSION'

for arg in $ARG; do
	if [ -z "${!arg}" ]; then
		unset PAM
		str=${arg,,} && FILE="/etc/pam.d/common-${str#*_} /etc/pam.d/system-auth /etc/pam.d/password-auth"

		for file in $FILE; do
			[ -f "$file" ] && export PAM="${PAM:+${PAM} }$file"
		done

		export "${arg^^}"="${PAM:-/etc/pam.conf}"
	fi
done

if [ "$PAM_AUTH" = "$PAM_ACCOUNT" ] && [ "$PAM_AUTH" = "$PAM_PASSWORD" ] && [ "$PAM_AUTH" = "$PAM_SESSION" ]; then
	# shellcheck disable=SC2086
	unset ${ARG#PAM_AUTH }
fi

VAR='EXCL_LOCALGROUPS LOCALGROUPS'

for var in $VAR; do
	if [ "${!var}" ]; then
		ARG="${!var}" && unset "$var"

		for arg in $ARG; do
			if cut -d ':' -f 1 "$GRPFILE" | grep -xq "$arg"; then
				export "${var}=${!var:+${!var} }$arg"
			fi
		done
	fi
done

if [ "${WBD_USERPROFILE:0:1}" != '/' ] || ! echo "$WBD_USERPROFILE" | grep -q '%U'; then
	WBD_USERPROFILE='/home/%U'
fi

if [ -x "$WBD_USERSHELL" ]; then
	str=$(stat -c %A "$WBD_USERSHELL")

	[ "${str:(-1)}" = 'x' ] || unset WBD_USERSHELL
fi

WBD_USERSHELL=${WBD_USERSHELL:=$(command -v bash)}

PAM_MOD_DIR=${PAM_MOD_DIR:='/lib /lib64 /usr/lib /usr/lib64'} ; unset DIR

for dir in $PAM_MOD_DIR; do
	if [ -d "$dir" ]; then
		if [ "${dir:(-1)}" = '/' ]; then
			DIR=${DIR:+${DIR} }${dir%/}
		else
			DIR=${DIR:+${DIR} }${dir}
		fi
	fi
done

PAM_MOD_DIR="$DIR"


# Declaring special variables
KRB_PRINCIPAL_NAMES=${KRB_PRINCIPAL_NAMES:='host cifs ipp http'}
FALLNTPSRV=${FALLNTPSRV:='pool.ntp.org'}
QTTLTIME=${QTTLTIME:='7d'}
DEFAULTUSER=$(grep ":${DEFAULTUSERID}:" "$PWDFILE" | cut -d ':' -f 1) ; export DEFAULTUSER
MAX_LOCAL_ID=$(grep -v nobody "$PWDFILE" | cut -d ':' -f 3 | sort -n | tail -1) && MAX_LOCAL_ID=${MAX_LOCAL_ID:=${DEFAULTUSERID}}
SMBSPOOLDIR=${SMBSPOOLDIR:=/var/spool/samba}
WBCACHEFILE='gencache.tdb' ; export WBCACHEFILE
export OLDLOGONSCRIPTDIR=${NETLOGON}/scripts_cid
export LOGONSCRIPTDIR=${NETLOGON}/cid

unset str DIR FILE ARG PAM VAR


# Logon_Variables Function
function Logon_Variables () {
	unset str USERNAME USERID GROUPID USERPROFILE USERSHELL USERGROUP USERDOMAIN USERGROUPS

	[ "$1" ] || return 1
	[ "$2" ] && return 0

	local str ; str=$(wbinfo -i "$1")
	USERID=$(echo "$str" | cut -d ':' -f 3) && USERID=${USERID:=$(id -u "$1")}

	[ "$USERID" -ge "$MIN_ID" ] || return 1

	USERNAME=$1
	GROUPID=$(echo "$str" | cut -d ':' -f 4)
	USERPROFILE=$(echo "$str" | cut -d ':' -f 6)
	USERSHELL=$(echo "$str" | cut -d ':' -f 7)
	USERGROUP=$(wbinfo --gid-info="$GROUPID" | cut -d ':' -f 1)

	if echo "${1/\\/@}" | grep -oq '@'; then
		USERDOMAIN=${1%\\*}
	else
		USERDOMAIN=$DOMAIN
	fi

	local ln

	for int in $(id -Gr "$1"); do
		if [ "$int" -ge "$MIN_ID" ]; then
			USERGROUPS=${USERGROUPS:+${USERGROUPS},}$(wbinfo --gid-info="$int" | cut -d ':' -f 1)
		else
			unset ln ; ln=$(cut -d ':' -f 3 "$GRPFILE" | grep -xn "$int")
			[ "$ln" ] && USERGROUPS=${USERGROUPS:+${USERGROUPS},}$(sed -n "${ln%:*}p" "$GRPFILE" | cut -d ':' -f 1)
		fi
	done

	export USERNAME USERID GROUPID USERPROFILE USERSHELL USERGROUP USERDOMAIN USERGROUPS NETLOGON
	return 0
}


# Creating temporary directory and file
[ ! -d "$TEMPDIR" ] && mkdir -p "$TEMPDIR"
[ "$(stat -c "%a" "$TEMPDIR")" != "777" ] && chmod 777 "$TEMPDIR"
TEMPFILE="$(mktemp -u -p "$TEMPDIR" 2>/dev/null)" ; TEMPFILE=${TEMPFILE:=${TEMPDIR}/output.log}