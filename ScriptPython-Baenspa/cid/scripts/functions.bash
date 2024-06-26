#!/usr/bin/env bash
# Description: Functions File
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


# Function: Message
Message () {
	if echo "${0##*/}" | grep -Eq "gtk|form"; then
		zenity --"$2" --title="${3:-Closed In Directory}" --ellipsize --text="$1" 2>/dev/null
	else
		local int

		if [ "$2" = "error" ]; then int=2; else int=1; fi

		echo -e "$1" >&"${int}"
	fi
}

# Function: Run
Run () {
	local function status

	if [ "$1" ]; then
		function="$1"
	else
		# shellcheck disable=SC2153
		function="${FUNCTION^}"
	fi

	# shellcheck disable=SC2153
	$function "$3" >"$TEMPFILE" 2>&1 ; status="$?"
	"${SCRIPTDIR}/logger.bash" "$TEMPFILE" "${2:-"${0##*/} >> ${function}"}" "$status" 2>/dev/null

	return "$status"
}

# Function: Check_Options
Check_Options () {
	echo "${2:-$OPTIONS}" | grep -wq "$1" ; return $?
}

# Function: Get_Flag
Get_Flag () {
	if ! Check_Options "$1" "${4:-$MODO}"; then
		echo "$2"
	else
		echo "$3"
	fi
}

# Function: Check_Backslash
Check_Backslash () {
	echo "$1" | grep -q '@' ; return $?
}

# Function: Backslash
Backslash () {
	local str=${1/\\/@}

	if Check_Backslash "$str"; then
		echo "${str%@*}\\\\${str#*@}"
	else
		echo "$str"
	fi
}

# Function: Get_IP
Get_IP () {
	if [ "$1" ]; then
		ip -br a | grep -w "$1" | awk '{print $1}'
	else
		ip -br a | awk '/(U|u)(P|p)/ {$1="";$2="";print $0}' | sed 's/^ *//g'
	fi
}

# Function: Get_DomainIP
Get_DomainIP () {
	local ip

	if [ "${1:0:6}" = 'fe80::' ]; then
		if ! ip=$(ping -6 -q -W 1 -c 1 "${FQDN}%$(Get_IP "$1")" 2>/dev/null); then return 1; fi
	elif [ -n "$1" ]; then
		if ! ip=$(ping -q -W 1 -c 1 -I "$1" "$FQDN"); then return 1; fi
	else
		if ! ip=$(ping -q -W 1 -c 1 "$FQDN"); then return 1; fi
	fi

	ip=${ip#*\(} && ip=${ip%% *} && ip=${ip%)*}

	echo "$ip" ; return 0
}

# Function: Check_Keytab
Check_Keytab () {
    if [ "$KEYTABFILE" = "/etc/krb5.keytab" ]; then return 0; else return 1; fi
}

# Function: Show_State
Show_State () {
	function ChkRole_RtrnStr () {
		Get_ObjID 'share' "$1" "$2"

		if [ "$INT" ]; then
			echo "${3:-Enabled}"
		else
			echo "${4:-Disabled}"
		fi
	}

	echo "FQDN: ${HOSTNAME,,}${FQDN:+.$FQDN}
IP Addresses:
$(Get_IP | sed -r 's/ +/\n/g' | sed 's/^/\t/g')

Domain: $FQDN
NetBIOS Domain: $DOMAIN
Organization Unit: $OU
Idmap Backend: $BACKEND
Minimum ID: $MIN_ID
Maximum ID: $MAX_ID
IDs per Domain: $ID_RANGE_SIZE
Maximum of Domains: $MAX_NUM_DOMAINS
Winbind NSS: $NSSINFO
Default User Profile: $WBD_USERPROFILE
Default User Shell: $WBD_USERSHELL

Fallback NTP Servers: $FALLNTPSRV

Joined by: $DOMAINUSER
Date of joined: $DATE
Join Options:
    - NetBIOS over TCP/IP: $(Get_Flag 1 'Yes' 'No')
    - Kerberos Authentication: $(Get_Flag 2 'Yes' 'No')
    - Credentials Cache: $(Get_Flag 3 'Yes' 'No')
    - Logon Script: $(Get_Flag 4 'Yes' 'No')
    - Default Domain: $(Get_Flag 5 'Yes' 'No')
    - Authenticate sudo: $(Get_Flag 6 'No' 'Yes')
    - RFC 2307: $(Get_Flag 7 'No' 'Yes')
    - Share All Printers: $(Get_Flag 8 'No' 'Yes')
    - Keytab Method: $(Get_Flag 9 'No' 'Yes')
	  - Keytab File: $(if [ "$(Get_Flag 9 'No' 'Yes')" = 'Yes' ]; then echo "${KEYTABFILE}"; else echo 'Not applicable'; fi)
	  - Kerberos Principal Names: $(if [ "$(Get_Flag 9 'No' 'Yes')" = 'Yes' ] && Check_Keytab; then echo "$KRB_PRINCIPAL_NAMES"; else echo 'Not applicable'; fi)
    - Additional Config File for Samba: $(if [ "$(Get_Flag 10 'No' 'Yes')" = "Yes" ]; then echo "${ADDSMBFILE}"; else echo 'Not applicable'; fi)

File Server Role: $(if [ "$(ChkRole_RtrnStr 'common' 'SHAREMODE')" = 'Enabled' ]; then echo 'Enabled'; else ChkRole_RtrnStr 'userfolder' 'SHAREMODE'; fi)
  - Tolerance Quota Time: $(ChkRole_RtrnStr '[0-9]+' 'SHAREQUOTA' "$QTTLTIME" 'Not applicable')
Print Server Role: $(if [ "$(ChkRole_RtrnStr 'printer' 'SHAREMODE')" = 'Enabled' ] || [ "$(Get_Flag 8 'No' 'Yes')" = "Yes" ]; then echo 'Enabled'; else echo 'Disabled'; fi)

Log Size: $(if [ "$LOGSIZE" -eq 0 ]; then echo 'Disabled'; else echo "${LOGSIZE}"; fi)
Default User ID: $DEFAULTUSERID
Other Local Groups: $LOCALGROUPS
Excluded local groups: $EXCL_LOCALGROUPS
Additional PAM Auth Modules: $ADD_PAM_AUTHMOD

System Paths:
    - Local Users File: $(if [ -f "$PWDFILE" ]; then echo "$PWDFILE"; else echo 'Unknown'; fi)
    - Local Groups File: $(if [ -f "$GRPFILE" ]; then echo "$GRPFILE"; else echo 'Unknown'; fi)
    - Local Groups Pass File: $(if [ -f "$GSDWFILE" ]; then echo "$GSDWFILE"; else echo 'Unknown'; fi)
    - Local Host Lookup File: $(if [ -f "$HOSTFILE" ]; then echo "$HOSTFILE"; else echo 'Unknown'; fi)
    - PAM Auth File: $(if [ -n "$PAM_AUTH" ]; then echo "$PAM_AUTH"; else echo 'Unknown'; fi)
    - PAM Account File: $(if [ -n "${PAM_ACCOUNT:-$PAM_AUTH}" ]; then echo "${PAM_ACCOUNT:-$PAM_AUTH}"; else echo 'Unknown'; fi)
    - PAM Password File: $(if [ -n "${PAM_PASSWORD:-$PAM_AUTH}" ]; then echo "${PAM_PASSWORD:-$PAM_AUTH}"; else echo 'Unknown'; fi)
    - PAM Session File: $(if [ -n "${PAM_SESSION:-$PAM_AUTH}" ]; then echo "${PAM_SESSION:-$PAM_AUTH}"; else echo 'Unknown'; fi)
    - Pam-Mount Config File: $(if [ -f "$MOUNTFILE" ]; then echo "$MOUNTFILE"; else echo 'Unknown'; fi)
    - NSS Config File: $(if [ -f "$NSSFILE" ]; then echo "$NSSFILE"; else echo 'Unknown'; fi)
    - Kerberos Config File: $(if [ -f "$KRBFILE" ]; then echo "$KRBFILE"; else echo 'Unknown'; fi)
    - Samba Config File: $(if [ -f "$SMBFILE" ]; then echo "$SMBFILE"; else echo 'Unknown'; fi)
    - NTP Config File: $(if [ -f "$NTPFILE" ]; then echo "$NTPFILE"; else echo 'Unknown'; fi)
    - LightDM Config File: $(if [ -f "$LDMFILE" ]; then echo "$LDMFILE"; else echo 'Unknown'; fi)
    - Sudo Files Directory: $(if [ -d "$SUDODIR" ]; then echo "$SUDODIR"; else echo 'Unknown'; fi)
    - Profile Directory: $(if [ -d "$PROFILEDIR" ]; then echo "$PROFILEDIR"; else echo 'Unknown'; fi)
    - Unit File Directory: $(if [ -d "$SYSTEMDDIR" ]; then echo "$SYSTEMDDIR"; else echo 'Unknown'; fi)
    - PAM Library Directory: $PAM_MOD_DIR
    - Printer Drivers Directory: $PRTDRVDIR
    - Netlogon Mount Point: $NETLOGON

Lock type: ${LOCK_TYPE^}
Locked to (Name): ${LOCKED_BY_NAME/@/\\}
Locked to (SID): $LOCKED_BY_SID"
}

# Function: Check_Hostname
Check_Hostname () {
	[ "${#1}" -gt 15 ] && return 1
	[ "${1:0:1}" == '-' ] && return 2

	if echo "$1" | grep -E "[^[:alnum:]]" | grep -vq '-'; then
		return 3
	else
		return 0
	fi
}

# Function: Set_Hostname
Set_Hostname () {
	hostnamectl set-hostname "$1" && sed -i "s/$HOSTNAME/$1/g" "$HOSTFILE" && export HOSTNAME="$1"
}

# Function: Set_Stamp
Set_Stamp () {
	echo "# [Modified by CID]
#
# This file has been modified by the CID (Closed In Directory) program.
# A copy of its previous state was saved in ${BACKUPDIR}$1
# and in ${RESTOREDIR}$1 if the program has made a
# reconfiguration in the file.
# For more details, see: https://cid-doc.github.io."
}

# Function: Check_Stamp
Check_Stamp () {
	grep -awq 'Modified by CID' "$1"; return $?
}

# Function: Backup
# shellcheck disable=SC2120
Backup () {
	if [ "$1" ]; then
		local FILE=$1
	else
		local FILE="$NSSFILE
$HOSTFILE
$KRBFILE
$SMBFILE
$NTPFILE
$MOUNTFILE
$PAM_AUTH
$PAM_ACCOUNT
$PAM_PASSWORD
$PAM_SESSION
$LDMFILE
${GRPFILE}*
${GSDWFILE}*"
	fi

	local file

	for file in $FILE; do
		if [ -f "$file" ] && ! Check_Stamp "$file"; then
            if [ -L "$file" ]; then
				file=$(readlink -m "$file")
			fi

			if [ ! -f "${BACKUPDIR}$file" ]; then
				[ ! -d "${BACKUPDIR}${file%/*}" ] && mkdir -p "${BACKUPDIR}${file%/*}"

				cp -pf "$file" "${BACKUPDIR}$file"
			else
				if ! diff -q "${BACKUPDIR}$file" "$file" >/dev/null 2>&1; then
					cp -pf "$file" "${BACKUPDIR}$file"
				fi
			fi
		fi
	done
}

# Function: Tempfile
Tempfile () {
	mktemp -u -p "$TEMPDIR" 2>/dev/null || for ((int=0; int >= 0 ; int++)); do [ ! -f "${TEMPDIR}/${1}${int}" ] && echo "${TEMPDIR}/${1}${int}" && break; done
}

# Function: Check_NoNum
Check_NoNum () {
	echo "$1" | grep -Eq "[^[:digit:]]" ; return $?
}

# Function: Get_IntValue
Get_IntValue () {
    echo "${1}${2}(1024^${3})" | bc | cut -d '.' -f 1
}

# Function: Get_NumLines
Get_NumLines () {
	wc -l "$1" | awk '{print $1}'
}

# Function: Config_nssfile
Config_nssfile () {
	local tempfile ; tempfile="$(Tempfile 'nss')"

	grep -Ev "^[[:blank:]]*#" "$NSSFILE" >"$tempfile"
	sed -i "s/^\t//g" "$tempfile"

	local PAR ; PAR=$(echo -e "passwd:winbind;group:winbind;hosts:\t\tfiles dns;initgroups:[success=continue] winbind")
	local int IFS=';'

	for par in $PAR; do
		int=$(grep -aEwn "^${par%%:*}" "$tempfile" | cut -d ':' -f 1)

		[ "$int" ] || continue

        if [ "${par%%:*}" = "hosts" ]; then
    		sed -i "${int}d" "$tempfile" && sed -i "${int}s/^/$par\n/" "$tempfile"
        else
            if ! sed -n "${int}p" "$tempfile" | grep -wq "${par##*:}"; then
				sed -i "${int}s/$/ ${par##*:}/" "$tempfile"
			fi
        fi
	done

	echo -e "$(Set_Stamp "$NSSFILE")\n\n$(cat "$tempfile")" >"$NSSFILE"
}

# Function: Config_hostfile
Config_hostfile () {
	local IP ; IP="$(Get_IP)"

	if [ "$IP" ]; then
		IP=$(echo "$IP" | sed -r 's/\/[0-9]{1,3}//g')
	else
		return 255
	fi

	local tempfile ; tempfile="$(Tempfile 'hosts')"

	echo -e "$(Set_Stamp "$HOSTFILE")\n\n$(grep -aEv "^[[:blank:]]*#|^$|$HOSTNAME" "$HOSTFILE")" >"$tempfile"

	for ip in ${IP,,}; do
		if Get_DomainIP "$ip" >/dev/null; then sed -i "8s/^/\n$ip\t$HOSTNAME.$FQDN\t$HOSTNAME/" "$tempfile"; fi
	done

	if grep -awq "$HOSTNAME" "$tempfile"; then
		cp -f "$tempfile" "$HOSTFILE" && return 0
	else
		return 1
	fi
}

# Function: Config_krbfile
Config_krbfile () {
	echo "$(Set_Stamp "$KRBFILE")

[libdefaults]
	default_realm = ${FQDN^^}
	dns_lookup_realm = false
	dns_lookup_kdc = true
	default_keytab_name = FILE:$KEYTABFILE" >"$KRBFILE"
}

# Function: Config_smbfile
Config_smbfile () {
	function Filter_AddCfgFile () {
		local tempfile STR PAR

		tempfile="$(Tempfile 'smb')" && rm -f "$tempfile"

        STR='apply group policies|browse?able|comment|create mask|dedicated keytab file|directory( mask)?|disable (netbios|spoolss)|force (create|directory) mode|guest ok|idmap (backend|config.*|gid|uid)|inherit (acls|permissions)|kerberos method|load printers|map (acl inherit|archive|hidden|system)|path|printable|printcap( name)?|printer( name)?|printing|print ok|public|read (list|only)|realm|root preexec|security|server role|smb ports|store dos attributes|template (homedir|shell)|winbind (expand groups|gid|normalize names|nss info|offline logon|refresh tickets|request timeout|separator|uid|use default domain)|valid users|workgroup|write?able|write (list|ok)'

		testparm -sv 2>/dev/null | grep -Ex ".+=.+" | cut -d '=' -f 1 | sed -r 's/^[[:blank:]]+//g;s/[[:blank:]]+$//g' | grep -Exiv "$STR" >"$tempfile"

		unset PAR

		while read -r str; do
			PAR=${PAR:+${PAR}\|}"$str"
		done < "$tempfile"

		[ "$PAR" ] || return 255

        sed -r 's/[[:blank:]]+/ /g;s/^[[:blank:]]+//g;s/[[:blank:]]+$//g' "$1" | grep -Exi "(${PAR}|[^(#|;)].+:.+)[[:blank:]]?=.+" >"$tempfile"

		if [ "$2" = 'common' ]; then
			if grep -awiq 'vfs objects' "$tempfile"; then
				sed -i "$(Get_NumLines "$SMBFILE")d" "$SMBFILE"

				if ! grep -aExiq "vfs objects[[:blank:]]?=.*acl_xattr.*" "$tempfile"; then
					sed -ri 's/vfs objects *= */vfs objects = acl_xattr /Ig' "$tempfile"
				fi
			fi
		fi

		echo -e "\n\t# Imported from: ${1}" >> "$SMBFILE"
		sed -r 's/^/\t/g' "$tempfile" >> "$SMBFILE"
	}

	echo "$(Set_Stamp "$SMBFILE")

[global]
	# SMB settings
	workgroup = $DOMAIN
	security = ADS
	smb ports = 445
	disable netbios = Yes
	load printers = No
	disable spoolss = Yes
	printcap name = cups
	printing = cups

	# Kerberos settings
	realm = ${FQDN^^}
	kerberos method = dedicated keytab
	dedicated keytab file = $KEYTABFILE

	# Winbind settings
	apply group policies = Yes
	winbind expand groups = 1
	winbind use default domain = Yes
	winbind refresh tickets = Yes
	winbind offline logon = Yes
	winbind request timeout = 5
	template homedir = $WBD_USERPROFILE
	template shell = $WBD_USERSHELL" > "$SMBFILE"

	if ! Check_Options 1; then sed -ri '/(smb ports|disable netbios)/d' "$SMBFILE"; fi
	if Check_Options 2; then sed -i '/winbind refresh tickets = Yes/d' "$SMBFILE"; fi
	if Check_Options 3; then sed -ri '/(winbind offline logon = Yes|winbind request timeout = 5)/d' "$SMBFILE"; fi
	if Check_Options 4 || ! command -v samba-gpupdate >/dev/null 2>&1; then sed -i '/apply group policies = Yes/d' "$SMBFILE"; fi
	if Check_Options 5; then sed -i '/winbind use default domain = Yes/d' "$SMBFILE"; fi
	if ! Check_Options 9; then sed -ri '/(dedicated keytab file|kerberos method)/d' "$SMBFILE"; fi

	if Check_Options 8; then
		sed -ri '/(load printers = No|disable spoolss)/d' "$SMBFILE"
		local bool=true
	else
		sed -ri '/(printcap name|printing)/d' "$SMBFILE"
		unset bool
	fi

	if Check_Options 7; then
		# shellcheck disable=SC2072
		if [ "$(smbd -V | grep -Eo "[[:digit:]]+\.[[:digit:]]+")" \< "4.6" ]; then
			echo "	winbind nss info = $NSSINFO" >> "$SMBFILE"
		else
			if [ "$NSSINFO" = "rfc2307" ]; then
				echo -e "\tidmap config $DOMAIN : unix_nss_info = Yes\n\tidmap config $DOMAIN : unix_primary_group = Yes" >> "$SMBFILE"
			fi
		fi

		echo "	idmap config $DOMAIN : backend = ${BACKEND}
	idmap config $DOMAIN : schema_mode = rfc2307
	idmap config $DOMAIN : range = ${MIN_ID}-${MAX_ID}
	idmap config * : range = $((MAX_ID+1))-$((MAX_ID+(ID_RANGE_SIZE*(MAX_NUM_DOMAINS-1))))" >> "$SMBFILE"
	else
		if [ "$MAX_LOCAL_ID" -ge 10000 ]; then
			MIN_ID=$((MAX_LOCAL_ID+1000))
		else
			MIN_ID=10000
		fi

		MAX_ID=$((MIN_ID+((ID_RANGE_SIZE*MAX_NUM_DOMAINS)-1)))
		BACKEND=autorid
		NSSINFO=template
		echo "	idmap config * : range = ${MIN_ID}-${MAX_ID}" >> "$SMBFILE"
	fi

	echo -e "\tidmap config * : backend = autorid\n\tidmap config * : rangesize = ${ID_RANGE_SIZE}" >> "$SMBFILE"

	if Check_Options 10 && [ -s "$ADDSMBFILE" ]; then
		Filter_AddCfgFile "$ADDSMBFILE"
	fi

	if [ -s "${DBDIR}/shareList.db" ]; then
		# shellcheck source=/dev/null
		. "${DBDIR}/shareList.db"

		# shellcheck disable=SC2153
		for ((int=0; int < ${#SHARENAME[*]}; int++)); do
			echo -e "\n[$(if [ "${SHAREMODE[${int}]}" = 'userfolder' ]; then echo 'homes'; else echo "${SHARENAME[${int}]}"; fi)]
	comment = ${SHARECOMMENT[${int}]}
	read only = No
	guest ok = ${SHAREGUEST[${int}]}
	browseable = $(if [ "${SHAREHIDDEN[${int}]}" = 'No' ]; then echo 'Yes'; else echo 'No'; fi)" >> "$SMBFILE"

			[ -n "${SHARETEMPLATE[${int}]}" ] && echo -e "\tcopy = ${SHARETEMPLATE[${int}]}" >> "$SMBFILE"

			case "${SHAREMODE[${int}]}" in
				'printer'		)
									echo "	path = \"$SMBSPOOLDIR\"
	printer name = ${SHAREPATH[${int}]}
	printable = Yes" >> "$SMBFILE"
									local bool=${bool:=true}
								;;

				'userfolder'	)
									echo "	path = \"${SHAREPATH[${int}]}/%S\"
	inherit permissions = Yes
	root preexec = ${SCRIPTDIR}/mkhomedir.bash \"${SHAREPATH[${int}]}/%S\" %u \"%g\" %D ${SHAREQUOTA[${int}]} ${SHARETOLERANCE[${int}]}
	valid users = $(if Check_Options 5; then echo '%D%w%S'; else echo '%S'; fi)" >> "$SMBFILE"
								;;

				'common'		)
									[ "${SHAREQUOTASUBD[${int}]}" = 'Yes' ] && echo "	root preexec = ${SCRIPTDIR}/setquota.bash \"${SHAREPATH[${int}]}\" ${SHAREQUOTA[${int}]} ${SHARETOLERANCE[${int}]}" >> "$SMBFILE"

									echo "	path = \"${SHAREPATH[${int}]}\"
	map acl inherit = Yes
	store dos attributes = Yes
	vfs objects = acl_xattr" >> "$SMBFILE"
								;;
			esac

			[ -s "${SHARECFGFILE[${int}]}" ] && Filter_AddCfgFile "${SHARECFGFILE[${int}]}" "${SHAREMODE[${int}]}"
		done
	fi

	[ "$bool" ] && echo "
[printers]
	path = $SMBSPOOLDIR
	printable = yes

[print$]
	comment = Printer Drivers for Windows Clients
	path = $PRTDRVDIR
	browseable = Yes
	read only = No
	guest ok = No" >> "$SMBFILE"
}

# Function: Config_ntpfile
Config_ntpfile () {
    echo "$(Set_Stamp "$NTPFILE")

[Time]
NTP=$FQDN
FallbackNTP=$FALLNTPSRV" > "$NTPFILE"
}

# Function: Get_NameSRVC
Get_NameSRVC () {
	systemctl list-unit-files | grep -Eo "${1}d?.service"
}

# Function: Manage_Service
Manage_Service () {
	if ! command -v systemctl >/dev/null 2>&1; then return 1; fi

	local str ; str=$(Get_NameSRVC "$1")

	[ "$str" ] && systemctl "$2" "$str"
}

# Function: Pre_Join
Pre_Join () {
	# shellcheck disable=SC2119
	Backup

	local FILE='NSSFILE HOSTFILE KRBFILE SMBFILE NTPFILE'

	for file in $FILE; do
		if [ ! -f "${!file}" ]; then
			echo "File ${!file} not found!" >&2
		else
			"Config_${file,,}"
		fi
	done

	Manage_Service 'systemd-timesyncd' 'restart'
	smbd -s "$SMBFILE"
}

# Function: Join
Join () {
	if [ -n "$HOST" ] && [ "$HOST" != "$HOSTNAME" ]; then
		Set_Hostname "$HOST"
	fi

	Pre_Join

	local os os_ver

	if [ -f "$OSFILE" ]; then
		os=$(grep -Ex "^ *NAME=.+" "$OSFILE" | cut -d '=' -f 2 | tr -d '"')
		os_ver=$(grep -Ex "^ *VERSION_ID=.+" "$OSFILE" | cut -d '=' -f 2 | tr -d '"')
	fi

	os=${os:='Closed In Directory'}
	os_ver=${os_ver:=${VERSION}}

	if net ads join osName="$os" osVer="$os_ver" createcomputer="$OU" -U "$DOMAINUSER"%"$PASS"; then
		return 0
	else
		local ip ; unset ip

		if ip=$(Get_DomainIP); then
			if net ads join osName="$os" osVer="$os_ver" createcomputer="$OU" -S "$ip" -U "$DOMAINUSER"%"$PASS"; then return 0; fi
		fi

		local str ; str=$(grep -aEio "\"workgroup\" set to '${DOMAIN}', should be '[[:graph:]]+'" "$TEMPFILE" | tr -d \')

		if [ -n "$str" ]; then
			str=${str##*should be } && DOMAIN=${str^^}
			Config_smbfile

			if net ads join osName="$os" osVer="$os_ver" createcomputer="$OU" -U "$DOMAINUSER"%"$PASS"; then
				return 4
			else
				if [ "$ip" ]; then
					if net ads join osName="$os" osVer="$os_ver" createcomputer="$OU" -S "$ip" -U "$DOMAINUSER"%"$PASS"; then return 4; fi
				fi
			fi
		fi

		if [ "$TEST_OU" -eq 1 ]; then
			if net ads join osName="$os" osVer="$os_ver" createcomputer='Computers' -U "$DOMAINUSER"%"$PASS"; then
				return 1
			else
				if [ "$ip" ]; then
					if net ads join osName="$os" osVer="$os_ver" createcomputer='Computers' -S "$ip" -U "$DOMAINUSER"%"$PASS"; then return 1; fi
				fi

				if net ads join osName="$os" osVer="$os_ver" -U "$DOMAINUSER"%"$PASS"; then
					return 2
				else
					if [ -n "$ip" ]; then
						if net ads join osName="$os" osVer="$os_ver" -S "$ip" -U "$DOMAINUSER"%"$PASS"; then return 2; fi
					fi
				fi
			fi
		else
			if net ads join osName="$os" osVer="$os_ver" -U "$DOMAINUSER"%"$PASS"; then
				return 3
			else
				if [ "$ip" ]; then
					if net ads join osName="$os" osVer="$os_ver" -S "$ip" -U "$DOMAINUSER"%"$PASS"; then return 3; fi
				fi
			fi
		fi
	fi

	return 255
}

# Function: Restore
Restore () {
	if [ "$1" ]; then
		local FILE=$1
	else
		local FILE="$NSSFILE
$HOSTFILE
$KRBFILE
$SMBFILE
$NTPFILE
$CUPSFILE
$MOUNTFILE
$LDMFILE
$CUPSBKDFILE
$PAM_AUTH
$PAM_ACCOUNT
$PAM_PASSWORD
$PAM_SESSION"
	fi

	local file

	for file in $FILE; do
        [ -L "$file" ] && file=$(readlink -m "$file")

		if [ -f "${BACKUPDIR}$file" ]; then
			[ ! -d "${RESTOREDIR}${file%/*}" ] && mkdir -p "${RESTOREDIR}${file%/*}"
			cp -pf "$file" "${RESTOREDIR}$file"
			cp -pf "${BACKUPDIR}$file" "$file"
		elif [ "$file" = "$CUPSBKDFILE" ] && [ -f "$file" ]; then
			if Check_Stamp "$file"; then
				rm -f "$file"
				ln -s "${SMBSPOOLFILE:-$(command -v smbspool)}" "$file"
			fi
		fi
	done
}

# Function: Create_Keytab
Create_Keytab () {
	if Check_Options 9 && Check_Keytab; then true; else return 1; fi

	function Add_SPN () {
		for s in $1; do
			for h in $2; do
				net ads keytab add "${s}/${h}.${FQDN,,}@${FQDN^^}" -P
				net ads keytab add "${s}/${h^^}@${FQDN^^}" -P
				net ads keytab add "${s^^}/${h}.${FQDN,,}@${FQDN^^}" -P
				net ads keytab add "${s^^}/${h^^}@${FQDN^^}" -P
			done
		done
	}

	local hst srv

	if [ -f "$KEYTABFILE" ]; then
		net ads keytab flush -P
	else
		net ads keytab create -P
	fi

	for str in $KRB_PRINCIPAL_NAMES; do
		if echo "$str" | grep -q '/'; then
			if [ "${str:0:1}" = '/' ]; then
				hst="${hst:+${hst} }${str:1}"
			else
				Add_SPN "${str%/*}" "${str#*/}"
			fi
		else
			srv="${srv:+${srv} }$str"
		fi
	done

	hst="${hst:+${hst} }$HOSTNAME"

	Add_SPN "$srv" "$hst"
}

# Function: Get_AdminsGroup
# shellcheck disable=SC2120
Get_AdminsGroup () {
	wbinfo --gid-info="$(wbinfo -Y "$(wbinfo -D "$FQDN" 2>/dev/null | grep -Eo "S-1-5-21-[[:graph:]]+")-${1:-512}" 2>/dev/null)" 2>/dev/null | cut -d ':' -f 1
}

# Function: Check_SMBDirs
Check_SMBDirs () {
	local ARG='PRTDRVDIR:2775 SMBSPOOLDIR:1777'

	for arg in $ARG; do
		local dir=${arg%%:*}
		[ -d "${!dir}" ] || mkdir -p "${!dir}"
		[ "$(stat -c "%a" "${!dir}")" = "${arg##*:}" ] || chmod -R "${arg##*:}" "${!dir}"
	done

	local str

	# shellcheck disable=SC2119
	str="$(Get_AdminsGroup)"

	if [ "$str" ] && [ "$(stat -c "%G" "$PRTDRVDIR")" != "$str" ]; then
		chgrp -R "$str" "$PRTDRVDIR"
	fi

	unset str

	if [ -d "$OLDPRTDRVDIR" ] && [ "$OLDPRTDRVDIR" != "$PRTDRVDIR" ] && [ "$(stat -c "%G" "$OLDPRTDRVDIR" 2>/dev/null)" != "root" ]; then
		chgrp -R root "$OLDPRTDRVDIR"
	fi
}

# Function: Set_ToleranceQtTime
Set_ToleranceQtTime () {
	[ -s "${DBDIR}/quotaList.db" ] && xfs_quota -xc "timer $QTTLTIME -p"
}

# Function: Config_ldmfile
Config_ldmfile () {
	[ "$(command -v lightdm)" ] || return 127

	if [ ! -f "$LDMFILE" ]; then
		[ -d "${LDMFILE%/*}" ] || mkdir -p "${LDMFILE%/*}"

		if [ ! -f "${BACKUPDIR}$LDMFILE" ]; then
			[ -d "${BACKUPDIR}${LDMFILE%/*}" ] || mkdir -p "${BACKUPDIR}${LDMFILE%/*}"
			true >"${BACKUPDIR}$LDMFILE"
		fi

		echo -e "# [Modified by CID]\n#\n# This file was generated by the CID (Closed In Directory) program.\n# No original copy detected!\n\n[Seat:*]\ngreeter-show-manual-login=true\nallow-guest=false\nautologin-user=" > "$LDMFILE"
	else
		if Check_Stamp "$LDMFILE"; then
			Restore "$LDMFILE"
		fi

		sed -ri "/^[[:blank:]]*(#|$)|(greeter-show-manual-login|greeter-hide-users|allow-guest|autologin-user)=[[:graph:]]*/d" "$LDMFILE"

		local int
		int=$(grep -aExn "^[[:blank:]]*\[Seat\:\*\]" "$LDMFILE" | cut -d ':' -f 1 | tail -n 1)

		if [ "$int" ]; then
			sed -i "${int}s/$/\ngreeter-show-manual-login=true\nallow-guest=false\nautologin-user=/" "$LDMFILE"
		else
			echo -e "\n[Seat:*]\ngreeter-show-manual-login=true\nallow-guest=false\nautologin-user=" >> "$LDMFILE"
		fi

		sed -i "1s/^/# [Modified by CID]\n#\n# This file has been modified by the CID (Closed In Directory) program.\n# A copy of its previous state was saved in ${BACKUPDIR//\//\\/}${LDMFILE//\//\\/}\n# and in ${RESTOREDIR//\//\\/}${LDMFILE//\//\\/} if the program has made a\n# reconfiguration in the file.\n# For more details\, see\: https:\/\/cid-doc.github.io.\n\n/" "$LDMFILE"
	fi
}

# Function: Config_LogonScript
Config_LogonScript () {
	if Check_Options 4; then
		rm -f "${SUDODIR}/cid-sudo-allusers" "${PROFILEDIR}/cid.sh"
		return 0
	fi

	if [ -d "$SUDODIR" ]; then
		echo -e "# Run scripts CID as superuser without authentication\n\nALL ALL = NOPASSWD: ${SCRIPTDIR}/logger.bash\nALL ALL = NOPASSWD: ${SCRIPTDIR}/umount_netlogon.bash" >"${SUDODIR}/cid-sudo-allusers" && chmod 0440 "${SUDODIR}/cid-sudo-allusers"

		echo "[ \"\$(id -u)\" -ge \"$MIN_ID\" ] && ${SCRIPTDIR}/logon_commonUser.bash 2>/dev/null" >"${PROFILEDIR}/cid.sh"
		chmod 644 "${PROFILEDIR}/cid.sh"
	fi
}

#Function: Pam_CheckStamp
Pam_CheckStamp () {
	local FILE="$PAM_AUTH $PAM_ACCOUNT $PAM_PASSWORD $PAM_SESSION"

	for file in $FILE; do
		Check_Stamp "$file"

		[ "$?" -eq "$1" ] && return 0
	done

	return 1
}

# Function: Pam_FilterFile
Pam_FilterFile () {
    grep -aEv "^[[:blank:]]*#|^$" "$1" | sed -r "s/^( |\t)*//g" | grep -Ew "^-?$2" > "${TEMPDIR}/$2"

	local MOD

	MOD=$(grep -aEo "pam_winbind.so|pam_mount.so" "${TEMPDIR}/$2" | tac | awk '!i[$0]++')

	if [ -n "$MOD" ]; then
		local int ; int=$(($(Get_NumLines "${TEMPDIR}/$2")-1))

		while [ "$int" -gt 0 ]; do
			local PAR

			# shellcheck disable=SC2021
			PAR=$(sed -n "${int}p" "${TEMPDIR}/$2" | grep -Eo "\[[[:print:]]+\]" | tr -d '[,]' | sed -r "s/([[:blank:]]|\t)+/\n/g" | grep -Ew "[[:graph:]]+=[[:digit:]]+")

			for par in $PAR; do
				for mod in $MOD; do
					local LINE jump

					# shellcheck disable=SC2063
					LINE=$(grep -En "*" "${TEMPDIR}/$2" | sed -n "${int},$ p" | grep -w "$mod" | cut -d ':' -f 1 | tac) && unset jump

					for line in $LINE; do
						jump=${jump:=${par##*=}}

						if [ "${par##*=}" -ge "$((line-int))" ]; then
							if [ "$jump" -gt 1 ]; then
								sed -i "${int}s/${par%%=*}=${jump}/${par%%=*}=$((jump-1))/g" "${TEMPDIR}/$2" && jump=$((jump-1))
							else
								sed -i "${int}s/${par%%=*}=${jump}/${par%%=*}=ignore/g" "${TEMPDIR}/$2" && break
							fi
						fi
					done
				done
			done

			int=$((int-1))
		done

		sed -i '/pam_winbind.so/d;/pam_mount.so/d' "${TEMPDIR}/$2"
	fi

	grep -awn 'pam_unix.so' "${TEMPDIR}/$2" | sed -n '1p' | cut -d ':' -f 1
}

# Function: Pam_GetJump
Pam_GetJump () {
    sed -n "${2}p" "$1" | grep -Eo "success=[[:digit:]]+" | cut -d '=' -f 2
}

# Function: Pam_AddJump
Pam_AddJump () {
	local PAR int=$(($2-1))

	while [ "$int" -gt 0 ]; do
		# shellcheck disable=SC2021
		PAR=$(sed -n "${int}p" "$1" | grep -Eo "\[[[:print:]]+\]" | tr -d '[,]' | sed -r "s/([[:blank:]]|\t)+/\n/g" | grep -Ew "[[:graph:]]+=[[:digit:]]+")

		for par in $PAR; do
			[ "${par##*=}" -ge "$((${2}-int))" ] && sed -i "${int}s/$par/${par%%=*}=$((${par##*=}+$3))/g" "$1"
		done

		int=$((int-1))
	done
}

# Function: Config_PAM
Config_PAM () {
	function pam_auth {
		Pam_FilterFile "$1" 'auth'

		local flag mod str MOD int=2

		flag='try_first_pass'

		if ! Check_Options 2; then flag="$flag krb5_auth krb5_ccache_type=FILE" ; fi
		if ! Check_Options 3; then flag="$flag cached_login" ; fi
		[ -n "$LOCKED_BY_SID" ] && flag="$flag require_membership_of=$LOCKED_BY_SID"

		for mod in $ADD_PAM_AUTHMOD; do
			# shellcheck disable=SC2086
			if [ "$(find $PAM_MOD_DIR -type f -iname "${mod%:*}" -print -quit)" ]; then
				mod="${mod,,}"
			else
				continue
			fi

			if echo "$mod" | grep -q ':'; then
				if ! echo "${mod##*:}" | grep -Ewq "required|requisite|sufficient|optional"; then continue; fi

				str="${str:+${str}}auth\t${mod##*:}\t${mod%:*}\n"
			else
				str="${str:+${str}}auth\toptional\t${mod}\n"
			fi

			MOD="${MOD:+${MOD} }${mod}"
			int=$((int+1))
		done

		ADD_PAM_AUTHMOD="$MOD"

		sed -i "1s/^/auth\t[success=$(Get_Flag '4' "$int" "$((int-1))" "$OPTIONS") default=ignore]\tpam_succeed_if.so quiet uid < ${MIN_ID}\nauth\t[success=$(if ! Check_Options 4 || [ -n "$MOD" ]; then echo -n 'ok'; else echo -n 'done'; fi) default=die]\tpam_winbind.so $flag\n${str}auth\t[default=done]\tpam_mount.so\n/" "${TEMPDIR}/auth"

		if Check_Options 4; then
			if [ "$int" -gt 2 ]; then
				sed -ri "${int}s/optional/[default=done]/;${int}s/required|requisite|sufficient/[success=done default=die]/" "${TEMPDIR}/auth"
			fi

			sed -i '/pam_mount.so/d' "${TEMPDIR}/auth"
		else
			[ "$int" -gt 2 ] && sed -i "3,${int}s/sufficient/[success=ok default=die]/" "${TEMPDIR}/auth"
		fi

		return 0
    }

    function pam_account {
        Pam_FilterFile "$1" 'account'

        sed -i "1s/^/account\t[success=1 default=ignore]\tpam_succeed_if.so quiet uid < ${MIN_ID}\naccount\t[success=done new_authtok_reqd=done default=ignore]\tpam_winbind.so\n/" "${TEMPDIR}/account"

        return 0
    }

    function pam_password {
		local int ; unset int ; int=$(Pam_FilterFile "$1" 'password' 2> "$TEMPFILE")

        if [ -z "$int" ]; then
            sed -i "1s/^/password\tsufficient\tpam_winbind.so try_first_pass\n/" "${TEMPDIR}/password"
        else
            if [ "$int" -gt 1 ]; then
                local STR='pam_cracklib.so pam_pwquality.so pam_passwdqc.so'

                for str in $STR; do
                    for lin in $(sed -n "1,$int p" "${TEMPDIR}/password" | grep -awn "$str" | cut -d ':' -f 1 | tac); do
                        Pam_AddJump "${TEMPDIR}/password" "$lin" '1'
                        sed -i "${lin}s/^/password\t[success=1 default=ignore]\tpam_succeed_if.so quiet uid >= ${MIN_ID}\n/" "${TEMPDIR}/password"
                        int=$((int+1))
                    done
                done

                Pam_AddJump "${TEMPDIR}/password" "$int" '2'
            fi

            if [ "$(Pam_GetJump "${TEMPDIR}/password" "$int")" ]; then
                sed -i "${int}s/^/password\t[success=1 default=ignore]\tpam_succeed_if.so quiet uid < ${MIN_ID}\npassword\t[success=$(($(Pam_GetJump "${TEMPDIR}/password" "$int")+1)) default=die]\tpam_winbind.so try_first_pass\n/" "${TEMPDIR}/password"
            else
                sed -i "${int}s/^/password\t[success=1 default=ignore]\tpam_succeed_if.so quiet uid < ${MIN_ID}\npassword\t[success=done default=die]\tpam_winbind.so try_first_pass\n/" "${TEMPDIR}/password"
            fi
        fi

        return 0
    }

    function pam_session () {
        local int ; int=$(Pam_FilterFile "$1" 'session' 2> "$TEMPFILE")

        if [ -z "$int" ]; then
			int=$(($(Get_NumLines "${TEMPDIR}/session")+1))

            echo -e "session\t[success=done default=ignore]\tpam_succeed_if.so quiet uid < ${MIN_ID}\nsession\trequired\tpam_mkhomedir.so silent skel=/etc/skel/ umask=0077\nsession\toptional\tpam_winbind.so\nsession\t[success=$(Get_Flag '4' '4' '1' "$OPTIONS") default=ignore]\tpam_succeed_if.so quiet service != login service !~ ssh* service !~ xrdp* service !~ cdm* service !~ gdm* service !~ kdm* service !~ mdm* service !~ wdm* service !~ tdm* service !~ xdm* service !~ lxdm* service !~ sddm* service !~ lightdm* service !~ slim* service !~ qingy* service !~ entrance*\nsession\toptional\tpam_exec.so quiet ${SCRIPTDIR}/pre_logon.bash\nsession\toptional\tpam_mount.so\nsession\toptional\tpam_exec.so quiet ${SCRIPTDIR}/logon_superUser.bash\nsession\toptional\tpam_mount.so" >> "${TEMPDIR}/session"
        else
            [ "$int" -gt 1 ] && Pam_AddJump "${TEMPDIR}/session" "$int" "$(Get_Flag '4' '8' '5' "$OPTIONS")"

			sed -i "${int}s/^/session\t[success=$(Get_Flag '4' '7' '4' "$OPTIONS") default=ignore]\tpam_succeed_if.so quiet uid < ${MIN_ID}\nsession\trequired\tpam_mkhomedir.so silent skel=\/etc\/skel\/ umask=0077\nsession\toptional\tpam_winbind.so\nsession\t[success=$(Get_Flag '4' '4' '1' "$OPTIONS") default=ignore]\tpam_succeed_if.so quiet service != login service !~ ssh* service !~ xrdp* service !~ cdm* service !~ gdm* service !~ kdm* service !~ mdm* service !~ wdm* service !~ tdm* service !~ xdm* service !~ lxdm* service !~ sddm* service !~ lightdm* service !~ slim* service !~ qingy* service !~ entrance*\nsession\toptional\tpam_exec.so quiet ${SCRIPTDIR//\//\\/}\/pre_logon.bash\nsession\toptional\tpam_mount.so\nsession\toptional\tpam_exec.so quiet ${SCRIPTDIR//\//\\/}\/logon_superUser.bash\nsession\toptional\tpam_mount.so\n/" "${TEMPDIR}/session"
        fi

        if Check_Options 4; then sed -i "$((int+5)),$((int+7)) d" "${TEMPDIR}/session"; fi

        return 0
    }

	[ -z "$PAM_AUTH" ] && return 255

    find "${TEMPDIR}" -type f -name 'pam_*' -delete

	if Pam_CheckStamp 0; then Restore "$PAM_AUTH $PAM_ACCOUNT $PAM_PASSWORD $PAM_SESSION"; fi

	local file PAM='PAM_AUTH PAM_ACCOUNT PAM_PASSWORD PAM_SESSION'

	for pam in $PAM; do
		if [ "$pam" != "PAM_AUTH" ] && [ -z "${!pam}" ]; then
			local "${pam}"="$PAM_AUTH"
		fi

		for file in ${!pam}; do
			if [ -f "$file" ]; then
				[ -L "$file" ] && file=$(readlink -m "$file")

				if "${pam,,}" "$file"; then
					[ -f "${TEMPDIR}/pam_${file##*/}" ] || echo -e "$(Set_Stamp "$file")\n" > "${TEMPDIR}/pam_${file##*/}"

					echo -e "\n$(cat "${TEMPDIR}/$(echo "${pam##*_}" | tr '[:upper:]' '[:lower:]')")" >> "${TEMPDIR}/pam_${file##*/}"
                fi
			else
				echo "File ${file} not found!" >&2
			fi
		done
	done

	for pam in $PAM; do
		for file in ${!pam}; do
			[ -L "$file" ] && file=$(readlink -m "$file")
			[ -f "${TEMPDIR}/pam_${file##*/}" ] && cp -f "${TEMPDIR}/pam_${file##*/}" "$file"
		done
	done
}

# Function: Post_Join
Post_Join () {
	echo "# Data file of the current state of the station
FQDN=$FQDN
DOMAIN=$DOMAIN
OU='${OU}'
BACKEND=$BACKEND
MIN_ID=$MIN_ID
MAX_ID=$MAX_ID
NSSINFO=$NSSINFO
DOMAINUSER='${DOMAINUSER}'
DATE='${DATE:=$(date +%c)}'
MODO=$OPTIONS
LOGSIZE=$LOGSIZE
DEFAULTUSERID=$DEFAULTUSERID
LOCALGROUPS='${LOCALGROUPS}'
EXCL_LOCALGROUPS='${EXCL_LOCALGROUPS}'
ID_RANGE_SIZE=$ID_RANGE_SIZE
MAX_NUM_DOMAINS=$MAX_NUM_DOMAINS
KRB_PRINCIPAL_NAMES='${KRB_PRINCIPAL_NAMES}'
FALLNTPSRV='${FALLNTPSRV}'
QTTLTIME=$QTTLTIME
WBD_USERPROFILE=$WBD_USERPROFILE
WBD_USERSHELL=$WBD_USERSHELL
PROFILEDIR=$PROFILEDIR
SUDODIR=$SUDODIR
SYSTEMDDIR=$SYSTEMDDIR
PAM_MOD_DIR='$PAM_MOD_DIR'
NETLOGON=$NETLOGON
PRTDRVDIR=$PRTDRVDIR
SMBSPOOLDIR=$SMBSPOOLDIR
PWDFILE=$PWDFILE
GRPFILE=$GRPFILE
GSDWFILE=$GSDWFILE
NSSFILE=$NSSFILE
HOSTFILE=$HOSTFILE
KRBFILE=$KRBFILE
KEYTABFILE=$KEYTABFILE
NTPFILE=$NTPFILE
MOUNTFILE=$MOUNTFILE
SMBFILE=$SMBFILE
LDMFILE=$LDMFILE
PAM_AUTH='${PAM_AUTH}'
PAM_ACCOUNT='${PAM_ACCOUNT}'
PAM_PASSWORD='${PAM_PASSWORD}'
PAM_SESSION='${PAM_SESSION}'" > "${DBDIR}/station.db" && chmod 644 "${DBDIR}/station.db"

	[ -n "$ADDSMBFILE" ] && echo "ADDSMBFILE=$ADDSMBFILE" >> "${DBDIR}/station.db"

	if [ -n "$LOCK_TYPE" ] && [ -n "$LOCKED_BY_NAME" ] && [ -n "$LOCKED_BY_SID" ]; then
		echo -e "LOCK_TYPE=${LOCK_TYPE}\nLOCKED_BY_NAME='${LOCKED_BY_NAME}'\nLOCKED_BY_SID=${LOCKED_BY_SID}" >> "${DBDIR}/station.db"
	fi

	Create_Keytab
	Check_SMBDirs
	Set_ToleranceQtTime
	Config_ldmfile
	Config_LogonScript
	Config_PAM

	[ -n "$ADD_PAM_AUTHMOD" ] && echo "ADD_PAM_AUTHMOD='${ADD_PAM_AUTHMOD}'" >> "${DBDIR}/station.db"

	if [ -d "$SUDODIR" ] && [ ! -f "${SUDODIR}/cid-sudo-admusers" ]; then
		true >"${SUDODIR}/cid-sudo-admusers" && chmod 0440 "${SUDODIR}/cid-sudo-admusers"
	fi

	if command -v systemctl >/dev/null 2>&1; then
		if Check_Options 1; then
			Manage_Service 'nmb' 'mask'
			Manage_Service 'nmb' 'stop'
		fi

		if [ -d "$SYSTEMDDIR" ] && [ ! -s "${SYSTEMDDIR}/cid.service" ]; then
			echo "[Unit]
Description=CID Init Script
Documentation=http://cid-doc.github.io/#CIS
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=-/usr/share/cid/scripts/functions.bash start
ExecReload=/usr/share/cid/scripts/functions.bash reload
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target" >"${SYSTEMDDIR}/cid.service" && chmod 664 "${SYSTEMDDIR}/cid.service" && systemctl daemon-reload
			systemctl enable cid.service

			local str ; str=$(Get_NameSRVC 'winbind')
			[ "$str" ] && systemctl enable "$str"
		fi
	fi
}

# Function: Export_LogonScripts
Export_LogonScripts () {
	function Mount_Netlogon () {
		mount.cifs "//${dcaddr:-${FQDN}}/netlogon" "$NETLOGON" --verbose -o "${1+vers=${1}.0,}username=${DOMAINUSER},password=${PASS},domain=$FQDN"

		return $?
	}

	local dcaddr status FILE

	if ! dcaddr=$(Get_DomainIP); then dcaddr=$FQDN; fi

	[ -d "$NETLOGON" ] || mkdir -p "$NETLOGON"

	if ! Mount_Netlogon; then
		for((int=2;int > 0;int--)); do
			if Mount_Netlogon "$int"; then
				echo "SMBVER=$int" >> "${DBDIR}/station.db" ; status=0 ; break
			fi
		done

		[ ${status:-1} -eq 0 ] || return 1
	fi

	if [ -d "$LOGONSCRIPTDIR" ]; then
		FILE='shares.xml logon.sh logon_root.sh'

		for file in $FILE; do
			if [ ! -f "${LOGONSCRIPTDIR}/$file" ]; then
				if [ -f "${OLDLOGONSCRIPTDIR}/$file" ]; then
					cp -f "${OLDLOGONSCRIPTDIR}/$file" "${LOGONSCRIPTDIR}/$file"
				else
					if [ "$file" == 'logon_root.sh' ] && [ -f "${OLDLOGONSCRIPTDIR}/.logon_(root).sh" ]; then
						cp -f "${OLDLOGONSCRIPTDIR}/.logon_(root).sh" "${LOGONSCRIPTDIR}/$file" && continue
					fi

					cp -f "${MODELDIR}/$file" "${LOGONSCRIPTDIR}"/
				fi
			fi
		done
	else
		mkdir -p "$LOGONSCRIPTDIR"

		cp -f "${MODELDIR}"/* "$LOGONSCRIPTDIR"/

		[ -d "$OLDLOGONSCRIPTDIR" ] && cp -rf "${OLDLOGONSCRIPTDIR}"/* "$LOGONSCRIPTDIR"/
	fi

	umount "${NETLOGON}"
}

# Function: Success_Join
Success_Join () {
	Manage_Service 'winbind' 'restart'

	local str

	# shellcheck disable=SC2119
	str="$(Get_AdminsGroup)"

	net rpc rights grant "$str" SeDiskOperatorPrivilege -U "$DOMAINUSER"%"$PASS"
	net rpc rights grant "$str" SePrintOperatorPrivilege -U "$DOMAINUSER"%"$PASS"

	unset DATE LOCK_TYPE LOCKED_BY_NAME LOCKED_BY_SID

	[ -d "$DBDIR" ] || mkdir -p "$DBDIR"

	Post_Join
	Export_LogonScripts
}

# Function: Post_Leave
Post_Leave () {
	if [ -d "$PRTDRVDIR" ] && [ "$(stat -c "%G" "$PRTDRVDIR")" != "root" ]; then
		chgrp -R root "$PRTDRVDIR"
	fi

	local str FILE="${DBDIR}/accountList.db ${DBDIR}/shareList.db"

	for file in $FILE; do
		if [ -s "$file" ]; then
			# shellcheck source=/dev/null
			. "$file"

			if [[ $file =~ .+account.+ ]]; then
				str="account:${#ACCOUNTSID[*]}"
			else
				str="share:${#SHARENAME[*]}"
			fi

			for ((int=0; int < ${str#*:}; int++)); do
				"Rm${str%:*}" "$int"
			done
		fi
	done

	find "${DBDIR}" -type f -delete

	# shellcheck disable=SC2046
	find $(smbd -b | grep -Ew "LOCKDIR|STATEDIR|CACHEDIR|PRIVATE_DIR" | tr -d '[:blank:]' | cut -d ':' -f 2 2>/dev/null) -type f -regextype posix-egrep -iregex ".+.(t|l)db$" -delete

	[ -f "${SYSTEMDDIR}/cid.service" ] && systemctl disable cid.service && rm -f "${SYSTEMDDIR}/cid.service" && systemctl daemon-reload

	FILE="/etc/krb5.keytab ${SUDODIR}/cid-sudo-admusers ${SUDODIR}/cid-sudo-allusers ${PROFILEDIR}/cid.sh"

	for file in $FILE; do
		[ -f "$file" ] && rm -f "$file"
	done
}

# Function: Leave
Leave () {
	if [ -n "$PASS" ]; then
		local str ip status

		# shellcheck disable=SC2119
		str="$(Get_AdminsGroup)"

		Manage_Service 'systemd-timesyncd' 'restart'

		net rpc rights revoke "$str" SeDiskOperatorPrivilege -U "$DOMAINUSER"%"$PASS"
		net rpc rights revoke "$str" SePrintOperatorPrivilege -U "$DOMAINUSER"%"$PASS"

		if ! net ads leave -U "$DOMAINUSER"%"$PASS"; then
			if ip=$(wbinfo -P); then
				if echo "$ip" | grep -wq "$FQDN"; then
					ip=${ip%\"*} && ip=${ip#*\"}

					net ads leave -S "$ip" -U "$DOMAINUSER"%"$PASS" ; status="$?"
				else
					status=1
				fi
			else
				if ip=$(Get_DomainIP); then
					net ads leave -S "$ip" -U "$DOMAINUSER"%"$PASS" ; status="$?"
				else
					status=1
				fi
			fi
		fi

		unset DOMAINUSER PASS
	fi

	Restore
	Post_Leave
	return ${status:-0}
}

# Function: Fix_Obj
Fix_Obj () {
	if Check_Options 5 "$MODO"; then
		if ! Check_Backslash "${OBJ/\\/@}"; then
			OBJ="${DOMAIN}\\${OBJ}" && return
		fi
	else
		if echo "${OBJ%\\*}" | grep -wiq "$DOMAIN"; then
			OBJ="${OBJ#*\\}" && return
		fi
	fi

	if Check_Backslash "${OBJ/\\/@}"; then
		OBJ="$(echo "${OBJ%\\*}" | tr '[:lower:]' '[:upper:]')\\${OBJ#*\\}"
	fi
}

# Function: Check_Obj
Check_Obj () {
	if [ -z "$OBJ" ]; then
		return 1
	else
		local bool

		if [ "$OBJ_TYPE" = "user" ] && echo "$OBJ" | grep -Eq "[[:blank:]]"; then bool=false; else unset bool; fi

		if Check_Backslash "$OBJ" || [ "$bool" = 'false' ]; then
			return 2
		else
			Fix_Obj

			if wbinfo -n "$OBJ" 2>/dev/null | grep -iq "$OBJ_TYPE"; then
				return 0
			else
				if grep -aEwiq "^$(Backslash "$OBJ")" "${FILE:=$PWDFILE}"; then
					return 3
				else
					return 4
				fi
			fi
		fi
	fi
}

# Function: Get_Sid
Get_Sid () {
	wbinfo -n "$1" | awk '{print $1}'
}

# Function: Check_AdminGroup
Check_AdminGroup () {
	[[ $1 =~ S-1-5-21-.+-512$ ]] && return 0 || return 1
}

# Function: Get_UserGroups
Get_UserGroups () {
	wbinfo --user-domgroups="$1" | grep -xv "$1"
}

# Function: Check_AdminUser
Check_AdminUser () {
	if Get_UserGroups "${1:-$SID}" | grep -Ewq "${2:-S-1-5-21-.+-512$}"; then
		return 0
	else
		return 1
	fi
}

# Function: Get_ObjID
Get_ObjID () {
	unset INT
	local var

	if [ "$1" = 'account' ]; then
		var='ACCOUNTSID'
	else
		var="${3:-SHARENAME}"
	fi

	if [ -s "${DBDIR}/${1}List.db" ]; then
		INT="$(sed 's/\$/@/g' "${DBDIR}/${1}List.db" | grep -aEx "^[[:blank:]]*${var}\[[0-9]+\]='${2/$/@}'")" && INT=${INT#*[} && INT=${INT%%]*} && export INT
		return 0
	fi

	return 1
}

# Function: Check_AccountName
# shellcheck disable=SC2120
Check_AccountName () {
	SID="$(Get_Sid "${1:-$OBJ}")"

	[ "$SID" ] || return 255

	if [ "$OBJ_TYPE" = 'group' ]; then
		if Check_AdminGroup "$SID"; then return 3 ; fi
	fi

	# shellcheck disable=SC2086
	unset ${!ACCOUNT*}

	if Get_ObjID 'account' "$SID"; then
		if [ "$INT" ]; then
			STR="$(sed -rn "/^[[:blank:]]*ACCOUNTNAME\[${INT}\]=[[:graph:]]+/p" "${DBDIR}/accountList.db" | cut -d '=' -f 2 | tr -d \')" && local str="${1:-$OBJ}"

			if [ "$STR" != "${str/\\/@}" ]; then
				sed -ri "/ACCOUNTNAME\[${INT}\]=/s/${STR}/${str/\\/@}/ig" "${DBDIR}/accountList.db"

				if [ "$OBJ_TYPE" = 'user' ]; then
					local FILE="${GRPFILE}* ${GSDWFILE}*"

					for file in $FILE; do
						[ ! -d "${RESTOREDIR}${file%/*}" ] && mkdir -p "${RESTOREDIR}${file%/*}"

						cp -f "$file" "${RESTOREDIR}$file"
						sed -i 's/\\/@/g' "$file"
						sed -i "s/${STR}/${str/\\/@}/ig" "$file"
						sed -i 's/@/\\/g' "$file"
					done
				fi

				return 2
			fi

			unset str STR ; return 1
		else
			# shellcheck source=/dev/null
			. "${DBDIR}/accountList.db"
		fi
	fi

	return 0
}

# Function: Manage_SudoUsers
Manage_SudoUsers () {
	[ -d "$SUDODIR" ] || return 255
	[ ! -f "${SUDODIR}/cid-sudo-admusers" ] && true >"${SUDODIR}/cid-sudo-admusers" && chmod 0440 "${SUDODIR}/cid-sudo-admusers"

	sed -i 's/\\\\/@/g' "${SUDODIR}/cid-sudo-admusers"

	if ! grep -awiq "${1/\\/@}" "${SUDODIR}/cid-sudo-admusers" && [ "$2" = 'true' ]; then
		local par

		if ! Check_Options 6 "$MODO"; then
			par='ALL = NOPASSWD: ALL'
		else
			par='ALL = ALL'
		fi

		echo -e "${1/\\/@}\t$par" >> "${SUDODIR}/cid-sudo-admusers"
	elif grep -awiq "${1/\\/@}" "${SUDODIR}/cid-sudo-admusers" && [ "$2" = 'false' ]; then
		sed -i "/${1/\\/@}/Id" "${SUDODIR}/cid-sudo-admusers"
	fi

	sed -i 's/@/\\\\/g' "${SUDODIR}/cid-sudo-admusers"
}

# Function: Get_SystemGroups
Get_SystemGroups () {
	local tempfile ; tempfile="$(Tempfile 'sgrp')"

	grep -aw "$DEFAULTUSER" "$GRPFILE" | cut -d ':' -f 1 >"$tempfile"

	while read -r str; do
		LOCALGROUPS="${LOCALGROUPS:+${LOCALGROUPS} }$str"
	done < "$tempfile"

	LOCALGROUPS="${LOCALGROUPS:+${LOCALGROUPS} }sudo wheel"
	EXCL_LOCALGROUPS="${EXCL_LOCALGROUPS:+${EXCL_LOCALGROUPS} }$DEFAULTUSER"

	cut -d ':' -f 1 "$GRPFILE" | grep -Ex "${LOCALGROUPS// /\|}" | grep -Evw "${EXCL_LOCALGROUPS// /\|}" >"$tempfile"

	sort -u "$tempfile"
}

# Function: Get_AllGroupMembers
Get_AllGroupMembers () {
	wbinfo --group-info="$1" | sed -r "s/.+://;s/,/${2:- }/g"
}

# Function: Create_ObjList
Create_ObjList () {
	[ ! -f "${DBDIR}/${1}List.db" ] && true >"${DBDIR}/${1}List.db" && chmod 600 "${DBDIR}/${1}List.db"
	[ "$1" = 'quota' ] && Set_ToleranceQtTime
}

# Function: Delete_ObjList
Delete_ObjList () {
	sed -ri "/^${1^^}[A-Z]+\[${2}\]=/d" "${DBDIR}/${1}List.db"
}

# Function: Insert_AccountList
Insert_AccountList () {
	Create_ObjList 'account'

	# shellcheck source=/dev/null
	[ "$5" ] || . "${DBDIR}/accountList.db"

	local int=${5:-${#ACCOUNTSID[*]}}

	echo "ACCOUNTNAME[${int}]='${1/\\/@}'
ACCOUNTSID[${int}]='${2}'
ACCOUNTMODE[${int}]='${3:-auto}'
ACCOUNTTYPE[${int}]='${4:-user}'" >> "${DBDIR}/accountList.db"

	[ "$5" ] && return 0

	# shellcheck source=/dev/null
	. "${DBDIR}/accountList.db"

	if [ "${ACCOUNTSID[${int}]}" = "$2" ]; then
		return 0
	else
		return 255
	fi
}

# Function: Addaccount
Addaccount () {
	# shellcheck disable=SC2119
	Check_AccountName

	local status=$?
	[ "$status" -eq 0 ] || return "$status"

	case "$OBJ_TYPE" in
		'user'	) "${SCRIPTDIR}/manager_systemGroups.bash" "$OBJ" 'true' 'manual' "$SID" ;;
		'group'	) Insert_AccountList "$OBJ" "$SID" 'manual' 'group' "${#ACCOUNTSID[*]}" ;;
	esac

	return $?
}

# Function: Rmaccount
Rmaccount () {
	[ "${ACCOUNTTYPE[${1}]}" = "group" ] && return 0

	"${SCRIPTDIR}/manager_systemGroups.bash" "${ACCOUNTNAME[${1}]/@/\\}" 'false'

	return $?
}

# Function: Show_Block
Show_Block () {
	grep -aEnv "^[[:blank:]]*#" "$1" | grep -Ew "^[0-9]+:[[:blank:]]*auth" | grep -w 'pam_winbind.so' | grep -Ew "require_membership_of=[[:graph:]]+"
}

# Function: Unlock
Unlock () {
	unset PAR ; local FILE file status

	if [ "$1" ]; then
		FILE=$1
	else
		FILE="$PAM_AUTH"
	fi

	for file in $FILE; do
		[ -L "$file" ] && file=$(readlink -m "$file")

		PAR="$(Show_Block "$file")"

		if [ -n "$PAR" ]; then
			[ -d "${RESTOREDIR}${file%/*}" ] || mkdir -p "${RESTOREDIR}${file%/*}"

			cp -f "$file" "${RESTOREDIR}$file"
			sed -i "${PAR%%:*}s/$(echo "$PAR" | grep -Eo "require_membership_of=[[:graph:]]+")//" "$file"

			if [ ! "$(Show_Block "$file")" ]; then
				status=0
			else
				status=1
			fi
		else
			status=255
		fi
	done

	if [ "$status" -eq 0 ]; then
		sed -i '/LOCK_TYPE/d;/LOCKED_BY_NAME/d;/LOCKED_BY_SID/d' "${DBDIR}/station.db"
		unset LOCK_TYPE LOCKED_BY_NAME LOCKED_BY_SID
	fi

	return $status
}

# Function: Block
Block () {
	SID=${SID:="$(Get_Sid "$OBJ")"}

	if [ -z "$SID" ]; then
		return 255
	else
		local file status

		for file in $PAM_AUTH; do
			[ -L "$file" ] && file=$(readlink -m "$file")

			Unlock "$file"

			PAR=${PAR:=$(grep -aEnv "^[[:blank:]]*#" "$file" | grep -Ew "^[0-9]+:[[:blank:]]*auth" | grep -w 'pam_winbind.so')}

			sed -i "${PAR%%:*}s/[[:blank:]]*$/ require_membership_of=$SID/" "$file"

			if [ "$(Show_Block "$file")" ]; then
				status=0
			else
				return 1
			fi
		done

		if [ "$status" -eq 0 ]; then
			echo -e "LOCK_TYPE=${OBJ_TYPE}\nLOCKED_BY_NAME='${OBJ/\\/@}'\nLOCKED_BY_SID=$SID" >> "${DBDIR}/station.db"
			return 0
		fi
	fi
}

# Function: Get_ShareDev
Get_ShareDev () {
	local dir="$1"

	while [ ! -d "$dir" ]; do
		dir=${dir%/*} && dir="${dir:=/}"
	done

	df -T "$dir" | grep -w 'xfs' | awk '{print $1}'
}

# Function: UnitToPower
UnitToPower () {
	local crt

	case "$1" in
		'm'|1 ) crt=M:1 ;;
		'g'|2 ) crt=G:2 ;;
		't'|3 ) crt=T:3 ;;
		'p'|4 ) crt=P:4 ;;
		'e'|5 ) crt=E:5 ;;
		'z'|6 ) crt=Z:6 ;;
		'y'|7 ) crt=Y:7 ;;
		*	) crt=K ;;
	esac

    if Check_NoNum "$1"; then
		echo "${crt#*:}"
	else
		echo "${crt%:*}"
	fi
}

# Function: Get_ShareRule
Get_ShareRule (){
	case "${SHAREMODE[${1}]}" in
		'printer'		) echo 'Defined by CUPS'			;;
		'userfolder'	) echo 'u:owner:f'					;;
		'common'		) getfacl -cp "${SHAREPATH[${1}]}"	;;
		*				) return 1							;;
	esac
}

# Function: ReadQuota
ReadQuota () {
    if Check_NoNum "$1"; then echo "$1" && return 0; fi

	local nb

    for((int=7;int >= 0;int--)); do
        nb=$(Get_IntValue "$1" '/' "$int")

        [ "$nb" -gt 0 ] && echo "${nb}$(UnitToPower ${int})" && break

        unset nb
    done
}

# Function: Check_ShareArgs
Check_ShareArgs () {
	function Check_DiffFlds () {
		local str

		for arg in "$@"; do
			[ "$arg" = 'false' ] && continue

			str=${arg%[*} && str=${str,,}

			if [ -z "${!str}" ] && [ "$1" != 'false' ]; then continue ; fi

			if [ "$str" = 'sharequota' ]; then
				if [ "${!str}" = '0' ] && [ ! "${!arg}" ]; then continue ; fi
			fi

			[ "${!str}" != "${!arg}" ] && return 1
		done

		return 0
	}

	function Set_DefVars () {
		sharecomment=${sharecomment:=${SHARECOMMENT[${INT}]}}
		sharequota=${sharequota:=${SHAREQUOTA[${INT}]}}
		sharetolerance=${sharetolerance:=${SHARETOLERANCE[${INT}]}}
		sharequotasubd=${sharequotasubd:=${SHAREQUOTASUBD[${INT}]}}
		sharehidden=${sharehidden:=${SHAREHIDDEN[${INT}]}}
		shareguest=${shareguest:=${SHAREGUEST[${INT}]}}
	}

	function Check_IgnFlds () {
		for arg in "$@"; do
			[ "${!arg}" ] && return 16
		done

		return 0
	}

	function FormatQuota () {
		local lst int="$1"

		if [ "${#1}" -gt 1 ]; then
			lst="${1:(-1)}" ; int="${1:0:$((${#1}-1))}"

			if Check_NoNum "${int/,/}"; then return 1; fi

			if Check_NoNum "$lst"; then
				if ! echo "$lst" | grep -Eiq "(k|m|g|t|p|e|z|y)"; then return 2 ; fi

				[ "${lst,,}" != 'k' ] && int=$(Get_IntValue "${int/,/.}" '*' "$(UnitToPower "${lst,,}")")
			else
				int="$1"
			fi

			if Check_NoNum "$int"; then int=$((${int%,*}+1)); fi
		fi

		if Check_NoNum "$int"; then return 1; fi

		if [ "$int" -eq 0 ]; then
			unset "$2"
		else
			export "${2}=$int"
		fi

		return 0
	}

	function LetterToOctal () {
		case "$1" in
			'r' ) echo 5 ;;
			'f' ) echo 7 ;;
			'd' ) echo 0 ;;
		esac
	}

	function RulesPerLine () {
		# shellcheck disable=SC2001
		echo "$sharerule" | sed "s/;/\n/g"
	}

	unset INT status

	if [ -z "$sharename" ] && [ -z "$sharetemplate" ] && [ "${sharemode:-common}" = 'common' ]; then return 1 ; fi
	if [ -n "$sharetemplate" ] && [ "${sharetemplate,,}" = "${sharename,,}" ]; then return 2 ; fi

	if [ -z "$sharename" ] && [ -n "$sharetemplate" ]; then
		sharename="${sharetemplate,,}"
		unset sharetemplate
	fi

	[ "$sharetemplate" ] && sharetemplate=${sharetemplate,,}
	[ "$sharename" ] && sharename=${sharename,,} && Get_ObjID 'share' "$sharename"

	if [ "$INT" ]; then
		if [ -n "$sharemode" ] && [ "$sharemode" != "${SHAREMODE[${INT}]}" ]; then return 3 ; fi
		if [ "${SHAREMODE[${INT}]}" != "printer" ] && [ -n "$sharepath" ] && [ "$sharepath" != "${SHAREPATH[${INT}]}" ]; then return 4 ; fi
		if [ "${SHAREMODE[${INT}]}" = "userfolder" ] && [ -n "$sharetemplate" ]; then return 5 ; fi

		sharemode=${sharemode:=${SHAREMODE[${INT}]}}
		sharecfgfile=${sharecfgfile:=${SHARECFGFILE[${INT}]}}

		function Update_FormatQuota () {
			for var in sharequota sharetolerance; do
				if [ "${!var}" ] && [ "${!var}" != '0' ]; then
					status=0 ; FormatQuota "${!var}" "$var" ; status=$((${?}+19))

					if [ "$status" -eq 19 ]; then
						unset status
					else
						return "$status"
					fi
				fi
			done

			return 0
		}

		case "$sharemode" in
			'printer'		)
								sharepath=${sharepath,,}

								if Check_DiffFlds SHARETEMPLATE[$INT] SHAREPATH[$INT] SHARECOMMENT[$INT] SHAREHIDDEN[$INT] SHAREGUEST[$INT] SHARECFGFILE[$INT]; then
									return 6
								fi
							;;
			'userfolder'	)
								if ! Update_FormatQuota; then
									return "$status"
								fi

								unset sharename

								if Check_DiffFlds SHARECOMMENT[$INT] SHAREQUOTA[$INT] SHARETOLERANCE[$INT] SHARECFGFILE[$INT]; then
									return 6
								fi

								if [ "$sharequota" = '0' ]; then
									sharequotasubd=${sharequotasubd:='No'}
								elif [ -n "$sharequota" ]; then
									sharequotasubd=${sharequotasubd:='Yes'}
								fi
							;;
			'common'		)
								if ! Update_FormatQuota; then
									return "$status"
								fi

								if Check_DiffFlds SHARETEMPLATE[$INT] SHARERULE[$INT] SHARECOMMENT[$INT] SHAREQUOTA[$INT] SHARETOLERANCE[$INT] SHAREQUOTASUBD[$INT] SHAREHIDDEN[$INT] SHAREGUEST[$INT] SHARECFGFILE[$INT]; then
									return 6
								fi
							;;
		esac

		sharetemplate=${sharetemplate:=${SHARETEMPLATE[${INT}]}}
		sharepath=${sharepath:=${SHAREPATH[${INT}]}}
		Set_DefVars
	else
		if [ "$sharename" = "global" ] || [ "$sharename" = "homes" ] || [ "$sharename" = "printers" ] || [ "$sharename" = "print$" ]; then
			return 7
		fi

		if Check_Backslash "${sharename//\\/@}"; then return 8 ; fi

		if [ "$sharetemplate" ]; then
			Get_ObjID 'share' "$sharetemplate"
			sharemode=${sharemode:=${SHAREMODE[${INT}]}}

			[ "$sharemode" != "${SHAREMODE[${INT}]}" ] && return 9
			[ "${SHAREMODE[${INT}]}" = "userfolder" ] && return 10

			if [ "$sharemode" = 'common' ] && [ -n "$sharepath" ] && [ "${sharepath:0:1}" != '/' ]; then
				sharepath="${SHAREPATH[${INT}]%/*}/${sharepath}"
			fi

			sharecfgfile=${sharecfgfile:=${SHARECFGFILE[${INT}]}}
			sharerule=${sharerule:=${SHAREPATH[${INT}]}}
			Set_DefVars ; unset INT
		fi

		sharemode=${sharemode:='common'}

		case "$sharemode" in
			'printer'		)
								if [ -z "$sharename" ] && [ -z "$sharepath" ]; then
									return 11
								fi

								sharepath=${sharepath,,}
								sharename=${sharename:=${sharepath}}
								sharepath=${sharepath:=${sharename}}
							;;
			'userfolder'	)
								sharepath=${sharepath:=/home}
							;;
			'common'		)
								if [ -z "$sharename" ] || [ -z "$sharepath" ]; then
									return 12
								fi

								sharerule=${sharerule:='u:everyone:r'}
							;;
		esac
	fi

	if [ "$sharemode" != "printer" ]; then
		[ "${sharepath:0:1}" != '/' ] && return 13
		[ "${sharepath:(-1)}" = '/' ] && sharepath=${sharepath%/}
	else
		if ! lpstat -p "$sharepath"; then return 14 ; fi
	fi

	if [ -z "$INT" ]; then
		Get_ObjID 'share' "$sharepath" 'SHAREPATH'
		[ "$INT" ] && return 15
	fi

	local VAR status

	case "$sharemode" in
		'printer'		)
							if [ "$INT" ] && [ "$sharequotasubd" = 'No' ]; then
								unset sharequotasubd
							fi

							VAR='sharerule sharequota sharetolerance sharequotasubd'

							# shellcheck disable=SC2086
							Check_IgnFlds $VAR ; status=$?

							# shellcheck disable=SC2086
							unset $VAR VAR
						;;
		'userfolder'	)
							if [ "$INT" ]; then
								if [ "$sharequota" = '0' ] || [ ! "$sharequota" ]; then
									[ "$sharequotasubd" = 'No' ] && unset sharequotasubd
								else
									[ "$sharequotasubd" = 'Yes' ] && unset sharequotasubd
								fi

								[ "$sharehidden" = 'Yes' ] && unset sharehidden
								[ "$shareguest" = 'No' ] && unset shareguest
							fi

							VAR='sharename sharetemplate sharerule sharequotasubd sharehidden shareguest'

							# shellcheck disable=SC2086
							Check_IgnFlds $VAR ; status=$?

							# shellcheck disable=SC2086
							unset $VAR VAR

							sharename='homes'
							[ "$sharequota" ] && sharequotasubd='Yes'
							sharehidden='Yes'
							shareguest='No'
							sharecomment=${sharecomment:='Network Home Folder of %S (by CID)'}
						;;
	esac

	if [ "$sharequota" ]; then
		if ! command -v bc >/dev/null 2>&1; then return 17 ; fi

		unset sharequotadev ; sharequotadev=$(Get_ShareDev "$sharepath")

		[ "$sharequotadev" ] || return 18

		if ! mount | grep -w "$sharequotadev" | grep -q 'prjquota'; then return 19 ; fi

		for var in sharequota sharetolerance; do
			if [ "${!var}" ]; then
				FormatQuota "${!var}" "$var"

				case $? in
					1	) return 20 ;;
					2	) return 21 ;;
				esac
			fi
		done

		[ "${sharetolerance:-0}" -gt "${sharequota:-0}" ] && return 22

		local int ; int=$(df -B 1K --output=size "$sharequotadev" | tail -n 1 | awk '{print $1}' | grep -Eo "[0-9]+")

		[ "${sharequota:-0}" -gt "${int:-0}" ] && return 23
	else
		[ "$sharetolerance" ] && return 24
		[ "$sharequotasubd" = 'Yes' ] && return 25
	fi

	if [ -n "$sharerule" ] && [ ! -d "$sharerule" ]; then
		sharerule=${sharerule,,}

		[ "${sharerule:(-1)}" = ';' ] && sharerule=${sharerule%;}

		local crt="${sharerule:0:1}"

		# shellcheck disable=SC1001
		if [[ $crt =~ \+|\- ]]; then
			sharerule="${sharerule:1}"

			case "$crt" in
				'+'	)
						if RulesPerLine | grep -Exvq "(u|g):[^:]+:(r|f|d)"; then
							return 26
						else
							BOOL=true
						fi
				;;
				'-'	)
						if RulesPerLine | grep -Exvq "(u|g):[^:]+"; then
							return 26
						else
							BOOL=false
						fi
				;;
			esac
		else
			if RulesPerLine | grep -Exvq "(u|g):[^:]+:(r|f|d)"; then
				return 26
			else
				unset crt BOOL
			fi
		fi

		if RulesPerLine | sort -u | cut -d ':' -f 1-2 | uniq -c | awk '{print $1}' | grep -xvq '1'; then
			return 27
		fi

		local tempfile str nb

		tempfile="$(Tempfile 'rule')"

		RulesPerLine | sort -u >"$tempfile" && unset sharerule

		for((int=$(Get_NumLines "$tempfile");int > 0;int--)); do
			str=$(sed -n "${int}p" "$tempfile")
			OBJ=$(echo "${str}" | cut -d ':' -f 2)

			if [ "$OBJ" = 'everyone' ]; then
				if [ "$BOOL" = 'false' ]; then
					nb=0
				else
					nb=$(LetterToOctal "${str##*:}")
				fi

				sharerule="${sharerule:+${sharerule},}o:${nb},d:o:${nb}"
			else
				if [ "${str%%:*}" = 'u' ]; then
					OBJ_TYPE='user'
				else
					OBJ_TYPE='group'
				fi

				if ! Check_Obj; then return 28; fi

				if [ "$BOOL" = 'false' ]; then
					unset nb
				else
					nb=:$(LetterToOctal "${str##*:}")
				fi

				sharerule="${sharerule:+${sharerule},}${str%%:*}:${OBJ}${nb},d:${str%%:*}:${OBJ}${nb}"
			fi
		done
	fi

	[ "$sharecfgfile" = 'No' ] && unset sharecfgfile
	[ "$sharequota" ] || sharequotasubd='No'

	sharequotasubd=${sharequotasubd:=No}
	sharehidden=${sharehidden:=No}
	shareguest=${shareguest:=No}
	sharecomment=${sharecomment:='%S section in Samba (by CID)'}

	return ${status:-0}
}

# Function: Create_QuotaDirList
Create_QuotaDirList () {
	local tempfile ; tempfile="$(Tempfile 'list')"

	if [ "$2" = 'Yes' ]; then
		find "$1" -maxdepth 1 -type d | grep -xv "$1" >"$tempfile"
	else
		echo "$1" >"$tempfile"
	fi

	echo "$tempfile"
}

# Function: Get_QuotaID
Get_QuotaID () {
	[ -s "${DBDIR}/quotaList.db" ] || return 1

	grep -Exna "[0-9]+:$1" "${DBDIR}/quotaList.db" | cut -d ':' -f 1-2

	return 0
}

# Function: Rmquota
Rmquota () {
	local tempfile dir ln id

	tempfile=$(Create_QuotaDirList "$1" "$2")

	for((int=$(Get_NumLines "$tempfile");int > 0;int--)); do
		dir=$(sed -n "${int}p" "$tempfile")

		unset id

		if ! id=$(Get_QuotaID "$dir"); then return 0; fi

		[ "$id" ] || continue

		ln=${id%:*} && id=${id#*:}

		xfs_quota -D "${DBDIR}/quotaList.db" -xc "limit bsoft=0 bhard=0 -p $id" "${sharequotadev:=$(Get_ShareDev "$1")}"
		xfs_quota -D "${DBDIR}/quotaList.db" -xc "project -C $id" "$sharequotadev"
		sed -i "${ln}d" "${DBDIR}/quotaList.db"
	done
}

# Function: Addquota
Addquota () {
	local tempfile dir id

	tempfile=$(Create_QuotaDirList "$1" "$4")

	for((int=$(Get_NumLines "$tempfile");int > 0;int--)); do
		dir=$(sed -n "${int}p" "$tempfile")

		[ "$(Get_QuotaID "$dir")" ] && continue

		unset id

		id=$(($(xfs_quota -xc 'report -pbhnNa' | awk '{print $1}' | sed -r "s/[^[:digit:]]//g" | sort -n | tail -n 1) + 1)) && Create_ObjList 'quota'

		while cut -d ':' -f 1 "${DBDIR}/quotaList.db" | grep -xq "$id"; do id=$((${id:-0}+1)) ; done

		echo "${id}:$dir" >> "${DBDIR}/quotaList.db"

		xfs_quota -D "${DBDIR}/quotaList.db" -xc "project -s $id" "${sharequotadev:=$(Get_ShareDev "$1")}"
		xfs_quota -D "${DBDIR}/quotaList.db" -xc "limit bsoft=${2}k bhard=$((${2}+${3}))k -p $id" "$sharequotadev"
	done
}

# Function: Insert_ShareList
Insert_ShareList () {
	Create_ObjList 'share'

	echo "SHAREMODE[${1}]='${sharemode}'
SHARENAME[${1}]='${sharename}'
SHARETEMPLATE[${1}]='${sharetemplate}'
SHAREPATH[${1}]='${sharepath}'
SHARECOMMENT[${1}]='${sharecomment}'
SHAREQUOTA[${1}]='${sharequota}'
SHARETOLERANCE[${1}]='${sharetolerance}'
SHAREQUOTASUBD[${1}]='${sharequotasubd}'
SHAREHIDDEN[${1}]='${sharehidden}'
SHAREGUEST[${1}]='${shareguest}'
SHARECFGFILE[${1}]='${sharecfgfile}'" >> "${DBDIR}/shareList.db"
}

# Function: Share_ConfigSmbfile
Share_ConfigSmbfile () {
	# shellcheck disable=SC2001,SC2046,SC2086
	unset $(echo ${!SHARE*} | sed 's/SHAREDIR//')
	Restore "$SMBFILE"
	[ "$1" ] || OPTIONS="$MODO"
	Config_smbfile
	[ "$1" ] || unset OPTIONS
	Manage_Service 'smb' 'restart'
}

# Function: Addshare
Addshare () {
	if [ "$sharemode" != "printer" ] && [ ! -d "$sharepath" ]; then
		mkdir -pv "$sharepath"
	fi

	if [ "$INT" ]; then
		if [ "$sharemode" != "printer" ]; then
			if ! Check_DiffFlds false SHAREQUOTA[$INT] SHARETOLERANCE[$INT] SHAREQUOTASUBD[$INT]; then
				Rmquota "$sharepath" "${SHAREQUOTASUBD[${INT}]}"
			fi
		fi

		Delete_ObjList 'share' "$INT"
	else
		INT=${#SHARENAME[*]}
	fi

	[ "$sharequota" ] && Addquota "$sharepath" "$sharequota" "${sharetolerance:-0}" "$sharequotasubd"

	if [ "$sharerule" ]; then
		if [ -d "$sharerule" ]; then
			getfacl "$sharerule" | setfacl -R --set-file=- "$sharepath"

			# shellcheck disable=SC2119
			chgrp -R "$(Get_AdminsGroup)" "$sharepath"
		else
			unset crt

			if [ "$BOOL" ]; then
				[ "$BOOL" = 'false' ] && local crt=x
			else
				setfacl -R -b "$sharepath"

				# shellcheck disable=SC2119
				chgrp -R "$(Get_AdminsGroup)" "$sharepath"
				chmod 770 "$sharepath"
			fi

			setfacl -R -${crt:-m} "$sharerule" "$sharepath"
		fi
	fi

	Insert_ShareList "$INT"
	Share_ConfigSmbfile

	if [ "${SHARENAME[${INT}]}" = "$sharename" ]; then
		return 0
	else
		return 1
	fi
}

# Function: Rmshare
Rmshare () {
	[ "${SHAREMODE[${1}]}" = 'common' ] && setfacl -R -b "${SHAREPATH[${1}]}" && chgrp -R root "${SHAREPATH[${1}]}"
	[ "${SHAREQUOTA[${1}]}" ] && Rmquota "${SHAREPATH[${1}]}" "${SHAREQUOTASUBD[${1}]}"

	return 0
}

# Function: Delobj
Delobj () {
	[ "$INT" ] || return 255

	local lst tempfile status

	if [ "$1" = "account" ]; then
		lst=$((${#ACCOUNTNAME[*]}-1))
	else
		lst=$((${#SHARENAME[*]}-1))
	fi

	tempfile="$(Tempfile 'list')"
	status=${2:-1}

	echo -e "${INT//|/\\n}" | sort -rn >"$tempfile"

	while read -r pos; do
		if ! "Rm${1}" "$pos"; then
			LIST="${LIST:+${LIST} }${ACCOUNTNAME[${pos}]}"
			continue
		fi

		Delete_ObjList "$1" "$pos" && local status=0

		if [ "$pos" -lt "$lst" ]; then
			for ((i=pos;i<lst;i++)); do
				sed -ri "/^${1^^}[A-Z]+\[$((i+1))\]=/s/\[$((i+1))\]/\[${i}\]/" "${DBDIR}/${1}List.db"
			done
		fi

		if [ "$lst" -gt 0 ]; then
			lst=$((lst-1))
		else
			rm -f "${DBDIR}/${1}List.db"
		fi
	done < "$tempfile"

	[ "$1" = "share" ] && Share_ConfigSmbfile

	return "$status"
}

# Function: Check_Change
Check_Change () {
    if Check_Options "$1" && ! Check_Options "$1" "$MODO"; then
        echo 1
    elif ! Check_Options "$1" && Check_Options "$1" "$MODO"; then
        echo 2
    else
        echo 0
    fi
}

# Function: Change_Behavior
Change_Behavior () {
	local int

	if [ -s "${SUDODIR}/cid-sudo-admusers" ]; then
		int=$(Get_NumLines "${SUDODIR}/cid-sudo-admusers")
	else
		unset int
	fi

	if [ "${int:-0}" -gt 0 ]; then
		case $(Check_Change 6) in
			1)
				while [ "$int" -gt 0 ]; do
					if sed -n "${int}p" "${SUDODIR}/cid-sudo-admusers" | grep -wq 'NOPASSWD:'; then
						sed -i "${int}s/NOPASSWD: ALL$/ALL/" "${SUDODIR}/cid-sudo-admusers"
					fi

					int=$((int-1))
				done
			;;
			2)
				while [ "$int" -gt 0 ]; do
					if ! sed -n "${int}p" "${SUDODIR}/cid-sudo-admusers" | grep -wq 'NOPASSWD:'; then
						sed -i "${int}s/ALL$/NOPASSWD: ALL/" "${SUDODIR}/cid-sudo-admusers"
					fi

					int=$((int-1))
				done
			;;
		esac
	fi

	case $(Check_Change 5) in
		1)
			if [ -s "${DBDIR}/accountList.db" ]; then
				# shellcheck source=/dev/null
				. "${DBDIR}/accountList.db"

				for((int=0;int < ${#ACCOUNTSID[*]};int++)); do
					[ "${ACCOUNTTYPE[${int}]}" = 'group' ] && continue

					if Check_Backslash "${ACCOUNTNAME[${int}]}"; then continue ; fi

					local FILE="${GRPFILE}* ${GSDWFILE}*"

					for file in $FILE; do
						sed -i "s/,${ACCOUNTNAME[${int}]}/,${DOMAIN}@${ACCOUNTNAME[${int}]}/ig" "$file"
						sed -i 's/@/\\/g' "$file"
					done

					if [ -f "${SUDODIR}/cid-sudo-admusers" ]; then
						if grep -aEwq "^${ACCOUNTNAME[${int}]}" "${SUDODIR}/cid-sudo-admusers"; then
							sed -i "s/^${ACCOUNTNAME[${int}]}/${DOMAIN}@${ACCOUNTNAME[${int}]}/g" "${SUDODIR}/cid-sudo-admusers"
							sed -i 's/@/\\\\/g' "${SUDODIR}/cid-sudo-admusers"
						fi
					fi
				done

				sed -ri "/ACCOUNTNAME\[[0-9]+\]='[^@]+'/s/='/='${DOMAIN}@/g" "${DBDIR}/accountList.db"
			fi

			if ! Check_Backslash "$LOCKED_BY_NAME"; then
				sed -i "s/LOCKED_BY_NAME='${LOCKED_BY_NAME}'/LOCKED_BY_NAME='${DOMAIN}@${LOCKED_BY_NAME}'/" "${DBDIR}/station.db"
			fi
		;;

		2)
			if [ -s "${DBDIR}/accountList.db" ]; then
				# shellcheck source=/dev/null
				. "${DBDIR}/accountList.db"

				for((int=0;int < ${#ACCOUNTSID[*]};int++)); do
					[ "${ACCOUNTTYPE[${int}]}" = 'group' ] && continue

					if ! echo "${ACCOUNTNAME[${int}]}" | grep -Eioq "^${DOMAIN}@"; then continue ; fi

					local FILE="${GRPFILE}* ${GSDWFILE}*"

					for file in $FILE; do
						sed -i 's/\\/@/g' "$file"
						sed -i "s/,${ACCOUNTNAME[${int}]}/,${ACCOUNTNAME[${int}]#*@}/ig" "$file"
						sed -i 's/@/\\/g' "$file"
					done

					if [ -f "${SUDODIR}/cid-sudo-admusers" ]; then
						sed -i 's/\\\\/@/g' "${SUDODIR}/cid-sudo-admusers"

						if grep -aEwq "^${ACCOUNTNAME[${int}]}" "${SUDODIR}/cid-sudo-admusers"; then
							sed -i "s/^${ACCOUNTNAME[${int}]}/${ACCOUNTNAME[${int}]#*@}/g" "${SUDODIR}/cid-sudo-admusers"
						fi

						sed -i 's/@/\\\\/g' "${SUDODIR}/cid-sudo-admusers"
					fi
				done

				sed -ri "/ACCOUNTNAME\[[0-9]+\]='${DOMAIN}@.+'/s/${DOMAIN}@//g" "${DBDIR}/accountList.db"
			fi

			if Check_Backslash "$LOCKED_BY_NAME"; then
				sed -i "s/LOCKED_BY_NAME='${LOCKED_BY_NAME}'/LOCKED_BY_NAME='${LOCKED_BY_NAME#*@}'/" "${DBDIR}/station.db"
			fi
		;;
	esac

	case $(Check_Change 10) in
		1) [ "$ADDSMBFILE" ] && echo "ADDSMBFILE=$ADDSMBFILE" >> "${DBDIR}/station.db" ;;
		2) sed -i '/ADDSMBFILE/d' "${DBDIR}/station.db" ; unset ADDSMBFILE ;;
	esac

	Share_ConfigSmbfile false

	case $(Check_Change 1) in
		1) Manage_Service 'nmb' 'stop' ; Manage_Service 'nmb' 'mask' ;;
		2) Manage_Service 'nmb' 'unmask' ; Manage_Service 'nmb' 'start' ;;
	esac

	if [ "$(command -v samba-gpupdate)" ]; then
		case $(Check_Change 4) in
			1) samba-gpupdate -P --unapply ;;
			2) samba-gpupdate -P --force ;;
		esac
	fi

	[ "$(Check_Change 9)" = "1" ] && Create_Keytab

	Config_PAM
	Config_LogonScript

	local ARG='BACKEND MIN_ID MAX_ID NSSINFO'

	for arg in $ARG; do
		local par ; par=$(grep -aEw "^$arg=[[:graph:]]+" "${DBDIR}/station.db")

		if [ -n "$par" ] && [ "${par#*=}" != "${!arg}" ]; then
			sed -i "s/^$par/${par%=*}=${!arg}/" "${DBDIR}/station.db"
		fi
	done

	sed -i "s/MODO=$MODO/MODO=$OPTIONS/" "${DBDIR}/station.db" && MODO=$OPTIONS && unset OPTIONS
}

# Function: Reconfigure
Reconfigure () {
	OPTIONS="$MODO"

	if [ "$1" = 'update' ]; then
		local str FILE file ARG

		if [ -s "${DBDIR}/userLogons_history.db" ]; then
			FILE="${GRPFILE}* ${GSDWFILE}*"

			for file in $FILE; do
				[ ! -d "${RESTOREDIR}${file%/*}" ] && mkdir -p "${RESTOREDIR}${file%/*}"

				cp -f "$file" "${RESTOREDIR}$file"
				sed -i 's/\\/@/g' "$file"

				while read -r user; do
					if ! grep -axiq "$user" "${DBDIR}/admUsers_dynamicList.db"; then
						sed -i "s/,$user//ig" "$file"
					fi
				done <"${DBDIR}/userLogons_history.db"

				sed -i 's/@/\\/g' "$file"
			done

			rm -f "${DBDIR}/userLogons_history.db"
		fi

		if [ -s "${DBDIR}/admUsers_dynamicList.db" ]; then
			if [ -s "${DBDIR}/accountList.db" ]; then
				# shellcheck source=/dev/null
				. "${DBDIR}/accountList.db"

				rm -f "${DBDIR}/accountList.db"

				for ((int=0; int < ${#ACCOUNTSID[*]}; int++)); do
					Insert_AccountList "${ACCOUNTNAME[${int}]}" "${ACCOUNTSID[${int}]}" 'manual' 'group' "$int"
				done

				# shellcheck source=/dev/null
				. "${DBDIR}/accountList.db"
			fi

			file="${DBDIR}/admUsers_staticList.db"

			if [ -s "$file" ]; then
				unset str
			else
				str='auto'
			fi

			while read -r user; do
				Insert_AccountList "$user" "$(Get_Sid "${user/@/\\}")" "${str:-$(if grep -axiq "$user" "$file"; then echo 'manual'; fi)}"
			done <"${DBDIR}/admUsers_dynamicList.db"

			rm -f "$file" "${DBDIR}/admUsers_dynamicList.db"
		fi

		if [ -s "${DBDIR}/shareList.db" ] && ! grep -wq 'SHAREMODE' "${DBDIR}/shareList.db"; then
			# shellcheck source=/dev/null
			. "${DBDIR}/shareList.db"

			rm -f "${DBDIR}/shareList.db"

			for ((int=0; int < ${#SHARENAME[*]}; int++)); do
				ARG="SHAREMODE[${int}] SHARENAME[${int}] SHARETEMPLATE[${int}] SHAREPATH[${int}] SHARECOMMENT[${int}] SHAREQUOTA[${int}] SHARETOLERANCE[${int}] SHAREQUOTASUBD[${int}] SHAREHIDDEN[${int}] SHAREGUEST[${int}] SHARECFGFILE[${int}]"

				for arg in $ARG; do
					str="${arg%[*}" && str="${str,,}" && unset "$str"
					declare "$str"="${!arg}"
				done

				if [ -z "$sharemode" ]; then
					# shellcheck disable=SC2153
					case "${SHARERULE[${int}]}" in
						'Defined by CUPS'	) sharemode='printer' ;;
						'u:owner:f'			) sharemode='userfolder' ;;
						*					) sharemode='common' ;;
					esac
				fi

				Insert_ShareList "$int"
			done
		fi

		[ "$NTPFILE" = "/etc/ntp.conf" ] && sed -i '/NTPFILE/d' "${DBDIR}/station.db" && rm -f "${SYSTEMDDIR}/cid.service"
		[ -f "${PROFILEDIR}/cid_DomainUsersLogon.sh" ] && rm -f "${PROFILEDIR}/cid_DomainUsersLogon.sh"
		[ -f "${VARLIBDIR}/mount_netlogon.xml" ] && rm -f "${VARLIBDIR}/mount_netlogon.xml"
		[ -d "${MODELDIR}/scripts_cid" ] && rm -rf "${MODELDIR}/scripts_cid"

		if grep -Eiwq "(n|s)mb.*\.(target|service)" "${SYSTEMDDIR}/cid.service" || ! grep -Ewq "Documentation|true" "${SYSTEMDDIR}/cid.service"; then
			rm -f "${SYSTEMDDIR}/cid.service"
		fi

		Reconfigure 'reload'
	elif [ "$1" = "reload" ]; then
		Restore

		# shellcheck source=/dev/null
		. "${SCRIPTDIR}/vars.bash" "$1"

		Pre_Join
		Manage_Service 'smb' 'restart'
		Manage_Service 'winbind' 'restart'
		Post_Join
	else
		local f dir FILE='NSSFILE KRBFILE SMBFILE NTPFILE LDMFILE'

		for file in $FILE; do
			if [ -f "${!file}" ] && ! Check_Stamp "${!file}"; then
				f=${file,,} && Restore "${!file}" && "Config_$f"

				[ "$file" = 'SMBFILE' ] && smbcontrol all reload-config
			fi
		done

		if Pam_CheckStamp 1; then Config_PAM; fi

		if Config_hostfile; then
			net ads dns register -P
			Check_SMBDirs
		fi

		dir="$(smbd -b | grep -w 'LOCKDIR' | sed -r 's/.*: *//')"

		if [ -f "${DBDIR}/${WBCACHEFILE}" ] && [ -d "$dir" ]; then
			cp -pf "${DBDIR}/${WBCACHEFILE}" "$dir"
		fi
	fi

	unset OPTIONS
}


# shellcheck source=/dev/null
. /usr/share/cid/scripts/vars.bash

if [ "$1" = 'start' ] || [ "$1" = 'reload' ] || [ "$1" = 'update' ]; then
	Run "Reconfigure $1" "CID Init Script >> $1"
fi
