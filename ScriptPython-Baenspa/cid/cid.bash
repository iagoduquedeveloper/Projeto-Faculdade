#!/usr/bin/env bash
# Description: CID command line utility
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


# Function: Help_Main
Help_Main () {
	echo -e "Use: ${0##*/} [COMMAND]...
 or: ${0##*/} [OPTION]

Utility to insert and manage the computer in AD

COMMANDS:
    join\tInserts the computer in AD or changes its behavior
    leave\tRemove computer from AD
    block\tRestrict logon to a specific AD user or group
    unlock\tUnlocks the logon
    account\tManages AD accounts in local groups
    share\tManages file/printer shares
    status\tDisplays computer information

To view help of a specific command, run: ${0##*/} [COMMAND] {-h|--help}

OPTIONS:
    -h, --help\t\tShow this help and exit
    -v, --version\tShow the version and exit\n"
	exit "$1"
}

# Function: Help_No_Arguments
Help_No_Arguments () {
	if [ "$1" ]; then
		local int=2
	else
		local int=1
	fi

	echo -e "Use: ${0##*/} $FUNCTION
 or: ${0##*/} $FUNCTION [OPTION]

This requires the computer to belong to a domain!

OPTION:
    -h, --help\t\tShow this help and exit\n" >&$int
	exit "$1"
}

# Function: Help_Join
Help_Join () {
	echo -e "Use: ${0##*/} join [ARGUMENTS...] [OPTIONS...]
or: ${0##*/} join

Use options with no arguments to change the station's behavior if it already
belongs to a domain.

ARGUMENTS:
 domain=<fqdn>\t\tDomain Name
 user=<admin account>\tUser (domain admin)
 pass=<password>\tUser password
 ou=<container>\t\tOrganizational Unit (optional)
 host=<hostname>\tNew computer account name (optional)
 credentials=<filename>\tSpecifies a file that contains the arguments (optional)

 config_file={<path>|false}\tAdditional config file to \"Samba Global Section\"
\t\t\t\tThis acts as a behavior option (optional)

OPTIONS:
 --[no-]netbios\t\tEnable or disable NetBIOS over TCP/IP
 --[no-]kerberos\tEnable or disable authentication via Kerberos
 --[no-]ccache\t\tEnable or disable credential caching
 --[no-]logonscripts\tEnable or disable logon scripts
 --[no-]defaultdomain\tUse or does not the domain as default
 --[no-]auth-sudo\tEnable or disable authentication for the sudo command
 --[no-]share-printers\tShares or not all printers on CUPS via Samba
 --[no-]use-keytab\tUse or not keytab for kerberos validation in Samba
 --[no-]rfc2307\t\tUse or not the backend idmap_ad instead of idmap_tdb
\t\t\tIf enabled, requires the arguments:
   min_id=<NUM>\t\t\tInitial ID of the range for backend idmap_ad
   max_id=<NUM>\t\t\tLast ID of the range for backend idmap_ad
   nssinfo={rfc2307|template}\tInformation Base for Home and Shell of the user
\t\t\t\t(default: template)

    -p, --preserve\tPreserve previously set behavior options
    -h, --help\t\tShow this help and exit\n"
	exit "$1"
}

# Function: Help_Leave
Help_Leave () {
	echo -e "Use: ${0##*/} leave
 or: ${0##*/} leave [ARGUMENTS...]
 or: ${0##*/} leave [OPTION]

This requires the station to belong to a domain!

ARGUMENTS:
 user=<admin account>\tUser (domain admins)
 pass=<password>\tUser password
 credentials=<filename>\tSpecifies a file that contains the arguments (optional)

OPTION:
    -h, --help\t\tShow this help and exit\n"
	exit "$1"
}

# Function: Help_Block
Help_Block () {
	echo -e "Use: ${0##*/} block [username|@groupname]
 or: ${0##*/} block [OPTION]

This requires the station to belong to a domain!
You can enter only one user or group account!

OPTION:
    -h, --help\t\tShow this help and exit\n"
	exit "$1"
}

# Function: Help_Account
Help_Account () {
	echo -e "Use: ${0##*/} account {add|del} user1 @group1 @group2* 'DOMAIN\\user'...
 or: ${0##*/} account list [username|@groupname]
 or: ${0##*/} account [OPTION]

This requires the station to belong to a domain!

Use @groupname to add or remove a group account. By entering an asterisk (*)
at the end of the group name all members of this group will be added or removed
from the local groups of this computer.

SUBCOMMANDS:
    add\t\tAdd AD accounts to local groups
    del\t\tDelete AD accounts of the local groups
    list\tList AD accounts who have been added

Specify one or more accounts to add or remove.

OPTION:
    -h, --help\t\tShow this help and exit\n"
	exit "$1"
}

# Function: Help_Share
Help_Share () {
	echo -e "Use: ${0##*/} share add [ARGUMENTS...] [OPTIONS...]
 or: ${0##*/} share del fileshare printershare homes...
 or: ${0##*/} share list [sharename]

This requires the station to belong to a domain!

SUBCOMMANDS:
    add\t\tAdd/update file or printer share
    del\t\tDelete file or printer share
    list\tList the file or printer shares on this computer

Run cid $FUNCTION add {-h|--help} for the help of this subcommand.

OPTION:
    -h, --help\t\tShow this help and exit\n"
	exit "$1"
}

# Function: Function_Error
Function_Error () {
	echo -e "${1:-'Syntax error! Argument repeated!'}\n" >&2
	"Help_${2:-${FUNCTION^}}" 1
}

# Function: Error
Error () {
	echo -e "An unexpected error occurred!\nSee ${LOGDIR}/functions.log for more details." >&2
	exit 255
}

# Function: Check_Member_Domain
Check_Member_Domain () {
	[ ! -s "${DBDIR}/station.db" ] && echo "This command requires the station to belong to a domain!" >&2 && exit 1
}

# Function: Import_Functions
Import_Functions () {
	if [ "$(id -u)" -eq 0 ]; then
		if [ -f "${workdir%/*}/scripts/functions.bash" ]; then
			# shellcheck source=/dev/null
			. "${workdir%/*}/scripts/functions.bash"
		else
			echo "File ${workdir%/*}/scripts/functions.bash not found!" > "${TEMPFILE:=/tmp/._cidError}"
			"${workdir%/*}/scripts/logger.bash" "$TEMPFILE" "${0##*/}" 1 2>/dev/null
			Error
		fi
	else
		echo -e "Permission denied!\nRun: sudo ${0##*/} $FUNCTION" >&2
		exit 1
	fi
}

# Function: Check_NoPart
Check_NoPart () {
	echo "$1" | grep -q '\-\-no\-' ; return $?
}

# Function: Check_CfgFile
Check_CfgFile () {
	if [ "$1" ]; then
			[ "$1" = 'false' ] && return 2

			if [ -s "$1" ]; then
				if [ "$1" = "$SMBFILE" ]; then
					Function_Error "'config_file' cannot be the samba config file!" "$2"
				else
					return 0
				fi
			fi

			Function_Error "'config_file' must receive the path to a regular text file or 'false'!" "$2"
	else
		return 1
	fi
}

# Function: Flag
Flag () {
	case "$1" in
		y|Y) ;;
		*) echo 'Aborted!' ; exit 2 ;;
	esac
}

# Function: Define_Vars
Define_Vars () {
	# shellcheck disable=SC2086
	unset bool obj FILE INT ${!OBJ*} ${!ACCOUNT*}
	OBJ="${1,,}"

	[ "${OBJ:(-1)}" = "*" ] && OBJ=${OBJ%\*} && bool[0]=true
	[ "${OBJ:0:1}" = "@" ] && OBJ=${OBJ#@} && OBJ_TYPE=group && FILE=$GRPFILE

	OBJ_TYPE="${OBJ_TYPE:=user}" && FILE="${FILE:=$PWDFILE}"

	Run 'Check_Obj' ; local status=$?

	case $status in
		0) ;;
		2) echo "$1 argument contains an invalid character!" >&2 ;;
		3) echo "$OBJ is a local ${OBJ_TYPE}!" >&2 ;;
		4) echo "$OBJ $OBJ_TYPE not found!" >&2 ;;
		*) if [ "$2" ]; then "$2"; else echo "Error processing $1 argument!" >&2; fi ;;
	esac

	return $status
}


# Start:
if [ -L "$0" ]; then workdir=$(readlink -m "$0"); else workdir=$0; fi

if [ -f "${workdir%/*}/scripts/vars.bash" ]; then
	# shellcheck source=/dev/null
	. "${workdir%/*}/scripts/vars.bash"
else
	echo "${workdir%/*}/scripts/vars.bash file not found!" >&2
	exit 127
fi

FUNCTION=$1 && shift

case $FUNCTION in
	join)
		if [ $# -eq 0 ]; then
			OPTIONS=default
		elif [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
			"Help_${FUNCTION^}" "$(if [ "$#" -eq 1 ]; then echo 0; else echo 1; fi)"
		else
			unset bool opt OPTIONS status host config_file
		fi

		while [ $# -gt 0 ]; do
			if echo "$1" | grep -Ewq "(domain|user|pass|ou|host|credentials|min_id|max_id|config_file)=[[:print:]]+|nssinfo=(rfc2307|template)"; then
				arg=${1%%=*}

				if [ -n "${!arg}" ]; then
					Function_Error
				else
					# shellcheck disable=SC2163
					export "$1"
				fi
			elif echo "$1" | grep -Ewq "\-p|\-\-(preserve|(no-)?(netbios|kerberos|ccache|logonscripts|defaultdomain|auth-sudo|share-printers|use-keytab|rfc2307))"; then
				function Check_OPT {
					if echo "$opt $OPTIONS" | grep -wq "$1"; then Function_Error; fi
				}

				function Insert_OPT {
					if [ "$3" ]; then
						if ! Check_NoPart "$1"; then OPTIONS=${OPTIONS:+$OPTIONS-}${2}; else opt=${opt:+${opt} }${2}; fi
					else
						if Check_NoPart "$1"; then OPTIONS=${OPTIONS:+$OPTIONS-}${2}; else opt=${opt:+${opt} }${2}; fi
					fi
				}

				case $1 in
					--no-netbios|--netbios					) Check_OPT 1 ; Insert_OPT "$1" 1 ;;
					--no-kerberos|--kerberos				) Check_OPT 2 ; Insert_OPT "$1" 2 ;;
					--no-ccache|--ccache					) Check_OPT 3 ; Insert_OPT "$1" 3 ;;
					--no-logonscripts|--logonscripts		) Check_OPT 4 ; Insert_OPT "$1" 4 ;;
					--no-defaultdomain|--defaultdomain		) Check_OPT 5 ; Insert_OPT "$1" 5 ;;
					--no-auth-sudo|--auth-sudo				) Check_OPT 6 ; Insert_OPT "$1" 6 false ;;
					--no-rfc2307|--rfc2307					) Check_OPT 7 ; Insert_OPT "$1" 7 false ;;
					--no-share-printers|--share-printers	) Check_OPT 8 ; Insert_OPT "$1" 8 false ;;
					--no-use-keytab|--use-keytab			) Check_OPT 9 ; Insert_OPT "$1" 9 false ;;
					-p|--preserve							) [ "${bool[0]}" ] && Function_Error ; bool[0]=true ;;
				esac
			else
				Function_Error "$1 argument is invalid!"
			fi

			shift
		done

		# shellcheck disable=SC2154
		Check_CfgFile "$config_file" ; status=$?

		if [ $status -ne 1 ]; then
			[ "$OPTIONS" = 'default' ] && unset OPTIONS

			OPTIONS=${OPTIONS:+$OPTIONS-}10
		fi

		function Config_Backend () {
			if ! echo "$OPTIONS" | grep -wq '7'; then
				# shellcheck disable=SC2154
				if [ -n "$min_id" ] || [ -n "$max_id" ] || [ -n "$nssinfo" ]; then
					Function_Error "nssinfo, min_id and max_id arguments require the --rfc2307 option!"
				fi
			else
				if [ -z "$min_id" ]; then
					Function_Error "The --rfc2307 option requires at least the min_id argument!"
				elif Check_NoNum "$min_id" || Check_NoNum "$max_id"; then
					Function_Error "min_id and max_id must contain an integer!"
				elif [ "$min_id" -le "$MAX_LOCAL_ID" ]; then
					Function_Error "IDs less than $((MAX_LOCAL_ID+1)) are used by the local system!"
				elif [ -n "$max_id" ] && [ "$max_id" -le "$min_id" ]; then
					Function_Error "max_id must be greater than min_id!"
				else
					export MIN_ID=$min_id
					export MAX_ID=${max_id:=$((min_id+(ID_RANGE_SIZE-1)))}
					export BACKEND=ad
					export NSSINFO=${nssinfo:=template}
				fi
			fi
		}

		function Config_AddCfgFile () {
			case $status in
				0) export ADDSMBFILE="$config_file" ;;
				2) OPTIONS=$(echo "$OPTIONS" | sed -r 's/-?10//;s/^-//') ; unset ADDSMBFILE ;;
				*) return 1 ;;
			esac
		}

		function Config_Options () {
			if [ "$OPTIONS" ]; then
				for int in $opt; do
					if echo "$OPTIONS" | grep -wq "$int"; then
						OPTIONS=$(echo "$OPTIONS" | sed -r "s/-?${int}//;s/^-//")
					fi
				done
			fi
		}

		if [ -s "${DBDIR}/station.db" ]; then
			# shellcheck disable=SC2154
			if [ -n "$domain" ] || [ -n "$user" ] || [ -n "$pass" ] || [ -n "$credentials" ] || [ -n "$ou" ] || [ -n "$host" ]; then
				Function_Error "The arguments are not valid when the computer belongs to a domain, except 'config_file'!"
			fi

			if [ "$OPTIONS" ] || [ "$opt" ]; then
				Import_Functions
				Config_Backend

				[ "$OPTIONS" = 'default' ] && unset OPTIONS

				for int in $opt; do
					if echo "$MODO" | grep -wq "$int"; then
						OPTIONS=${OPTIONS:=$MODO}
						bool[1]=false
						Config_Options
						break
					fi
				done

				OPTIONS=${OPTIONS:=default}

				if [ "${bool[1]}" != 'false' ]; then
					for int in ${OPTIONS//-/ }; do
						if ! echo "$MODO" | sed -r 's/-?(7|10)//;s/^-//' | grep -wq "$int"; then
							bool[1]=false
							break
						fi
					done
				fi

				[ "${bool[1]}" != 'false' ] && echo 'No changes!' >&2 && exit 2

				if [ "${bool[0]}" ] && [ "$MODO" != 'default' ]; then
					[ "$OPTIONS" = 'default' ] && unset OPTIONS

					for int in ${MODO//-/ }; do
						if ! echo "$OPTIONS" | grep -wq "$int"; then
							OPTIONS=${OPTIONS:+$OPTIONS-}$int
						fi
					done
				fi

				Config_AddCfgFile
				Config_Options ; OPTIONS=${OPTIONS:=default}

				[ "$OPTIONS" = "$MODO" ] && echo 'No changes!' >&2 && exit 2

				Run 'Change_Behavior'
				echo 'Changes completed!' && exit 0
			else
				[ "${bool[0]}" ] && Function_Error "-p or --preserve must be used with other behavior options!"
			fi
		else
			[ "${bool[0]}" ] && Function_Error "-p or --preserve are valid only when the station belongs to a domain!"

			if [ -n "$credentials" ]; then
				if [ -f "$credentials" ]; then
					if [ ! "$(cat "$credentials")" ]; then
						Function_Error "File $credentials contains no arguments!"
					elif grep -Exv "(domain|user|pass|ou|host)=[[:print:]]+" "$credentials"; then
						Function_Error "$credentials file contains invalid arguments!"
					else
						# shellcheck source=/dev/null
						. "$credentials"
					fi
				else
					Function_Error "$credentials file not found!"
				fi
			fi

			if [ -z "$domain" ] || [ -z "$user" ] || [ -z "$pass" ]; then
				Function_Error "domain, user and pass arguments are required!"
			else
				if [ -n "$host" ] && ! command -v hostnamectl >/dev/null 2>&1; then
					echo "Cannot use host argument! \`hostnamectl\` command not found!" >&2 ; exit 1
				fi

				Import_Functions
				Check_Hostname "${host:-${HOSTNAME}}"

				case "$?" in
					0) export HOST="${host:-${HOSTNAME}}" ;;
					1) echo "The hostname cannot be longer than 15 characters for compatibility with the NetBIOS API!" >&2 ; exit 1 ;;
					2) echo "The hostname cannot start with a hyphen (-)!" >&2 ; exit 1 ;;
					3) echo "Hostname contains invalid character!" >&2 ; exit 1 ;;
				esac

				Config_Backend
				Config_AddCfgFile
				Config_Options
				OPTIONS=${OPTIONS:='default'}
				FQDN=${domain,,}
				DOMAIN=${workgroup:=${FQDN%%.*}} && DOMAIN=${DOMAIN^^}
				DOMAINUSER=${user,,}
				PASS=$pass

				if [ -z "$ou" ]; then
					OU='computers'
					export TEST_OU=0
				else
					OU=${ou,,}
					export TEST_OU=1
				fi

				function Clear_Mem () {
					unset FQDN DOMAIN HOST OU TEST_OU DOMAINUSER PASS BACKEND MIN_ID MAX_ID NSSINFO ADDSMBFILE
				}

				function Success () {
					Run 'Success_Join'
					echo "Welcome to the $DOMAIN domain!"
					[ "$1" ] && echo -e "WARNING: $1"
					echo 'Reboot recommended!'
					Clear_Mem
				}

				Run

				case $? in
					0|4) Success ; exit 0 ;;
					1) old_ou=$OU ; OU='computers' ; Success "$old_ou OU not found!\nAccount created in \"computers\"!" ; exit 2 ;;
					2) old_ou=$OU ; OU='unknown' ; Success "$old_ou OU not found!\nAccount created in default OU!" ; exit 3 ;;
					3) OU='unknown' ; Success ; exit 4 ;;
					255) echo -e "Failure to join \"$DOMAIN\"!\nSee ${LOGDIR}/functions.log for more details." >&2 ; Run 'Restore' ; Clear_Mem ; exit 1 ;;
					*) Clear_Mem ; Error ;;
				esac
			fi
		fi
	;;
	leave)
		# shellcheck disable=SC2166
		if [ $# -eq 1 ] && [ "$1" = "-h" -o "$1" = "--help" ]; then
			"Help_${FUNCTION^}" 0	
		elif [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
			"Help_${FUNCTION^}" 1
		fi

		unset user pass credentials

		while [ $# -gt 0 ]; do
			if ! echo "$1" | grep -Ewq "(user|pass|credentials)=[[:print:]]+"; then Function_Error "Argument $1 is invalid!" ; fi

			arg=${1%%=*}

			if [ -n "${!arg}" ]; then
				Function_Error
			else
				# shellcheck disable=SC2163
				export "$1"
			fi

			shift
		done

		Check_Member_Domain

		if [ -n "$credentials" ]; then
			if [ -f "$credentials" ]; then
				if [ ! "$(cat "$credentials")" ]; then
					Function_Error "$credentials file contains no arguments!"
				elif grep -Exvq "(user|pass)=[[:print:]]+" "$credentials"; then
					Function_Error "$credentials file contains invalid arguments!"
				else
					# shellcheck source=/dev/null
					. "$credentials"
				fi
			else
				Function_Error "$credentials file not found!"
			fi
		fi

		if [ -z "$user" ] && [ -n "$pass" ]; then
			Function_Error "The pass argument requires user argument!"
		else
			Import_Functions

			if [ -n "$user" ]; then
				export DOMAINUSER=$user PASS=${pass:-$user}
			else
				echo -n "Are you sure you want to remove domain join settings? [N/y] " && read -r flag && Flag "$flag"
			fi

			if ! Run; then
				echo "WARNING: Could not delete computer account from domain!"
			fi

			echo -e "Successful procedures!\nReboot recommended!"
			unset user pass credentials
			exit 0
		fi
	;;
	block)
		# shellcheck disable=SC2166
		if [ $# -eq 0 ] || [ $# -eq 1 -a "$1" = "-h" ] || [ $# -eq 1 -a "$1" = "--help" ]; then
			"Help_${FUNCTION^}" 0
		fi

		Check_Member_Domain

		[ $# -gt 1 ] && Function_Error "This command receives only one account!"

		Import_Functions
		Define_Vars "$1" 'Error' ; status=$?

		[ $status -eq 0 ] || exit $status

		if ! Run; then Error ; fi

		echo 'Restricted logon!' && exit 0
	;;
	unlock)
		if [ $# -gt 0 ]; then
			# shellcheck disable=SC2166
			if [ $# -eq 1 ] && [ "$1" = "-h" -o "$1" = "--help" ]; then
				Help_No_Arguments 0
			else
				Help_No_Arguments 1
			fi
		else
			Check_Member_Domain
			Import_Functions
			Run

			case $? in
				0) echo 'Unrestricted logon!' ; exit 0 ;;
				1) Error ;;
				255) echo 'Lock parameter not found!' >&2 ; exit 2 ;;
			esac
		fi
	;;
	account)
		# shellcheck disable=SC2166
		if [ $# -eq 0 ] || [ $# -eq 1 -a "$1" = "-h" ] || [ $# -eq 1 -a "$1" = "--help" ]; then
			"Help_${FUNCTION^}" 0
		elif [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
			"Help_${FUNCTION^}" 1
		elif [ "$1" != "add" ] && [ "$1" != "del" ] && [ "$1" != "list" ]; then
			Function_Error "$1 argument is invalid!"
		else
			subfunction=$1 && shift
		fi

		Check_Member_Domain
		Import_Functions

		case $subfunction in
			list)
				function PrintAccount {
					echo "Account Name: ${ACCOUNTNAME[${1}]/@/\\}
Account Type: ${ACCOUNTTYPE[${1}]}
Mode: ${ACCOUNTMODE[${1}]}"
				}

				if [ $# -eq 0 ]; then
					[ -s "${DBDIR}/accountList.db" ] || exit 1

					# shellcheck source=/dev/null
					. "${DBDIR}/accountList.db"

					for ((int=0; int < ${#ACCOUNTSID[*]}; int++)); do
						PrintAccount "$int" ; [ $((int+1)) -eq ${#ACCOUNTSID[*]} ] || echo
					done

					exit 0
				elif [ $# -eq 1 ]; then
					[ -s "${DBDIR}/accountList.db" ] || Function_Error 'No accounts!'

					if Define_Vars "$1" ; then
						Run 'Check_AccountName'

						case $? in
							0	) echo "$OBJ $OBJ_TYPE not found!" >&2 ; exit 1 ;;
							1|2	)
									# shellcheck source=/dev/null
									. "${DBDIR}/accountList.db"

									PrintAccount "$INT" ; exit 0
								;;
							3	) echo "$OBJ group is already added by default!" >&2 ; exit 3 ;;
							*	) Function_Error "Error processing $1 argument!" ;;
						esac
					fi
				else
					Function_Error "$subfunction only receives a maximum of one argument!"
				fi
			;;
			add)
				[ $# -lt 1 ] && Function_Error "$subfunction requires one (or more) account!"

				function AddObjSysGrp () {

					function Add_AllGroupMembers () {
						status=1

						if [ "$OBJ_TYPE" = "group" ] && [ "${bool[0]}" ]; then
							obj="$OBJ" && OBJ_TYPE='user' && FILE="$PWDFILE"

							for OBJ in $(Get_AllGroupMembers "$obj"); do
								Fix_Obj ; AddObjSysGrp
							done

							status=0
						fi
					}

					Run "Addaccount"

					case $? in
						0)
							echo "$OBJ $OBJ_TYPE added!" ; Add_AllGroupMembers ; status=0
						;;
						1)
							Add_AllGroupMembers
							[ $status -ne 0 ] && echo "$OBJ $OBJ_TYPE has already been added to system groups!" >&2
						;;
						2)
							Add_AllGroupMembers
							[ $status -ne 0 ] && echo "The $OBJ $OBJ_TYPE had already been added to the local groups with the name '${STR}'! The ${OBJ_TYPE}name has been updated!" >&2 && status=2
						;;
						3)
							Add_AllGroupMembers
							[ $status -ne 0 ] && echo "Members of the $OBJ group are already automatically added to the local groups!" >&2 && status=3
						;;
						*)
							echo "Error adding $OBJ $OBJ_TYPE to system groups!" >&2 ; status=255
						;;
					esac
				}

				while [ $# -gt 0 ]; do
					Define_Vars "$1" ; status=$?
					[ $status -eq 0 ] && AddObjSysGrp
					shift
				done

				exit $status
			;;
			del)
				function RemObjSysGrp () {
					Run 'Delobj account' ; status=$?

					[ $status -eq 0 ] && echo "$1 $2 deleted!" && return 0

					echo "Error processing ${3:-$1} argument!" >&2
					status=255
				}

				function Rem_AllGroupMembers () {
					[ "${bool[0]}" ] || return 1

					# shellcheck source=/dev/null
					. "${DBDIR}/accountList.db"

					for ((int=$((${#ACCOUNTSID[*]}-1));int >= 0;int--)); do
						[ "${ACCOUNTTYPE[${int}]}" = "group" ] && continue

						if ! Check_AdminUser "${ACCOUNTSID[${int}]}" "$1"; then continue ; fi

						INT=$int ; RemObjSysGrp "${ACCOUNTNAME[${int}]/@/\\}" "${ACCOUNTTYPE[${int}]}"
					done

					return 0
				}

				[ $# -lt 1 ] && Function_Error "$subfunction requires one (or more) username!"

				while [ $# -gt 0 ]; do
					Define_Vars "$1" ; status=$?

					if [ $status -eq 0 ]; then
						Run 'Check_AccountName'

						case $? in
							0)
								echo "$OBJ $OBJ_TYPE not found!" >&2
								status=1
							;;

							1|2)
								# shellcheck source=/dev/null
								. "${DBDIR}/accountList.db"
								RemObjSysGrp "$OBJ" "$OBJ_TYPE" "$1"

								[ "$OBJ_TYPE" = "group" ] && Rem_AllGroupMembers "${ACCOUNTSID[${INT}]}"
							;;

							3)
								Rem_AllGroupMembers
								[ $? -eq 1 ] && echo "The $OBJ group cannot be removed!" >&2 && status=3
							;;

							*)
								echo "Error processing $1 argument!" >&2 ; status=255
							;;
						esac
					fi

					shift
				done

				exit $status
			;;
		esac
	;;
	share)
		# shellcheck disable=SC2166
		if [ $# -eq 0 ] || [ $# -eq 1 -a "$1" = "-h" ] || [ $# -eq 1 -a "$1" = "--help" ]; then
			"Help_${FUNCTION^}" 0
		elif [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
			"Help_${FUNCTION^}" 1
		elif [ "$1" != "add" ] && [ "$1" != "del" ] && [ "$1" != "list" ]; then
			Function_Error "Argument $1 is invalid!"
		else
			subfunction=$1 && shift
		fi

		case $subfunction in
			list)
				Check_Member_Domain

				function PrintShare {
					local str ; str=$(Get_ShareRule "$1")

					# shellcheck disable=SC1078,SC2001,SC2153
					echo "Mode: ${SHAREMODE[${1}]}
Name: ${SHARENAME[${1}]}
Template: ${SHARETEMPLATE[${1}]:-None}
Path: ${SHAREPATH[${1}]}
Comment: ${SHARECOMMENT[${1}]}
Disk Quota: $(ReadQuota "${SHAREQUOTA[${1}]:-None}")
Tolerance Quota: $(ReadQuota "${SHARETOLERANCE[${1}]:-None}")
Subdirs Quotas: ${SHAREQUOTASUBD[${1}]}
Hidden: ${SHAREHIDDEN[${1}]}
Guest: ${SHAREGUEST[${1}]}
Add Config File: ${SHARECFGFILE[${1}]:-None}
Rules:$(echo "$str" | sed 's/^/\t/g')"
				}

				if [ $# -eq 0 ]; then
					[ -s "${DBDIR}/shareList.db" ] || exit 1

					Import_Functions

					# shellcheck source=/dev/null
					. "${DBDIR}/shareList.db"

					for ((int=0; int < ${#SHARENAME[*]}; int++)); do
						PrintShare "$int" ; [ $((int+1)) -eq ${#SHARENAME[*]} ] || echo
					done

					exit 0
				elif [ $# -eq 1 ]; then
					Import_Functions ; unset INT

					if Get_ObjID 'share' "${1,,}"; then
						if [ -n "$INT" ]; then
							# shellcheck source=/dev/null
							. "${DBDIR}/shareList.db"

							PrintShare "$INT" ; exit 0
						else
							echo "$1 not found!" >&2 ; exit 1
						fi
					else
						echo 'No shares!' >&2 ; exit 1
					fi
				else
					Function_Error "$subfunction only receives a maximum of one argument!"
				fi
			;;
			add)
				function Help_Addshare () {
					echo -e "Use: ${0##*/} $FUNCTION $subfunction [ARGUMENTS...] [OPTIONS...]

Some arguments and/or options only work in specific modes.
(See documentation!)

To update a share it is necessary to specify only the arguments and/or 
options you want to change.

ARGUMENTS:
 mode={common|userfolder|printer}\tShare mode (default: common)
 name=<sharename>\t\t\tShare name
 template=<sharename>\t\t\tShare template
 path=<folder|printer>\t\t\tDirectory path or printer name in CUPS
 comment=<description>\t\t\tDescription
 quota=<value>[unit]\t\t\tDisk quota size
 tolerance=<value>[unit]\t\tTolerance quota size
\t\t\t\t\tPossible units: {k|m|g|t|p|e|z|y}

 rule=[{+|-}]{u|g}:account:{r|f|d}\tAccess rule to sharing (default: u:everyone:r)
 config_file={<path>|false}\t\tAdditional config file to \"Samba share section\"

OPTIONS:
    --[no-]subdir-quota\t\tApply or not apply quota to the fst-level of subdirs
    --[no-]hidden\t\tHide or not hide share
    --[no-]allow-guest\t\tAllow or disallow guest (non-authenticated access)


    -h, --help\t\t\tShow this help and exit\n"
					exit "$1"
				}

				# shellcheck disable=SC2166
				if [ $# -eq 0 ] || [ $# -eq 1 -a "$1" = "-h" ] || [ $# -eq 1 -a "$1" = "--help" ]; then
					Help_Addshare 0
				elif [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
					Help_Addshare 1
				else
					# shellcheck disable=SC2001,SC2046,SC2086
					unset ${!share*} $(echo ${!SHARE*} | sed 's/SHAREDIR//') config_file
				fi

				Check_Member_Domain
				Import_Functions

				while [ $# -gt 0 ]; do
					if echo "$1" | grep -Ewq "(name|template|path|comment|quota|tolerance|rule|config_file)=[[:print:]]+|mode=(common|userfolder|printer)"; then
						arg=${1%%=*}
						
						if [ -n "${!arg}" ]; then
							Function_Error 'Syntax error! Argument repeated!' 'Addshare'
						else
							# shellcheck disable=SC2163
							export "$1"
						fi
					elif echo "$1" | grep -Ewq "\-\-(no-)?(subdir-quota|hidden|allow-guest)"; then
						case $1 in
							--no-subdir-quota|--subdir-quota	)
										[ "$sharequotasubd" ] && Function_Error 'Syntax error! Argument repeated!' 'Addshare'

										if Check_NoPart "$1"; then
											sharequotasubd='No'
										else
											sharequotasubd='Yes'
										fi
																;;

							--no-hidden|--hidden				)
										[ "$sharehidden" ] && Function_Error 'Syntax error! Argument repeated!' 'Addshare'

										if Check_NoPart "$1"; then
											sharehidden='No'
										else
											sharehidden='Yes'
										fi
																;;

							--no-allow-guest|--allow-guest		)
										[ "$shareguest" ] && Function_Error 'Syntax error! Argument repeated!' 'Addshare'

										if Check_NoPart "$1"; then
											shareguest='No'
										else
											shareguest='Yes'
										fi
																;;
						esac
					else
						Function_Error "$1 argument is invalid!" 'Addshare'
					fi

					shift
				done

				Check_CfgFile "$config_file" 'Addshare'

				case $? in
					0) export sharecfgfile="$config_file" ;;
					2) export sharecfgfile='No' ;;
				esac

				ARG='mode name template path comment quota tolerance rule'

				for arg in $ARG; do
					export "share${arg}=${!arg}" && unset "$arg"
				done

				# shellcheck source=/dev/null
				[ -s "${DBDIR}/shareList.db" ] && . "${DBDIR}/shareList.db"

				Run 'Check_ShareArgs'

				# shellcheck disable=SC2154
				case $? in
					1	) Function_Error "The name argument is required!" 'Addshare' ;;
					2	) Function_Error "You cannot use a template with the same name as the share!" 'Addshare' ;;
					3	) Function_Error "You cannot change the mode of a share!" 'Addshare' ;;
					4	) Function_Error "You cannot change a share's directory!" 'Addshare' ;;
					5	) Function_Error "The \"Userfolder\" mode does not accept templates!" 'Addshare' ;;
					6	) echo "There are no changes applicable to this share!" >&2 ; exit 6 ;;
					7	) Function_Error "\"$sharename\" is a reserved word and cannot be used!" 'Addshare' ;;
					8	) Function_Error "The share name contains an invalid character!" 'Addshare' ;;
					9	) Function_Error "Template and Share must have the same mode!" 'Addshare' ;;
					10	) Function_Error "The \"homes\" share cannot be copied!" 'Addshare' ;;
					11	) Function_Error "The \"Printer\" mode requires the \"Name\" or \"Path\" argument!" 'Addshare' ;;
					12	) Function_Error "The \"Common\" mode requires the \"Name\" and \"Path\" argument!" 'Addshare' ;;
					13	) Function_Error "Directory paths must be started with a slash \"(/)\"!" 'Addshare' ;;
					14	) Function_Error "The \"$sharepath\" printer was not found on the CUPS server!" 'Addshare' ;;
					15	) Function_Error "The \"$sharepath\" path is already being used by the share \"${SHARENAME[${INT}]}\"!" 'Addshare' ;;
					16	) echo "WARNING: Some arguments are not compatible with \"$sharemode\" mode and will be ignored!" >&2 ;;
					17	) Function_Error "The \"bc\" software is required for quota usage and was not found!" 'Addshare' ;;
					18	) Function_Error "The quota feature is currently only available on \"XFS\" file systems!" 'Addshare' ;;
					19	) Function_Error "The \"$sharequotadev\" device must be mounted with the \"prjquota\" option!" 'Addshare' ;;
					20	) Function_Error "Invalid quota value!" 'Addshare' ;;
					21	) Function_Error "Invalid quota unit!" 'Addshare' ;;
					22	) Function_Error "The \"tolerance quota\" must be less than the \"disk quota\"!" 'Addshare' ;;
					23	) Function_Error "The disk quota cannot be greater than the total disk space on the partition of the shared directory!" 'Addshare' ;;
					24	) Function_Error "Tolerance quota requires setting a disk quota value!" 'Addshare' ;;
					25	) Function_Error "Subdirectory quotas requires setting a disk quota value!" 'Addshare' ;;
					26	) Function_Error "Rule contains an invalid format!" 'Addshare' ;;
					27	) Function_Error "There is a conflict of rules for the same account!" 'Addshare' ;;
					28	) Function_Error "The rule contains an invalid account!" 'Addshare' ;;
				esac

				if [ "$INT" ]; then
					wrd='updat'
				else
					wrd='add'
				fi

				Run 'Addshare' ; status=$?

				if [ "$status" -eq 0 ]; then
					echo "$sharename share ${wrd}ed!"
				else
					echo "Error ${wrd}ing the \"${sharename}\" share!" >&2
				fi

				# shellcheck disable=SC2086
				unset INT ${!share*}

				exit "$status"
			;;
			del)
				Check_Member_Domain
				[ $# -lt 1 ] && Function_Error "$subfunction requires one (or more) sharename!"

				Import_Functions

				while [ $# -gt 0 ]; do
					Get_ObjID 'share' "${1,,}"

					[ $? -eq 1 ] && Function_Error "There is currently no shares to remove!"
					[ -z "$INT" ] && echo "$1 not found!" >&2 && status=1 && shift && continue

					# shellcheck source=/dev/null
					[ "${SHARENAME[0]}" ] || . "${DBDIR}/shareList.db"

					Run 'Delobj share' ; status=$?

					if [ "$status" -eq 0 ]; then
						echo "$1 deleted!"
					else
						echo "Failed to remove ${1}!" >&2
					fi

					shift
				done

				exit "$status"
			;;
		esac
	;;
	status)
		if [ $# -gt 0 ]; then
			# shellcheck disable=SC2166
			if [ $# -eq 1 ] && [ "$1" = "-h" -o "$1" = "--help" ]; then
				Help_No_Arguments 0
			else
				Help_No_Arguments 1
			fi
		else
			Check_Member_Domain
			Import_Functions
			Show_State
			exit $?
		fi
	;;
	-v|--version)
		if [ $# -eq 0 ]; then
			echo "CID version $VERSION" && exit 0
		else
			Help_Main 1
		fi
	;;
	-h|--help)
		if [ $# -eq 0 ]; then
			Help_Main 0
		else
			Help_Main 1
		fi
	;;
	*)
		Help_Main 1
	;;
esac
