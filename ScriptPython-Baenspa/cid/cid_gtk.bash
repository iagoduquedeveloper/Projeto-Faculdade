#!/usr/bin/env bash
# Description: CID interactive interface (GTK+)
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


# Function: Menu
Menu () {

	# Subfunction: Menu >> Error
	Error () {
		# shellcheck disable=SC2153
		[ -s "$TEMPFILE" ] || echo "Execution error on: $1" > "$TEMPFILE"

		"${0%/*}/scripts/logger.bash" "$TEMPFILE" "$1" "$2"

		local str ; str="
		An unexpected error has occurred!


Check the application log in the menu \"Help >> App log\",
or see the \"${LOGDIR}/functions.log\" file.


			Aborting operation...
"
		Message "$str" 'error'
		Menu
	}

	# Subfunction: Menu >> Help
	Help () {

		# Subfunction: Menu >> Help >> Show_Log
		Show_Log () {
			local int

			if [ -f "${LOGDIR}/${1:-functions}.log" ]; then
				int="$(grep -anEwm 1 "^$(LC_ALL=C date "+%b %d")" "${LOGDIR}/${1:-functions}.log" | cut -d ':' -f 1)"
			else
				unset int
			fi

			if [ -f "${LOGDIR}/${1:-functions}.log" ] && [ "$int" ]; then
				tempfile="$(Tempfile 'daylog')"
				par='--width=700 --height=700'
				str="$(if [ "$1" ]; then echo "${1^}"; else echo 'App'; fi) log"

				tail -n +"$int" "${LOGDIR}/${1:-functions}.log" >"$tempfile"
			else
				Message "\nNo log records found on the current date!\n\nCheck the complete log of the application in \"${LOGDIR}/${1:-functions}.log\" file.\n" 'warning'
				Help
			fi
		}


		# Exec: Help
		local function int ; unset tempfile

		function='cid-gtk >> Help'

		int="$(zenity --list \
		 --title="Help" --width="400" --height="550" --window-icon="${0%/*}/icons/cid.png" --radiolist --hide-header --hide-column=2 \
		 --ok-label="Select" --cancel-label="Back" --text="\n Select an option:\n" \
		 --column="" --column="" --column="" \
	TRUE 1 "

About CID

" \
	FALSE 2 "

Station info

" \
	FALSE 3 "

App log

" \
	FALSE 4 "

Scripts log

" 2>/dev/null)"
		case "$int" in
			1)
				Message "CID version ${VERSION}\n\nLicense: GPLv3\n\nHome: https://c-i-d.sourceforge.io\n\nCopyright \(C\) 2012-2023 Eduardo Moraes" 'info' 'About CID'

				Help
			;;
			2)
				[ ! -s "${DBDIR}/station.db" ] && Message "\nThere is no data to display because the station does not belong to a domain!\n" 'warning' && Help

				local tempfile par str
				tempfile="$(Tempfile 'state')"
				
				Show_State >"$tempfile"
				par='--width=450 --height=650'
				str='Station info'
			;;
			3)
				Show_Log
			;;
			4)
				Show_Log 'scripts'
			;;
			*)
				Menu
			;;
		esac

		if [ -f "$tempfile" ]; then
			# shellcheck disable=SC2086
			if zenity --text-info $par --title="$str" --window-icon="${0%/*}/icons/cid.png" \
			--ok-label="Back" --cancel-label="Menu" --filename="$tempfile" 2>/dev/null; then
				Help
			else
				Menu
			fi
		else
			echo "File $tempfile not found!" > "$TEMPFILE" && Error "$function" 1
		fi
	}

	# Subfunction: Menu >> Progress
	Progress () {
		local tempfile ; tempfile="$(Tempfile 'pid')"

		(
			while : ; do : ; done
		) | zenity --progress --title="$3" --width="400" --height="550" --window-icon="${0%/*}/icons/cid.png" \
		--text="${4:-"$3"}" --percentage=0 --pulsate --no-cancel --time-remaining --auto-close &

		echo $! >"$tempfile"
		Run "$1" "$2" "$5" ; local status=$?
		kill "$(cat "$tempfile")" "$(($(cat "$tempfile") - 1))"
		return $status
	}

	# Subfunction: Menu >> Select_File
	Select_File () {
		unset "$1"

		export "${1}"="$(zenity --file-selection --title="Select additional config file" "${2:---filename="$2"}" 2>/dev/null)"

		[ "${!1}" = "$SMBFILE" ] && Message "\nThe selected file cannot be the samba config file!\n" 'error' && Select_File "$1" "$2"
	}

	# Subfunction: Menu >> Question
	Question () {
		zenity --question --title="Closed In Directory" --ok-label="${2:-Yes}" --cancel-label="${3:-No}" --ellipsize --text="$1" 2>/dev/null
		return "$?"
	}

	# Subfunction: Menu >> Set_Behavior
	Set_Behavior () {

		# Subfunction: Menu >> Set_Behavior >> Form
		Form () {
			local tempfile ; tempfile="$(Tempfile 'form')"

			if ! zenity --forms \
			--title="Backend Information" --width="350" --height="400" --window-icon="${0%/*}/icons/cid.png" --separator="
" --ok-label="Next" --cancel-label="Back" --text="\n Information from the \"idmap_ad\" (RFC2307): \n" \
			--add-entry="

Initial ID:
(Eg: 10000)
" \
			--add-entry="

Final ID:
(Eg: 1999999)

" \
			--add-combo="winbind nss info: 
(Default: template)" --combo-values="|template|rfc2307" >"$tempfile" 2>/dev/null
			then
				Set_Behavior "$1"
			fi

			MIN_ID="$(sed -n '1p' "$tempfile")"
			MAX_ID="$(sed -n '2p' "$tempfile")"
			NSSINFO="$(sed -n '3p' "$tempfile")"

			rm -f "$tempfile"

			if [ -z "$MIN_ID" ]; then
				Message "\nThe \"Initial ID\" field is required!\n" 'error'
				Form "$1"
			elif Check_NoNum "$MIN_ID" || Check_NoNum "$MAX_ID"; then
				Message "\nThe \"Initial ID\" and \"Final ID\" fields should only contain integers!\n" 'error'
				Form "$1"
			elif [ "$MIN_ID" -le "$MAX_LOCAL_ID" ]; then
				Message "\nIDs lower than \"$((MAX_LOCAL_ID+1))\" are already used by local users!\n" 'error'
				Form "$1"
			elif [ -z "$MAX_ID" ]; then
				zenity --question --title="Closed In Directory" --ok-label="Continue" --cancel-label="Back" --ellipsize \
				--text="\n\t\tFinal ID is not set!\n\nIf it continues, the value \"$((MIN_ID+(ID_RANGE_SIZE-1)))\" will be assigned."

				case "$?" in
					0) MAX_ID="$((MIN_ID+(ID_RANGE_SIZE-1)))" ;;
					1) Form "$1" ;;
				esac
			elif [ "$MAX_ID" -le "$MIN_ID" ]; then
				Message "\nThe \"Final ID\" field should contain a value greater than the \"Initial ID\" field!\n" 'error'
				Form "$1"
			fi

			[ "$NSSINFO" != 'rfc2307' ] && NSSINFO='template'
			export MIN_ID MAX_ID NSSINFO
			export BACKEND='ad'
		}


		# Exec: Set_Behavior
		if ! OPTIONS="$(zenity --list \
		--title="Change station behavior" --width="580" --height="680" --window-icon="${0%/*}/icons/cid.png" \
		--separator=- --ok-label="Next" --cancel-label="Back" --checklist --hide-header --hide-column=2 \
		--text="\n Select the following options:\n" \
		--column="" --column="" --column="" \
	"$(Get_Flag 1 'FALSE' 'TRUE')" 1 "
Disable NetBIOS over TCP/IP
 (Disables NetBIOS support - Affects \"Browsing\" and \"WINS\")
" \
	"$(Get_Flag 2 'FALSE' 'TRUE')" 2 "
Disable authentication via Kerberos
 (Do not get kerberos tickets during logon)
" \
	"$(Get_Flag 3 'FALSE' 'TRUE')" 3 "
Disable credential caching
 (It requires communication with authentication server during logon)
" \
	"$(Get_Flag 4 'FALSE' 'TRUE')" 4 "
Disable logon scripts
 (Disables the execution of logon scripts)
" \
	"$(Get_Flag 5 'FALSE' 'TRUE')" 5 "
Do not use domain as default
 (Requires the user to specify the domain at logon: DOMAIN\user)
" \
	"$(Get_Flag 6 'FALSE' 'TRUE')" 6 "
Enable authentication for sudo
 (Requires password confirmation when running sudo command)
" \
	"$(Get_Flag 7 'FALSE' 'TRUE')" 7 "
Use idmap_ad (RFC 2307)
 (Obtains user and group IDs from Domain Controller)
" \
	"$(Get_Flag 8 'FALSE' 'TRUE')" 8 "
Share all printers on CUPS
 (Shares all printers on local CUPS server via Samba (SMB protocol))
" \
	"$(Get_Flag 9 'FALSE' 'TRUE')" 9 "
Use keytab file method
 (Uses a keytab file for checking Kerberos tickets in Samba)
" \
	"$(Get_Flag 10 'FALSE' 'TRUE')" 10 "
Add config file to Samba
 (Appends additional config file to Samba Global Section)
" 2>/dev/null)"
		then
			"$1"
		fi

		OPTIONS="${OPTIONS:=default}"

		[ "$OPTIONS" = "$MODO" ] && Message "\nNo changes selected!\n" 'warning' && Set_Behavior "$1"
		[ "$(Check_Change 7)" = "1" ] && Form "$1"

		if [ "$(Check_Change 10)" = "1" ]; then
			Select_File 'ADDSMBFILE'
			[ "$ADDSMBFILE" ] || Set_Behavior "$1"
		fi

		if [ "$1" = "Menu" ]; then
			Progress 'Change_Behavior' 'cid-gtk >> Change_Behavior' 'Change station behavior' 'Making changes...'

			if Question "\nChanges completed!\n" 'Back' 'Menu'; then
				Set_Behavior 'Menu'
			else
				Menu
			fi
		fi
	}

	# Subfunction: Menu >> Failed
	Failed () {
		local str="
		$1

Check the application's log in the \"Help >> App log\" menu,
or see the \"${LOGDIR}/functions.log\" file.

The following actions may also help to solve the problem:

-> Check the data reported and the network settings!

-> Check for communication with DC!

-> Make sure the computer time is synchronized with DC!

-> Run the following commands on the terminal:

		nslookup $2
		ping -c 4 $2

If successful, restart the system and try the procedure again.
Otherwise, confirm that the network DNS is configured correctly
in the network parameters.
"
		Message "$str" 'error'
	}

	# Subfunction: Menu >> Reboot
	Reboot () {
		Question "\n\t\t\tSuccessful procedures!\n\nIn order for the procedures performed to take effect,\nit is recommended that the system be restarted.\n\n\tDo you want to restart the system now?"

		case "$?" in
			0) systemctl reboot -i ; shutdown -rq now ; reboot ; shutdown -r now ;;
			1) rm -rf "${TEMPDIR}" ; Menu ;;
		esac
	}

	# Subfunction: Menu >> Menu_In
	Menu_In () {

		# Subfunction: Menu >> Menu_In >> Join_Gtk
		Join_Gtk () {

			# Subfunction: Menu >> Menu_In >> Join_Gtk >> Form
			Form () {
				unset HOST
				local tempfile ; tempfile="$(Tempfile 'form')"

				if ! zenity --forms \
				--title="Join the domain" --width="400" --height="550" --window-icon="${0%/*}/icons/cid.png" --separator="
" --ok-label="Join" --text="\n Domain Info: \n" \
				--add-entry="

Domain:
(Eg: example.com)
" \
				--add-entry="

Hostname (optional):
(Current: $HOSTNAME)
" \
				--add-entry="

Organizational Unit (optional):
(Eg: Computers/Linux)
" \
				--add-entry="

User:
(Eg: Administrator)
" \
				--add-password="

Password:

" \
				--add-combo="Mode: 
(Default: Default)" --combo-values="|Default|Advanced" >"$tempfile" 2>/dev/null
				then
					rm -f "$tempfile"
					Menu_In
				fi

				local str

				FQDN="$(sed -n '1p' "$tempfile")"
				HOST="$(sed -n '2p' "$tempfile")"
				OU="$(sed -n '3p' "$tempfile")"
				DOMAINUSER="$(sed -n '4p' "$tempfile")"
				PASS="$(sed -n '5p' "$tempfile")"
				str="$(sed -n '6p' "$tempfile")"

				rm -f "$tempfile"

				if [ -z "$FQDN" ] || [ -z "$DOMAINUSER" ] || [ -z "$PASS" ]; then
					Message "\nThe \"Domain\", \"User\" and \"Password\" fields are required!\n" 'error'
					Form
				fi

				if [ "$(echo "$HOST" | sed -r 's/[[:blank:]]*//g')" ] && ! command -v hostnamectl >/dev/null 2>&1; then
					if Question "\n\t\t\"hostnamectl\" command not found!\n\nIf proceeding, CID will attempt to create the computer\naccount in AD with the current hostname ($HOSTNAME).\n\n\t\t\tDo you want to proceed?"; then
						unset HOST
					else
						Form
					fi
				fi

				Check_Hostname "${HOST:-${HOSTNAME}}"

				case "$?" in
					1)
						Message "\nThe hostname cannot be longer than 15 characters for compatibility with the NetBIOS API!\n" 'error' ; Form
					;;
					2)
						Message "\nThe hostname cannot start with a hyphen (-)!\n" 'error' ; Form
					;;
					3)
						Message "\nHostname contains invalid character!\n" 'error' ; Form
					;;
				esac

				if [ "$str" = "Advanced" ]; then
					MODO='default'
					Set_Behavior 'Join_Gtk'
				else
					OPTIONS='default'
				fi

				FQDN="${FQDN,,}"
				DOMAIN="${workgroup:=${FQDN%%.*}}" && DOMAIN="${DOMAIN^^}"
				DOMAINUSER="${DOMAINUSER,,}"

				if [ -z "$OU" ]; then
					OU='computers'
					export TEST_OU=0
				else
					OU="${OU,,}"
					export TEST_OU=1
				fi
			}

			# Subfunction: Menu >> Menu_In >> Join_Gtk >> Success
			Success () {
				local function='cid-gtk >> Menu_In >> Join_Gtk >> Success'
				Message "\nWelcome to the \"$DOMAIN\" domain!\n" 'info'
				Progress 'Success_Join' "$function" 'Join the domain' 'Completing settings...'
				unset HOST OPTIONS FQDN DOMAIN OU TEST_OU DOMAINUSER PASS BACKEND MIN_ID MAX_ID NSSINFO
				Reboot
			}


			# Exec: Join_Gtk
			local function='cid-gtk >> Menu_In >> Join_Gtk'

			Form
			Progress 'Join' "$function" 'Join the domain' 'Joining to domain...'

			case "$?" in
				0|4) Success ;;
				1) Message "\nCould not find \"$OU\" OU!\nThe computer account was created in \"Computers\" OU!\n" 'warning' ; OU='computers' ; Success ;;
				2) Message "\nCould not find \"$OU\" OU!\nThe computer account was created in the default container!\n" 'warning' ; OU='unknown' ; Success ;;
				3) OU='unknown' ; Success ;;
				255) Failed "Failed to join in \"$DOMAIN\"!" "$FQDN" ; Restore ; Join_Gtk ;;
				*) Error "$function" "$?" ;;
			esac
		}


		# Exec: Menu_In
		local int ; int="$(zenity --list \
		 --title="Closed In Directory" --width="400" --height="550" --window-icon="${0%/*}/icons/cid.png" --radiolist --hide-header --hide-column=2 \
		 --cancel-label="Quit" --text="\n Hostname: $HOSTNAME\n" \
		 --column="" --column="" --column="" \
	TRUE 1 "

Join the domain..

" \
	FALSE 2 "

Help..

" 2>/dev/null)"
		case "$int" in
			1) Join_Gtk ;;
			2) Help ;;
			*) exit 0 ;;
		esac
	}

	# Subfunction: Menu >> Menu_Out
	Menu_Out () {

		# Subfunction: Menu >> Menu_Out >> Leave_Gtk
		Leave_Gtk () {

			# Subfunction: Menu >> Menu_Out >> Leave_Gtk >> Form
			Form () {
				unset DOMAINUSER PASS

				if ! str="$(zenity --forms \
				--title="Remove from domain" --width="350" --height="450" --window-icon="${0%/*}/icons/cid.png" \
				--ok-label="Remove" --text=" Optionally, fill in the fields below with the credentials of a 
domain admin to send a command to the DC, and remotely 
exclude the computer account from AD database. \n" \
				--add-entry="

User:
(Eg: Administrator)

" \
				--add-password="

Password:


" 2>/dev/null)"
				then
					Menu
				fi

				DOMAINUSER="${str%%|*}" && PASS="${str#*|}"

				if [ -z "$DOMAINUSER" ] && [ -n "$PASS" ]; then
					Message "\nThe Password argument requires User argument!\n" 'error'
					Form
				else
					export PASS="${PASS:=$DOMAINUSER}" DOMAINUSER
				fi
			}


			# Exec: Leave_Gtk
			local function='cid-gtk >> Menu_Out >> Leave_Gtk'

			Form

			if Progress 'Leave' "$function" 'Remove from domain' 'Removing from domain...'; then
				Message "\nAccount successfully removed!\n" 'info'
			else
				Message "\nCould not delete computer account from domain!\nEven then the station was reconfigured!\n" 'warning'
			fi

			Reboot
		}

		# Subfunction: Menu >> Menu_Out >> Form_RadioList_OfTwo
		Form_RadioList_OfTwo () {
			# shellcheck disable=SC2046
			return $(zenity --list \
				--title="$1" --ok-label="Select" --cancel-label="Back" --width="400" --height="550" \
				--window-icon="${0%/*}/icons/cid.png" --radiolist --hide-header --hide-column=2 \
				--text="$2" --column="" --column="" --column="" \
	TRUE 0 "

${3}..

" \
	FALSE 2 "

${4}..

" 2>/dev/null)
		}

		# Subfunction: Menu >> Menu_Out >> Get_Obj
		Get_Obj () {
			local function='cid-gtk >> Menu_Out >> Get_Obj'

			# shellcheck disable=SC2086
			unset ${!OBJ*} BOOL

			if ! OBJ="$(zenity --forms \
			--title="$1" --width="400" --height="550" --window-icon="${0%/*}/icons/cid.png" --ok-label="${1%% *}" --cancel-label="Back" --text="\n Enter the AD account type and name that\n  ${2}:\n" \
			--add-combo="Account Type: 
(Default: User)" --combo-values="|User|Group" \
			--add-entry="
	
Account Name:

" 2>/dev/null)"
			then
				"$3"
			else
				OBJ_TYPE="${OBJ%%|*}" ; OBJ="${OBJ#*|}"
				OBJ_TYPE="${OBJ_TYPE,,}" ; OBJ="${OBJ,,}"

				if [ "${1%% *}" != "Block" ] && [ "${OBJ:(-1)}" = "*" ]; then
					BOOL=true
				fi

				if [ "$OBJ_TYPE" = 'group' ]; then
					[ "$BOOL" ] && OBJ=${OBJ%\*}
					export FILE="$GRPFILE"
				else
					[ "$BOOL" ] && Message "\nThe wildcard character \"*\" should only be used with a group account!\n" 'error' && Get_Obj "$1" "$2" "$3"
					OBJ_TYPE='user'
					export FILE="$PWDFILE"
				fi
			fi

			Run 'Check_Obj' "$function"

			case $? in
				0) ;;
				1) Message "\nIt is necessary to inform a account!\n" 'error' ; Get_Obj "$1" "$2" "$3" ;;
				2) Message "\nInvalid character!\n" 'error' ; Get_Obj "$1" "$2" "$3" ;;
				3) Message "\n\"$OBJ\" is a local system ${OBJ_TYPE}!\n" 'error' ; Get_Obj "$1" "$2" "$3" ;;
				4) Message "\n\tCan not find the \"$(Backslash "$OBJ")\" ${OBJ_TYPE}!\n\nMake sure the $OBJ_TYPE name is correct and try again!\n" 'error' ; Get_Obj "$1" "$2" "$3" ;;
				*) Error "$function" $? ;;
			esac
		}

		# Subfunction: Menu >> Menu_Out >> Block_Unlock
		Block_Unlock () {
			local function='cid-gtk >> Menu_Out >> Block_Unlock'

			if [ "${STR%% *}" = "Block" ]; then
				Get_Obj "$STR" 'will have exclusive access to this computer' 'Menu'
				unset SID ; Run 'Block' "$function"

				case "$?" in
					0) Message "\nRestricted logon!\n" 'info' ; Menu ;;
					*) Error "$function" "$?" ;;
				esac
			else
				Run 'Unlock' "$function"

				case $? in
					0) Message "\nUnrestricted logon!\n" 'info' ; Menu ;;
					255) Message "\nLock parameter not found!\n" 'error' ; Menu ;;
					*) Error "$function" "$?" ;;
				esac
			fi
		}

		# Subfunction: Menu >> Menu_Out >> Manager
		Manager () {
			FUNCTION="${1,}"

			Form_RadioList_OfTwo "$2" "$3" "Add$(if [ "${FUNCTION%%manager*}" = 'share' ]; then echo '/Update share'; else echo ' account'; fi)" "Remove ${FUNCTION%%manager*}"

			case "$?" in
				0) "${1%%manager*}add" ;;
				2) if [ -s "${DBDIR}/${FUNCTION%%manager*}List.db" ]; then
						"${1%%manager*}del"
					else
						Message "\nThere is currently no ${FUNCTION%%manager*} to remove!\n" 'warning'
						"$1"
					fi ;;
				*) Menu ;;
			esac
		}

		# Subfunction: Menu >> Menu_Out >> Form_CheckList
		Form_CheckList () {
			unset LST
			local tempfile ; tempfile="$(Tempfile 'list')_form"

			# shellcheck disable=SC2016,SC2086
			echo '#!/usr/bin/env bash

. '${SCRIPTDIR}'/functions.bash

List_Form () {
	unset int

	int=$(zenity --list --checklist --window-icon=&${ICONDIR}/cid.png& --cancel-label=&Back& @
		--width=&'${3:-400}'& --height=&550& --ok-label=&Remove& --title=&'${2}'& --text=&@n Select the ${FUNCTION}(s) for removal:@n& @
		--hide-column=2 --column=& & --column=&& '$PAR > "${tempfile}.sh"

			cat "$1" >> "${tempfile}.sh"

			# shellcheck disable=SC2016,SC2086
			echo '2>/dev/null)

	if [ $? -ne 0 ]; then
		exit 1
	else
		if [ -z &$int& ]; then
			Message &@nYou must select at least one '${FUNCTION%%manager*}'!@n& &error&
			List_Form
		else
			echo &$int&
			exit 0
		fi
	fi
}

List_Form' >> "${tempfile}.sh"

			sed -i 's/@/\\/g;s/&/"/g' "${tempfile}.sh"
			[ -x "${tempfile}.sh" ] || chmod +x "${tempfile}.sh"
			LST="$("${tempfile}.sh")"
			[ "$?" -eq 1 ] && "${FUNCTION^}"
		}

		# Subfunction: Menu >> Menu_Out >> Accountmanager >> Exec_RmList
		Exec_RmList () {
			[ "$INT" ] || return 255

			Progress 'Delobj' "$2" "$3" "Removing ${1}s..." "$1"

			status=${4:-$?}
		}

		# Subfunction: Menu >> Menu_Out >> CheckFailList
		CheckFailList () {
			[ -n "$1" ] && local IFS=\| && Message "\nThere was an error ${2}(s):\n\n$(for ent in $1; do Backslash "$ent"; done)\n" 'warning'
		}

		# Subfunction: Menu >> Menu_Out >> Accountmanager
		Accountmanager () {

			# Subfunction: Menu >> Menu_Out >> Accountmanager >> Accountadd
			Accountadd () {

				# Subfunction: Menu >> Menu_Out >> Accountmanager >> Accountadd >> Add_AllGroupMembers
				Add_AllGroupMembers () {
					local obj="$OBJ" && OBJ_TYPE='user' && local IFS=\| ; unset list

					for OBJ in $(Get_AllGroupMembers "$obj" '|'); do
						Fix_Obj

						Progress "Addaccount" "$function" "$str" "Adding \"$(Backslash "$OBJ")\" user..."

						case $? in
							0|1|2	) ;;
							*		) local list="${list:+${list}\|}${OBJ/\\/@}" ;;
						esac
					done

					CheckFailList "$list" 'adding the user'

					OBJ="$obj" && OBJ_TYPE='group'
				}

				# Subfunction: Menu >> Menu_Out >> Accountmanager >> Accountadd >> Check_AddAllMembers
				Check_AddAllMembers () {
					if [ -n "$BOOL" ]; then
						Add_AllGroupMembers
						[ "$1" -eq 0 ] || Success_AddAccount "$1"
					fi

					if Question "\n${4}\n\n\n${5:-Do you want to add all the members that currently belong to this group to the local groups of this computer?}\n"; then
						"$2"
					else
						"$3"
					fi

					Success_AddAccount "$1"
				}

				# Subfunction: Menu >> Menu_Out >> Accountmanager >> Accountadd >> Success_AddAccount
				Success_AddAccount () {
					[ "$1" -eq 0 ] || unset BOOL
					Check_AddAllMembers 0 'Accountadd' 'Accountmanager' "\"$(Backslash "$OBJ")\" $OBJ_TYPE added!" "Do you want to add another account?"
				}


				# Exec: Accountadd
				local function str
				function='cid-gtk >> Menu_Out >> Accountmanager >> Accountadd'
				str='Add AD account to local groups'

				Get_Obj "$str" 'you want to add to local groups' 'Accountmanager'
				Progress "Addaccount" "$function" "$str" "Adding \"$(Backslash "$OBJ")\" ${OBJ_TYPE}..."

				case "$?" in
					0) Success_AddAccount 0 ;;
					1)
						local str[1]
						str[1]="The \"$(Backslash "$OBJ")\" $OBJ_TYPE has already been added to the local groups!"
						[ "$OBJ_TYPE" = "user" ] && Message "\n${str[1]}\n" 'error' && Accountadd
					;;
					2)
						local str[1]
						str[1]="The \"$(Backslash "$OBJ")\" $OBJ_TYPE was added to the local groups with the name \"$(Backslash "$STR")\"!\nCID will update the name of this $OBJ_TYPE in its records."
						[ "$OBJ_TYPE" = "user" ] && Message "\n${str[1]}\n" 'warning' && Accountadd
					;;
					3)
						local str[1]
						str[1]="Members of the \"$(Backslash "$OBJ")\" group are already automatically added to local groups when they log on to this computer!"
					;;
					*) Error "$function" "$?" ;;
				esac

				Check_AddAllMembers 1 'Add_AllGroupMembers' 'Accountadd' "${str[1]}"
			}

			# Subfunction: Menu >> Menu_Out >> Accountmanager >> Accountdel
			# shellcheck disable=SC2120
			Accountdel () {

				# Subfunction: Menu >> Menu_Out >> Accountmanager >> Accountdel >> Create_RmList
				Create_RmList () {
					for int in $1; do
						if [ "${ACCOUNTTYPE[${int}]}" = "group" ]; then
							if Question "\nDo you want to remove all members of the \"$(Backslash "${ACCOUNTNAME[${int}]}")\" group\nthat are in the local groups of this computer?"; then
								sid=${sid:+${sid}|}${ACCOUNTSID[${int}]}
							fi
						else
							if Check_AdminUser "${ACCOUNTSID[${int}]}"; then
								if ! Question "\nThe \"$(Backslash "${ACCOUNTNAME[${int}]}")\" user is a domain administrator!\n\nAre you sure you want to remove it from local groups?"; then
									continue
								fi
							fi
						fi

						INT=${INT:+${INT}|}$int
					done
				}


				# Exec: Accountdel
				local function str tempfile

				function='cid-gtk >> Menu_Out >> Accountmanager >> Accountdel'
				str='Remove accounts from local groups'
				PAR='--column=& Account Name& --column=& Account Type& --column=& Mode& @'
				tempfile="$(Tempfile 'body')"

				rm -f "$tempfile"

				# shellcheck disable=SC2086
				unset ${!ACCOUNT*}

				# shellcheck source=/dev/null
				. "${DBDIR}/accountList.db"

				for ((int=0; int < ${#ACCOUNTSID[*]}; int++)); do
					echo -e "FALSE $int &\n${ACCOUNTNAME[${int}]}\n& &\t${ACCOUNTTYPE[${int}]^}& & ${ACCOUNTMODE[${int}]^}& @" >>"$tempfile"
				done

				Form_CheckList "$tempfile" "$str"
				unset sid INT ; local IFS=\| ; Create_RmList "$LST"
				unset status LIST ; Exec_RmList 'account' "$function" "$str"

				if [ -n "$sid" ] && [ -s "${DBDIR}/accountList.db" ]; then
					# shellcheck source=/dev/null
					. "${DBDIR}/accountList.db"

					unset INT

					for ((int=0; int < ${#ACCOUNTSID[*]}; int++)); do
						[ "${ACCOUNTTYPE[${int}]}" = "group" ] && continue

						if Check_AdminUser "${ACCOUNTSID[${int}]}" "$sid"; then
							Create_RmList "$int"
						fi
					done

					Exec_RmList 'account' "$function" "$str" 0
				fi

				if [ "$status" ]; then
					if [ "$status" -eq 0 ]; then
						if [ "$LIST" ]; then
							CheckFailList "$LIST" 'removing the account'
						else
							Message "\nAccount(s) successfully removed!\n" 'info'
						fi
					else
						Error "$function" 1
					fi
				else
					Message "\nThere are no accounts to remove!\n" 'warning'
				fi

				if [ -s "${DBDIR}/accountList.db" ]; then
					# shellcheck disable=SC2119
					Accountdel
				else
					Accountmanager
				fi
			}


			# Exec: Accountmanager
			Manager 'Accountmanager' "Managing AD Accounts in Local Groups" "\nAdd AD accounts to local groups so they\nhave administrative privileges on this computer.\n"
		}

		# Subfunction: Menu >> Menu_Out >> Sharemanager
		Sharemanager () {

			# Subfunction: Menu >> Menu_Out >> Sharemanager >> Shareadd
			# shellcheck disable=SC2120
			Shareadd () {
				local function tempfile

				function='cid-gtk >> Menu_Out >> Sharemanager >> Shareadd'
				tempfile="$(Tempfile 'form')"

				# shellcheck disable=SC2001,SC2046,SC2086
				unset ${!share*} $(echo ${!SHARE*} | sed 's/SHAREDIR//')

				# shellcheck source=/dev/null
				[ -s "${DBDIR}/shareList.db" ] && . "${DBDIR}/shareList.db"

				# shellcheck disable=SC2153
				if ! zenity --forms \
				--title="Add/Update share..." --window-icon="${0%/*}/icons/cid.png" --separator="
"               --ok-label="Add/Update" --cancel-label="Back" --text="\n Share Info: \n" \
				--add-combo="Mode:
(Default: Common)
" --combo-values="|Common|Userfolder|Printer" \
				--add-entry="Name:
(Share Name)
" \
				--add-combo="Template:
(Select Model/Update Share)
" --combo-values="$(for ((int=0; int < ${#SHARENAME[*]}; int++)); do echo -n \|"${SHARENAME[${int}]}"; done)" \
				--add-entry="Path:
(Folder/CUPS Printer Name)
" \
		                --add-entry="Rule:
(Default: u:everyone:r)
" \
				--add-entry="Comment:
(Optional)
" \
				--add-entry="Disk Quota Size:
(Default: Unlimited)
" \
				--add-entry="Tolerance Quota Size:
(Default: None)
" \
				--add-combo="Apply Quota to Fst-level of Subdirs:
(Default: No)
" --combo-values="|No|Yes" \
				--add-combo="Hidden:
(Default: No)
" --combo-values="|No|Yes" \
				--add-combo="Allow Guest:
(Default: No)
" --combo-values="|No|Yes" \
				--add-combo="Add Config File:
(Default: No)
" --combo-values="|No|Yes" >"$tempfile" 2>/dev/null
				then
					rm -f "$tempfile"
					Sharemanager
				fi

				sharemode="$(sed -n '1p' "$tempfile")" && export sharemode="${sharemode,,}"
				sharename="$(sed -n '2p' "$tempfile")" && export sharename
				sharetemplate="$(sed -n '3p' "$tempfile")" && export sharetemplate
				sharepath="$(sed -n '4p' "$tempfile")" && export sharepath
				sharerule="$(sed -n '5p' "$tempfile")" && export sharerule
				sharecomment="$(sed -n '6p' "$tempfile")" && export sharecomment
				sharequota="$(sed -n '7p' "$tempfile")" && export sharequota
				sharetolerance="$(sed -n '8p' "$tempfile")" && export sharetolerance
				sharequotasubd="$(sed -n '9p' "$tempfile")" && export sharequotasubd
				sharehidden="$(sed -n '10p' "$tempfile")" && export sharehidden
				shareguest="$(sed -n '11p' "$tempfile")" && export shareguest
				sharecfgfile="$(sed -n '12p' "$tempfile")" && export sharecfgfile

				rm -f "$tempfile"

				local ARG status
				
				ARG='sharemode sharename sharetemplate sharepath sharerule sharecomment sharequota sharetolerance sharequotasubd sharehidden shareguest sharecfgfile'

				for arg in $ARG; do
					[ "$(echo "${!arg}" | sed -r 's/[[:blank:]]*//g')" ] || unset "$arg"
				done

				Run 'Check_ShareArgs' "$function" ; status="$?"

				# shellcheck disable=SC2154
				case "$status" in
					1	) Message "\nEnter a share name or select one to update!\n" 'error' ;;
					2	) Message "\nYou cannot use a template with the same name as the share!\n" 'error' ;;
					3	) Message "\nYou cannot change the mode of a share!\n" 'error' ;;
					4	) Message "\nYou cannot change a share's directory!\n" 'error' ;;
					5	) Message "\nThe \"Userfolder\" mode does not accept templates!\n" 'error' ;;
					6	) Message "\nThere are no changes applicable to this share!\n" 'error' ;;
					7	) Message "\n\"$sharename\" is a reserved word and cannot be used!\n" 'error' ;;
					8	) Message "\nThe share name contains an invalid character!\n" 'error' ;;
					9	) Message "\nTemplate and Share must have the same mode!\n" 'error' ;;
					10	) Message "\nThe \"homes\" share cannot be copied!\n" 'error' ;;
					11	) Message "\nThe \"Printer\" mode requires the \"Name\" or \"Path\" argument!\n" 'error' ;;
					12	) Message "\nThe \"Common\" mode requires the \"Name\" and \"Path\" argument!\n" 'error' ;;
					13	) Message "\nDirectory paths must be started with a slash \"(/)\"!\n" 'error' ;;
					14	) Message "\nThe \"$sharepath\" printer was not found on the CUPS server!\n" 'error' ;;
					15	) Message "\nThe \"$sharepath\" path is already being used by the \"${SHARENAME[${INT}]}\" share!\n" 'error' ;;
					16	) Message "\nSome defined fields are not compatible with \"$sharemode\" mode and will be ignored!\n" 'warning' ; status=0 ;;
					17	) Message "\nThe \"bc\" software is required for quota usage and was not found!\n" 'error' ;;
					18	) Message "\nThe quota feature is currently only available on \"XFS\" file systems!\n" 'error' ;;
					19	) Message "\nThe \"$sharequotadev\" device must be mounted with the \"prjquota\" option!\n" 'error' ;;
					20	) Message "\nInvalid quota value!\n" 'error' ;;
					21	) Message "\nInvalid quota unit!\n" 'error' ;;
					22	) Message "\nThe \"tolerance quota\" must be less than the \"disk quota\"!\n" 'error' ;;
					23	) Message "\nThe disk quota cannot be greater than the total disk space on the partition of the shared directory!\n" 'error' ;;
					24	) Message "\nTolerance quota requires setting a disk quota value!\n" 'error' ;;
					25	) Message "\nSubdirectory quotas requires setting a disk quota value!\n" 'error' ;;
					26	) Message "\nRule contains an invalid format!\n" 'error' ;;
					27	) Message "\nThere is a conflict of rules for the same account!\n" 'error' ;;
					28	) Message "\nThe rule contains an invalid account!\n" 'error' ;;
				esac

				# shellcheck disable=SC2119
				[ "$status" -eq 0 ] || Shareadd

				if [ "$sharecfgfile" = 'Yes' ]; then
					# shellcheck disable=SC2153
					Select_File 'sharecfgfile' "${SHARECFGFILE[${INT}]}"

					if [ -z "$sharecfgfile" ]; then
						if Question "\nNo files were selected! \n\n\nDo you want to continue anyway?\n"; then
							unset sharecfgfile
						else
							# shellcheck disable=SC2119
							Shareadd
						fi
					fi
				fi

				local wrd

				if [ "$INT" ]; then
					wrd='Updat'
				else
					wrd='Add'
				fi

				Progress 'Addshare' "$function" "${wrd}ing share..." "${wrd}ing \"${sharename}\" share..." ; local status=$?

				if  [ "$status" -eq 0 ]; then
					if Question "\nThe \"${sharename}\" share has been ${wrd,}ed!\n\n\nDo you want to add/update another share?\n"; then
						# shellcheck disable=SC2119
						Shareadd
					else
						Sharemanager
					fi
				else
					Error "$function" "$status"
				fi
			}

			# Subfunction: Menu >> Menu_Out >> Sharemanager >> Sharedel
			Sharedel () {
				local function tempfile

				function='cid-gtk >> Menu_Out >> Sharemanager >> Sharedel'
				PAR='--column=& Mode& --column=& Name& --column=& Template& --column=& Path& --column=& Comment& --column=& Disk Quota& --column=& Tolerance Quota& --column=& Subdirs Quotas& --column=& Hidden& --column=& Guest& --column=& Add Config File& --column=& Rules& @'
				tempfile="$(Tempfile 'body')"

				rm -f "$tempfile"

				# shellcheck source=/dev/null
				. "${DBDIR}/shareList.db"

				for ((int=0; int < ${#SHARENAME[*]}; int++)); do
					local str ; str="$(Get_ShareRule $int)"

					# shellcheck disable=SC2027,SC2086,SC2153
					echo "FALSE $int &${SHAREMODE[${int}]^}& &${SHARENAME[${int}]}& &${SHARETEMPLATE[${int}]:-None}& &${SHAREPATH[${int}]}& &${SHARECOMMENT[${int}]}& &$(ReadQuota "${SHAREQUOTA[${int}]:-None}")& &$(ReadQuota "${SHARETOLERANCE[${int}]:-None}")& &${SHAREQUOTASUBD[${int}]}& &${SHAREHIDDEN[${int}]}& &${SHAREGUEST[${int}]}& &${SHARECFGFILE[${int}]:-None}& &"${str}"& @" >>"$tempfile"
				done

				Form_CheckList "$tempfile" 'Remove shares' '1360'

				INT="$LST" ; unset LIST ; Exec_RmList 'share' "$function" 'Removing shares...'
				CheckFailList "$LIST" 'removing the share'

				if [ "$status" -eq 0 ]; then
					Message "\nShare(s) successfully removed!\n" 'info'
				else
					Error "$function" $status
				fi

				if [ -s "${DBDIR}/shareList.db" ]; then
					Sharedel
				else
					Sharemanager
				fi
			}


			# Exec: Sharemanager
			Manager 'Sharemanager' "Manage shares" "\nManage Samba shares section.\n"
		}


		# Exec: Menu_Out
		local str int

		if [ -n "$LOCKED_BY_SID" ]; then
			str="Locked to \"$(Backslash "$LOCKED_BY_NAME")\" $LOCK_TYPE"
			STR='Unblock logon'
		else
			str='Unlocked'
			STR='Block logon..'
		fi

		int="$(zenity --list --radiolist \
		 --title="Closed In Directory" --ok-label="Select" --cancel-label="Quit" --width="400" --height="550" --window-icon="${0%/*}/icons/cid.png" \
		 --hide-header --hide-column=2 --text="\n FQDN: ${HOSTNAME,,}.${FQDN}\n Status: ${str}\n" \
		 --column="" --column="" --column="" \
	TRUE 1 "
Remove from domain..
" \
	FALSE 2 "
Change station behavior..
" \
	FALSE 3 "
$STR
" \
	FALSE 4 "
Manage AD accounts in local groups..
" \
	FALSE 5 "
Manage shares..
" \
	FALSE 6 "
Help..
" 2>/dev/null)"
		case "$int" in
			1) Leave_Gtk ;;
			2) Set_Behavior 'Menu' ;;
			3) Block_Unlock ;;
			4) Accountmanager ;;
			5) Sharemanager ;;
			6) Help ;;
			*) exit 0 ;;
		esac
	}


# Exec: Menu
	if [ -f "${0%/*}/scripts/functions.bash" ]; then
		# shellcheck source=/dev/null
		. "${0%/*}/scripts/functions.bash"

		if [ -s "${DBDIR}/station.db" ]; then
			Menu_Out
		else
			Menu_In
		fi
	else
		zenity --error --title="Closed In Directory" --ellipsize --text="\nFile ${0%/*}/scripts/functions.bash not found!\n" 2>/dev/null
		exit 1
	fi
}

# Start:
Menu
