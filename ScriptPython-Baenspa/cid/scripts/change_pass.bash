#!/usr/bin/env bash
# Description: Script to change password of domain users
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


Change_Pass () {

	Command () {
		if echo "${0##*/}" | grep -oq 'gtk'; then
			if ! zenity --forms \
			--title="CID Password Changer" --width="300" --height="300" --window-icon="${ICONDIR}/cid-cp.png" --ok-label="Change" \
			--separator="
" --text="

  Changing Password (Trying $2 of 3) 


   User:  $(Backslash "$1") " \
			--add-password="

Current password:

" \
			--add-password="

New password:

" > ~/.cid-change-pass 2>/dev/null
			then
				exit 255
			fi

			# shellcheck disable=SC2002
			cat ~/.cid-change-pass | wbinfo --change-user-password="$1" ; return $?
		else
			clear

			echo "
			*** CID Password Changer ***

-> Enter the current password and then the new password (Trying $2 of 3):
(Press \"Ctrl + c\" to Cancel)
"
			wbinfo --change-user-password="$1" ; return $?
		fi
	}

	for ((int = 1; int <= 3; int++)); do
		if Command "$1" "$int"; then
			Message "\nPassword changed successfully!\n" 'info'
			[ -f ~/.cid-change-pass ] && rm -f ~/.cid-change-pass
			break
		else
			if [ $int -eq 3 ]; then
				Message "\nAttempts number exhausted!\n" 'error'
			else
				Message "\nError! Try again!\n" 'error'
			fi

			[ -f ~/.cid-change-pass ] && rm -f ~/.cid-change-pass
		fi
	done
}


if [ -L "$0" ]; then
	workdir=$(readlink -m "$0")
else
	workdir=$0
fi

# shellcheck source=/dev/null
. "${workdir%/*}/functions.bash"

case $1 in
	-v|--version) Message "\nCID version $VERSION\n" 'info' ; exit 0 ;;
	-h|--help)
		str="Use: ${0##*/}\n or: ${0##*/} user1 user2 DOMAIN\\\\user... (only root)\n or: ${0##*/} [OPTION]\n\n\
Changes the user password of the domain that executed the process.\n\
You can also change the password of one or more specific users if run as root.\n\n\
OPTIONS:\n
 -h, --help\t\tShow this help and exit\n -v, --version\t\tShow the version and exit\n"
		Message "$str" 'info'
		exit 0
	;;
esac

if [ ! -s "${DBDIR}/station.db" ]; then
	Message "\nAt the moment the station does not belong to a domain!\n" 'error'
	exit 1
else
	if ! Run 'wbinfo -P' "${0##*/}"; then
		Message "\nAt the moment there is no communication with the DC!\n" 'error'
		exit 1
	else
		if [ $# -gt 0 ]; then
			if [ "$(id -u)" -eq 0 ]; then
				for str in "$@"; do
					OBJ=$(set | grep -Ew "^str" | cut -d '=' -f 2-)
					export OBJ OBJ_TYPE='user' && export FILE="$PWDFILE"

					if Run 'Check_Obj' "${0##*/}"; then
 						Change_Pass "$OBJ"
					else
						Message "\nThe $str argument is not a valid domain user!\n" 'error'
					fi
				done
			else
				Message "\nTo pass arguments to this program run it as superuser!\n" 'error'
				exit 1
			fi
		else
			if [ "$(id -u)" -eq 0 ]; then
				Message "\nSuperuser mode requires a domain user account as argument!\n" 'error'
				exit 1
			else
				if [ "$(id -u)" -lt "$MIN_ID" ]; then
					Message "\nThis feature is only enabled for domain users!\n" 'error'
					exit 1
				else
					Change_Pass "$USER"
				fi
			fi
		fi
	fi
fi

exit 0