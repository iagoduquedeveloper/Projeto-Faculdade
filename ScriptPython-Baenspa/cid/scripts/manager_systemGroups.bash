#!/usr/bin/env bash
# Description: Script to manage domain users in system groups
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


# shellcheck source=/dev/null
. "${0%/*}/functions.bash"

unset int bool

if [ "$2" ]; then
	bool="$2"
else
	[ -z "$1" ] && echo 'Argument not found!' >&2 && exit 1

	Check_AccountName "$1" || . "${DBDIR}/accountList.db"

	unset str

	[ "$INT" ] && int="$INT" && str="${ACCOUNTMODE[${INT}]}"

	if [ "$str" != 'manual' ]; then
		if Check_AdminUser; then
			bool=true
		else
			for str in $(Get_UserGroups "$SID"); do
				if ! Get_ObjID 'account' "$str"; then
					break
				fi

				[ "$INT" ] && bool=true && break
			done

			bool="${bool:=false}"
		fi
	fi
fi

if [ "$bool" ]; then
	Manage_SudoUsers "$1" "$bool"

	if [ "$bool" = "true" ]; then
		[ "$int" ] || Insert_AccountList "$1" "${4:-$SID}" "$3"
		
		for g in $(Get_SystemGroups); do
			if ! grep -aw "$g" "$GRPFILE" | sed 's/\\/@/g' | grep -wiq "${1/\\/@}"; then gpasswd -a "$1" "$g"; fi
		done
	else
		[ "$int" ] && Delete_ObjList 'account' "$int"
		
		for g in $(Get_SystemGroups); do
			if grep -aw "$g" "$GRPFILE" | sed 's/\\/@/g' | grep -wiq "${1/\\/@}"; then gpasswd -d "$1" "$g"; fi
		done
	fi
fi

exit 0