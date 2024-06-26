#!/usr/bin/env bash
# Description: Pre-Logon Script (Run with root id)
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


[ "$PAM_TYPE" = "open_session" ] || exit 0

# shellcheck source=/dev/null
. "${0%/*}/vars.bash"

if ! Logon_Variables "$PAM_USER"; then
	exit 0
fi

"${0%/*}/mkhomedir.bash" "$USERPROFILE" "${USERNAME#*\\}" "${USERGROUP#*\\}" "$USERDOMAIN" >"$TEMPFILE" 2>&1
"${0%/*}/logger.bash" "$TEMPFILE" "${0%/*}/mkhomedir.bash" "$?"

dcaddr=$(wbinfo -P 2>"$TEMPFILE") ; status="$?"
"${0%/*}/logger.bash" "$TEMPFILE" "$0" "$status"

if [ "$status" -eq 0 ]; then
	"${0%/*}/manager_systemGroups.bash" "$USERNAME" >"$TEMPFILE" 2>&1
	"${0%/*}/logger.bash" "$TEMPFILE" "${0%/*}/manager_systemGroups.bash" "$?"

	# Fix Samba Bug 14618
	if [ "$(command -v apt)" ]; then
		dir[0]="$(smbd -b | grep -w 'LOCKDIR' | sed -r 's/.*: *//')"
		dir[1]="$(testparm -sv 2>/dev/null | grep -w 'lock directory' | sed -r 's/.*= *//')"

		if [ "${dir[0]}" != "${dir[1]}" ]; then	dir[0]="${dir[0]:+${dir[0]} }${dir[1]}" ; fi

		# shellcheck disable=SC2086
		find ${dir[0]} -type f -name "$WBCACHEFILE" -exec cp -pf {} "${DBDIR}" \; -quit 2>/dev/null
	fi
fi

if ! echo "$MODO" | grep -wq 4; then
	if [ "$status" -eq 0 ]; then
		[ "$(command -v setenforce)" ] && setenforce 0

		[ "$(command -v samba-gpupdate)" ] && samba-gpupdate -P --force >"$TEMPFILE" 2>&1
		"${0%/*}/logger.bash" "$TEMPFILE" "$0" "$?"

		if echo "$dcaddr" | grep -wq "$FQDN"; then
			dcaddr=${dcaddr%\"*} && dcaddr=${dcaddr#*\"}
		else
			unset dcaddr
		fi

		echo "<pam_mount>
	<debug enable=\"0\"/>
	<mkmountpoint enable=\"1\" remove=\"false\"/>
	<logout wait=\"0\" hup=\"0\" term=\"0\" kill=\"0\" />
	<volume fstype=\"cifs\" server=\"${dcaddr:-$FQDN}\" path=\"netlogon\" mountpoint=\"${NETLOGON}\" ${SMBVER:+options=\"vers=${SMBVER}.0\" }/>
</pam_mount>" >"$MOUNTFILE"
	else
		echo '<pam_mount>
	<debug enable="0" />
	<mkmountpoint enable="0" remove="false" />
	<logout wait="0" hup="0" term="0" kill="0" />
</pam_mount>' >"$MOUNTFILE"
	fi
fi

Logon_Variables "$PAM_USER" false

exit 0
