#!/usr/bin/env bash
# Description: Logon Script (Run with session user id)
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
. "${0%/*}/vars.bash"

if mount | grep -w "$NETLOGON"; then
	Logon_Variables "${USER:=$(id -un)}"

	if [ ! -d "$LOGONSCRIPTDIR" ] && [ -d "$OLDLOGONSCRIPTDIR" ]; then
		LOGONSCRIPTDIR="$OLDLOGONSCRIPTDIR"
	fi

	[ -x "$LOGONSCRIPTDIR/logon.sh" ] && "$LOGONSCRIPTDIR/logon.sh" >"$TEMPFILE" 2>&1
	sudo "${0%/*}/logger.bash" "$TEMPFILE" "$LOGONSCRIPTDIR/logon.sh" "$?"

	sudo "${0%/*}/umount_netlogon.bash"

	Logon_Variables "$USER" false
fi

exit 0