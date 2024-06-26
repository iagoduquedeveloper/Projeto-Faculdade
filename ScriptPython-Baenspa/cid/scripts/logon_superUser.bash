#!/usr/bin/env bash
# Description: Logon Script (Run with root id)
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

if mount | grep -wq "$NETLOGON"; then
	Logon_Variables "$PAM_USER"

	if [ ! -d "$LOGONSCRIPTDIR" ] && [ -d "$OLDLOGONSCRIPTDIR" ]; then
		LOGONSCRIPTDIR="$OLDLOGONSCRIPTDIR"
	fi

	[ -x "$LOGONSCRIPTDIR/logon_root.sh" ] && "$LOGONSCRIPTDIR/logon_root.sh" >"$TEMPFILE" 2>&1
	"${0%/*}/logger.bash" "$TEMPFILE" "$LOGONSCRIPTDIR/logon_root.sh" "$?"

	[ -f "$LOGONSCRIPTDIR/shares.xml" ] && cp -f "$LOGONSCRIPTDIR/shares.xml" "$MOUNTFILE" 2>"$TEMPFILE"
	"${0%/*}/logger.bash" "$TEMPFILE" "$0" "$?"

	Logon_Variables "$PAM_USER" false
fi

exit 0