#!/usr/bin/env bash
# Description: User-Share Home Folder Creator
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

[ -d "$1" ] || mkdir -p "$1"

[ "$(stat -c "%a" "$1")" != "700" ] && chmod 700 "$1"

if Check_Backslash "${2/\\/@}"; then
	u="${2#*\\}"
else
	u="${2#$4}"
fi

if [ "$(stat -c "%U" "$1")" = "$u" ] || [ "$(stat -c "%U" "$1")" = "${4}\\$u" ]; then true; else chown -R "${4}"\\"$u" "$1"; fi

if Check_Backslash "${3/\\/@}"; then
	g="${3#*\\}"
else
	g="${3#$4}"
fi

if [ "$(stat -c "%G" "$1")" = "$g" ] || [ "$(stat -c "%G" "$1")" = "${4}\\$g" ]; then true; else chgrp -R "${4}"\\"$g" "$1"; fi

[ "$5" ] && unset sharequotadev && Addquota "$1" "$5" "${6:-0}"

exit 0