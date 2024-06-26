#!/usr/bin/env bash
# Description: Auto-Configurator of Subdirectory Quota
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

if [ -d "$1" ] && [ -n "$2" ]; then true; else exit 1; fi

unset sharequotadev

Addquota "$1" "$2" "${3:-0}" 'Yes' > "$TEMPFILE" 2>&1
"${0%/*}/logger.bash" "$TEMPFILE" "$0" $?

exit 0
