#!/usr/bin/env bash
# Description: Log Generator
# Copyright (C) 2012-2021 Eduardo Moraes <emoraes25@gmail.com>
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

[[ "${LOGSIZE:-0}" -eq '0' ]] && exit 0

if [ -f "$1" ]; then
	sed -i '/^$/d' "$1"

	lin="$(wc -l "$1" | awk '{print $1}')"

	if [ "${lin:-0}" -gt '0' ]; then
		[ -d "$LOGDIR" ] || mkdir -p "$LOGDIR"

		cd "$LOGDIR" || exit 0

		if [ -f "$2" ] || echo "$2" | grep -oq 'CID Init Script'; then
			file='scripts.log'
		else
			file='functions.log'
		fi

		if [ -f "$file" ]; then
			[[ "$(wc -l "$file" | awk '{print $1}')" -ge "${LOGSIZE:=1000}" || "$(stat -c %y "$file" | cut -d '-' -f 1)" -ne "$(date "+%Y")" ]] && tar -czf "${file}.$(($(find . -maxdepth 1 -name "${file}*.tar.gz" | grep -Ewc "${file}\.[0-9]+\.tar\.gz")+1)).tar.gz" "$file" && rm -f "$file"
		fi

		[ ! -f "${file}" ] && true >"$file" && chmod 600 "$file"

		for((int=1;int<=lin;int++)); do
			LC_ALL=C date "+%b %d %T $HOSTNAME ${2##*/} ${3}: $(sed -n ${int}p "$1")" >> "$file"
		done

		unset file
		cd - >/dev/null || exit 0
	fi

	rm -f "$1"
fi

exit 0