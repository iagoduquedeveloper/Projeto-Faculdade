#!/usr/bin/env bash
# Description: Logon Script (Executed with session user ID)
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
#---------------------------------------------------------------------#


# Note: Use this script to automate tasks on the system while a
# domain user opens a session on a Linux system. The commands
# added here will be executed with the ID of the user that are
# opening session, which restricts the settings and/or modifications
# only to the profile of this user, or in files and directories in
# which it has the appropriate permissions.
#
# The following environment variables will be imported during the
# execution of this script:
#
# VARIABLE		Description
# --------		-----------
# NETLOGON		Mount point of the Netlogon share on the system
# USERNAME		Name of the user that are opening session
# USERID		ID of the user that are opening session
# USERDOMAIN	Domain name of the user that is opening session
# USERPROFILE	Home directory path of the user that is opening session
# USERSHELL		Login shell of the user that is opening session
# GROUPID		Primary group ID of the user that is opening session
# USERGROUP		Primary group name of the user that is opening session
# USERGROUPS	Group list separated by commas (,) of the user that is opening session
#
# Eg: Copying image.jpg file from Wallpapers subfolder in Netlogon
# to user's home directory, and setting it as wallpaper in Gnome Shell:
#
# 	cp "${NETLOGON}/Wallpapers/image.jpg" "${USERPROFILE}/image.jpg"
# 	gsettings set org.gnome.desktop.background picture-uri file://${USERPROFILE}/image.jpg
#


# --- Add your script below:
