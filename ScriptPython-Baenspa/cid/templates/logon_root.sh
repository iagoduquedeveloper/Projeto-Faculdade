#!/usr/bin/env bash
# Description: Logon Script (Executed with root user ID)
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
#------------------------------------------------------------------------------#


# Note: Use this script to automate tasks on the system while a
# domain user opens a session on a Linux system. The commands
# added here will be executed with the root user ID, which
# allows you to make settings or modifications to the system.
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
# Eg: Adding printer to the system:
#
#	lpadmin -p printer -E -v ipp://${printer_addr}/ipp/printer -m everywhere
#

# --- Add your script below:
