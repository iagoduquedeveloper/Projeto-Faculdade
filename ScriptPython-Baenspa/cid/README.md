CID
---
Copyright (C) 2012-2023 Eduardo Moraes <<emoraes25@gmail.com>>  


LINKS
------
- [Homepage](https://c-i-d.sourceforge.io)
- [Documentation](https://cid-doc.github.io)
- [Donations](https://sourceforge.net/p/c-i-d/donate)


REQUIREMENTS
-------------
- acl (= any)
- attr (= any)
- awk (= any)
- bash (>= 4)
- cifs-utils (>= 6.4)
- CUPS (= any)
- {diff,find,core}utils (= any)
- grep (= any)
- gzip (= any)
- hostname (= any)
- iproute[2] (= any)
- Kerberos V5 (>= 1.13)
- keyutils (= any)
- mount (= any)
- pam_mount (>= 2.14)
- passwd (= any)
- ping (= any)
- pkexec (= any)
- Samba (>= 4.3.11)
- sed (= any)
- sudo (= any)
- systemd (= any)
- xhost (= any)
- zenity (>= 3.18.1)


INSTALLATION
-------------
- Ubuntu:  
	sudo add-apt-repository ppa:emoraes25/cid  
	sudo apt update  
	sudo apt install cid cid-gtk  

- Debian:  
	[ -d /etc/apt/keyrings ] || sudo mkdir -m0755 -p /etc/apt/keyrings  
	sudo wget -O /etc/apt/keyrings/cid-archive-keyring.pgp https://downloads.sf.net/c-i-d/pkgs/apt/debian/cid-archive-keyring.pgp  
	sudo wget -O /etc/apt/sources.list.d/cid.sources https://downloads.sf.net/c-i-d/pkgs/apt/debian/cid.sources  
	sudo apt update  
	sudo apt install cid cid-gtk  

- Fedora:  
	sudo rpm --import https://downloads.sf.net/c-i-d/docs/CID-GPG-KEY  
	sudo dnf config-manager --add-repo https://downloads.sf.net/c-i-d/pkgs/rpm/cid.repo  
	sudo dnf install cid  

- OpenSUSE:  
	sudo rpm --import https://downloads.sf.net/c-i-d/docs/CID-GPG-KEY  
	sudo zypper ar https://downloads.sf.net/c-i-d/pkgs/rpm/cid.repo  
	sudo zypper in cid  

- Other distros:  
	ver='x.x.x' #current version  
	wget https://downloads.sf.net/c-i-d/cid-${ver}.tar.gz  
	tar -xzf cid-${ver}.tar.gz  
	cd cid-${ver}  
	sudo ./INSTALL.sh  

> Note: Run **sudo ./INSTALL.sh uninstall** to uninstall the 
program files from the same version of the package.
