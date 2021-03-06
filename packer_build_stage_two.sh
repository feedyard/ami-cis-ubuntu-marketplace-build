#!/bin/bash

sudo lsof /var/lib/dpkg/lock

# remove unnecessary packages
sudo DEBIAN_FRONTEND=noninteractive apt-get -y auto-remove
dpkg --list | grep linux-image | awk '{ print $2 }' | sort -V | sed -n '/'`uname -r`'/q;p' | xargs sudo apt-get -y purge

# add new repository info
sudo bash -c 'cat <<EOF >> /etc/apt/sources.list
deb http://us-east-1.ec2.archive.ubuntu.com/ubuntu/ artful main restricted
deb http://security.ubuntu.com/ubuntu artful-security main restricted
EOF'

sudo bash -c 'cat <<EOF > /etc/apt/preferences.d/cis_patch.pref
Package: *
Pin: release n=artful
Pin-Priority: -10

Package: libpipeline1
Pin: release n=artful
Pin-Priority: 500

Package: man-db
Pin: release n=artful
Pin-Priority: 500

Package: git-man
Pin: release n=artful
Pin-Priority: 500

Package: git
Pin: release n=artful
Pin-Priority: 500

Package: cron
Pin: release n=artful
Pin-Priority: 500
EOF'

# update
sudo apt-get -y update

# specific package patch
sudo apt-get install -y libpipeline1
sudo apt-get install -y man-db
sudo apt-get install -y git-man
sudo apt-get install -y git
sudo apt-get install -y cron
