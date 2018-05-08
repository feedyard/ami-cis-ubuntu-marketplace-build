#!/bin/bash

sudo lsof /var/lib/dpkg/lock

# set pam config
sudo DEBIAN_FRONTEND=noninteractive pam-auth-update --package --force

# noninteractive dist-upgrade will maintain existing secure config file settings
sudo DEBIAN_FRONTEND=noninteractive apt-get -y update
sudo DEBIAN_FRONTEND=noninteractive apt-get -y -o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold' dist-upgrade

# remove unnecessary packages
sudo DEBIAN_FRONTEND=noninteractive apt-get -y auto-remove
