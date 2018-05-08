# On startup the CIS AMI will execute a daily cron security patch update
# need to wait a couple minutes for update to complete
sleep 180

#!/bin/bash
set -e

echo "---- set locale"
sudo locale-gen C.UTF-8 || true
sudo update-locale LANG=en_US.UTF-8
sudo /bin/bash -c 'echo "export LANG=C.UTF-8" >> /etc/skel/.bashrc'

echo "---- make Apt non interactive"
sudo /bin/bash -c 'echo "force-confnew" >> /etc/dpkg/dpkg.cfg'
sudo /bin/bash -c 'cat /tmp/dpkg.cfg.update >> /etc/sudoers.d/env_keep'
sudo cp /tmp/apt.conf.update /etc/apt/apt.conf

# set pam config
sudo DEBIAN_FRONTEND=noninteractive pam-auth-update --package --force

# noninteractive dist-upgrade will maintain existing secure config file settings
sudo DEBIAN_FRONTEND=noninteractive apt-get -y update
sudo DEBIAN_FRONTEND=noninteractive apt-get -y -o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold' dist-upgrade

# remove unnecessary packages
sudo DEBIAN_FRONTEND=noninteractive apt-get -y auto-remove
