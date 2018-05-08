# On startup the CIS AMI will execute a daily cron security patch update
# need to wait a couple minutes for update to complete
sleep 180

# set pam config
sudo pam-auth-update --package --force

# noninteractive dist-upgrade will maintain existing secure config file settings
sudo DEBIAN_FRONTEND=noninteractive apt-get -y -o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold' dist-upgrade

# remove unnecessary packages
sudo apt-get -y auto-remove
