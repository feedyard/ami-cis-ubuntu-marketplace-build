# On startup the CIS AMI will execute a daily cron security patch update
# need to wait a couple minutes for update to complete
sleep 180

# add new repository info
cat <<EOF >>  sudo tee /etc/apt/sources.list
deb http://us-east-1.ec2.archive.ubuntu.com/ubuntu/ artful main restricted
deb http://security.ubuntu.com/ubuntu artful-security main restricted
EOF

cat <<EOF > sudo tee /etc/apt/preferences.d/cis_patch.pref
Package: *
Pin: release n=artful
Pin-Priority: -10

Package: man-db
Pin: release n=artful
Pin-Priority: 500

Package: git
Pin: release n=artful
Pin-Priority: 500

Package: cron
Pin: release n=artful
Pin-Priority: 500
EOF

# update
sudo apt-get -y update

# specific package patch
sudo apt-get install -y man-db
sudo apt-get install -y git
sudo apt-get install -y cron
