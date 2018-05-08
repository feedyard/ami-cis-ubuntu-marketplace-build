# Install AWS Inspector agent
curl -O https://d1wk0tztpsntt1.cloudfront.net/linux/latest/install

# need to wait a couple minutes for a new cis boot to complete the apt-get daily upgrade
sleep 180

# install agent
sudo bash install

# confirm agent is running
sudo /etc/init.d/awsagent start
