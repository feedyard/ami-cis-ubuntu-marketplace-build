# ami-cis-ubuntu-marketplace-build
Pipeline to patch, congiure, version, and upload CIS Marketplace available Ubuntu 160.04 LTS hardened image

1. consider a target VPC/subnet location with pu blic access for 'builders'
2. 


# requirements

ruby >= 2.4.0
packer
test-kitchen
inspec
kitchen-ec2
kitchen-inspec


-o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold'


-o "Dpkg::Options::=--force-confdef" -o "Dpkg::Options::=--force-confold"

this job does not clean up legacy AMI. Consider pruning