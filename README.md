# ami-cis-ubuntu-marketplace-build
Pipeline to patch, configure, version, and upload CIS Marketplace available Ubuntu Linux 16.04 LTS level 1 image

    #
    # Performing a cve scan of the ami definition using AWS Inspector requires the configuration of
    # - assessment resource group definition based on key=value pair 'created-by=test-kitchen'
    # - assessment target definition based on the resource group
    # - assessment template using rules package 'Common Vulnerabilities and Exposures-1.1'
    #
    # steps:
    # - boto3 configuration of


# requirements

python
invoke
ruby >= 2.4.0
packer
inspec
test-kitchen
kitchen-ec2
kitchen-inspec
