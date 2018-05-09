# ami-cis-ubuntu-marketplace-build
Pipeline to patch, configure, version, and upload CIS Marketplace available Ubuntu Linux 16.04 LTS level 1 image

1. Two stage build

   stage one: Pulls CIS marketplace image, performs dist-upgrade
   stage two: Uses AMI from stage one, purge pre dist-upgrade kernels, perform any remaining cve remediation
   
2. Two kinds of testing

   inspec: cis level 1 benchmark tests to validate configuration hardening
   cve:    AWS Inspector cve scan for package vulnerabilities

3. AWS build location

The demo pipeline uses the default vpc for the instances used in building and testing the AMI definition. As part of
defining the aws role with appropriate permissions for this pipeline, you could consider also creating a specific
vpc for this kind of activity.

4. AWS Inspector

Performing a cve scan of the ami definition using AWS Inspector requires the configuration of
* assessment resource group definition based on key=value pair 'created-by=test-kitchen'
* assessment target definition based on the resource group
* assessment template using rules package 'Common Vulnerabilities and Exposures-1.1' (15min runtime)

This can be done either as part of the terraform pipeline that provisions a build network as described in point 3 above,
or you can use boto3 to idempotently create as part of the awsinspector function in tasks.py

The additional steps needed within '$invoke awsinspector' to perform the inspection:
* It already generates a test-kitchen tempmlate
* Use kitchen.create and kitchen.converge to create an AWS instance and install the Inspector agent
* boto3.client('inspector').start_assessment_run(assessmentTemplateArn='string', assessmentRunName='string') to trigger and assessment run
* poll boto3.client('inspector').list_assessment_runs with the assessmentTemplateArn until assessmentRunName appears (15-17 min)
* poll get_assessment_report with above assessmentRunArn and HTML format until it returns a download url
* download and archive, then scan html for vulnerabilities found and alert

As noted in item 1 above, if the cve scan shows vulnerabilities remediation is performed in stage two of the build.


# requirements

python
invoke
ruby >= 2.4.0
packer
inspec
test-kitchen
kitchen-ec2
kitchen-inspec
