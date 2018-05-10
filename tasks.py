from invoke import task
import os
from jinja2 import Environment, FileSystemLoader

@task
def build(ctx):
    ctx.run("packer build templates/cis_ubuntu1604_marketplace_release.json")

@task
def inspec(ctx, build_account, build_region, instance_type, key_pair, os_name):
    rendertemplate(build_account, build_region, instance_type, key_pair, os_name)
    ctx.run('kitchen test')

@task
def awsinspector(ctx, build_account, build_region, instance_type, key_pair, os_name):
    rendertemplate(build_account, build_region, instance_type, key_pair, os_name)
    ctx.run('echo aws inspector validation not yet configured')

def rendertemplate(build_account, build_region, instance_type, key_pair, os_name):
    DICTIONARY = {}
    PATH = os.path.dirname(os.path.abspath(__file__))
    TEMPLATE_ENVIRONMENT = Environment(
        autoescape=False,
        loader=FileSystemLoader(os.path.join(PATH)),
        trim_blocks=False)

    DICTIONARY['build_account'] = build_account
    DICTIONARY['build_region'] = build_region
    DICTIONARY['instance_type'] = instance_type
    DICTIONARY['key_pair'] = key_pair
    DICTIONARY['os_name'] = os_name

    template = TEMPLATE_ENVIRONMENT.get_template("kitchen_template.yml")
    renderedtemplate = template.render(**DICTIONARY)

    f = open(".kitchen.yml", 'w')
    f.write(renderedtemplate)
    f.close()

@task
def enc(ctx):
    ctx.run("openssl aes-256-cbc -e -in {} -out {} -k $FEEDYARD_PIPELINE_KEY".format('local.env', 'env.ci'))
    ctx.run("openssl aes-256-cbc -e -in {} -out {} -k $FEEDYARD_PIPELINE_KEY".format('id_rsa_ec2.env', 'id_rsa_ec2.ci'))
    ctx.run("openssl aes-256-cbc -e -in {} -out {} -k $FEEDYARD_PIPELINE_KEY".format('id_rsa_ec2.pub.env', 'id_rsa_ec2.pub.ci'))

@task
def dec(ctx):
    ctx.run("openssl aes-256-cbc -d -in {} -out {} -k $FEEDYARD_PIPELINE_KEY".format('env.ci', 'local.env'))
    ctx.run("openssl aes-256-cbc -d -in {} -out {} -k $FEEDYARD_PIPELINE_KEY".format('id_rsa_ec2.ci', 'id_rsa_ec2'))
    ctx.run("chmod 400 id_rsa_ec2")
    ctx.run("openssl aes-256-cbc -e -in {} -out {} -k $FEEDYARD_PIPELINE_KEY".format('id_rsa_ec2.pub.ci', 'id_rsa_ec2.pub'))
