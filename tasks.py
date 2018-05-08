from invoke import task
import os
from jinja2 import Environment, FileSystemLoader
import boto3
import pprint

@task
def build(ctx):
    ctx.run("packer build templates/cis_ubuntu1604_marketplace_release.json")

@task
def inspec(ctx, build_account, build_region, instance_type, key_pair):
    rendertemplate(build_account, build_region, instance_type, key_pair)
    ctx.run('kitchen test')

@task
def awsinspector(ctx, build_account, build_region, instance_type, key_pair):
    rendertemplate(build_account, build_region, instance_type, key_pair)
    ctx.run('echo aws inspector validation not yet configured')

def rendertemplate(build_account, build_region, instance_type, key_pair):
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

    template = TEMPLATE_ENVIRONMENT.get_template("kitchen_template.yml")
    renderedtemplate = template.render(**DICTIONARY)

    f = open(".kitchen.yml", 'w')
    f.write(renderedtemplate)
    f.close()

@task
def enc(ctx, file='local.env', encoded_file='env.ci'):
    ctx.run("openssl aes-256-cbc -e -in {} -out {} -k $FEEDYARD_PIPELINE_KEY".format(file, encoded_file))
    ctx.run("openssl aes-256-cbc -e -in {} -out {} -k $FEEDYARD_PIPELINE_KEY".format('id_rsa.env', 'id_rsa.ci'))
    ctx.run("openssl aes-256-cbc -e -in {} -out {} -k $FEEDYARD_PIPELINE_KEY".format('id_rsa.pub.env', 'id_rsa.pub.ci'))

@task
def dec(ctx, encoded_file='env.ci', file='local.env'):
    ctx.run("openssl aes-256-cbc -d -in {} -out {} -k $FEEDYARD_PIPELINE_KEY".format(encoded_file, file))
    ctx.run("openssl aes-256-cbc -d -in {} -out {} -k $FEEDYARD_PIPELINE_KEY".format('id_rsa.ci', 'id_rsa'))
    ctx.run("openssl aes-256-cbc -e -in {} -out {} -k $FEEDYARD_PIPELINE_KEY".format('id_rsa.pub.ci', 'id_rsa.pub'))