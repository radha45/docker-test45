import sys 
import os


# print(argumentList[1])

def load(user_id,account_id):
    # should we do os.path.expanduser here?
    ACCESS_KEY, SECRET_KEY, SESSION_TOKEN = get_crendentails(user_id,account_id)
    print(ACCESS_KEY,SECRET_KEY)
    os.environ["AWS_ACCESS_KEY_ID"] = ACCESS_KEY
    os.environ["AWS_SECRET_ACCESS_KEY"] = SECRET_KEY
    if SESSION_TOKEN:
        os.environ["AWS_SESSION_TOKEN"] = SESSION_TOKEN
    # from juno.schema import validate, StructureParser
    # data = update_policy(filename)
    # structure = StructureParser()
    # structure.validate(data)
    # load_resources(structure.get_resource_types(data))

    # if isinstance(data, list):
    #     log.warning('yaml in invalid format. The "policies:" line is probably missing.')
    #     return None

    # if validate:
    #     errors = validate(data)
    #     if errors:
    #         raise PolicyValidationError(
    #             "Failed to validate policy %s \n %s" % (
    #                 errors[1], errors[0]))

    # # Test for empty policy file
    # if not data or data.get('policies') is None:
    #     return None

    # collection = PolicyCollection.from_data(data, options)
    # if validate:
    #     # non schema validation of policies
    #     [p.validate() for p in collection]
    # return collection

import json
import boto3
import datetime
import pymysql
#
# MYSQL_DATABASE_USER = 'sudeesh'
# MYSQL_DATABASE_PASSWORD = 'Pleas3Chang3Passw0rd!'
# MYSQL_DATABASE_DB = 'junodb'
# MYSQL_DATABASE_HOST = 'junodb.c435hsq53dfq.us-east-1.rds.amazonaws.com'

MYSQL_DATABASE_USER = 'admin'
MYSQL_DATABASE_PASSWORD = 'Radha456'
MYSQL_DATABASE_DB = 'juno'
MYSQL_DATABASE_HOST = 'eadha-docker.cutn3y51xkog.us-west-2.rds.amazonaws.com'
from pymysql import cursors

def db_conncetion():
    # connection = pymysql.connect(host=MYSQL_DATABASE_HOST,
    #                                      database=MYSQL_DATABASE_DB,
    #                                      user=MYSQL_DATABASE_USER,
    #                                      password=MYSQL_DATABASE_PASSWORD)


    # Connect to the database
    connection = pymysql.connect(host=MYSQL_DATABASE_HOST,
                                 user=MYSQL_DATABASE_USER,
                                 password=MYSQL_DATABASE_PASSWORD,
                                 db=MYSQL_DATABASE_DB,
                                 charset='utf8mb4',
                                 cursorclass= pymysql.cursors.DictCursor)
    return connection

def get_crendentails(account_id):
        connection = db_conncetion()
        cursor = connection.cursor()
       
        cred_query = "SELECT aws_api_key, aws_access_key,account_id, assumerole, external_id FROM tbl_cloudaccount where account_id='{}' ".format(account_id)
        cursor = connection.cursor()
        cursor.execute(cred_query)
        cred_rows = cursor.fetchall()
        access_key = cred_rows[0]['aws_api_key']
        # print(access_key)
        seceret_key = cred_rows[0]['aws_access_key']
        account_id = cred_rows[0]['account_id']
        assumerole = cred_rows[0]['assumerole']
        external_id = cred_rows[0]['external_id']
        cursor.close()
        connection.close()
        if access_key:
            return  access_key ,seceret_key,None
        else:

            sts_client = boto3.client('sts')
            role_arn = f"arn:aws:iam::{account_id}:role/{assumerole}"
            assumed_role_object = sts_client.assume_role(RoleArn=role_arn,
                                                            RoleSessionName="AssumeRoleSession1" + account_id,
                                                            ExternalId=external_id)
            credentials = assumed_role_object['Credentials']

            return credentials['AccessKeyId'],credentials['SecretAccessKey'],credentials['SessionToken']
          
