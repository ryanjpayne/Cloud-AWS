import json
import logging
import os
import sys
import subprocess
import boto3
import base64
from botocore.exceptions import ClientError
import datetime

# pip install falconpy package to /tmp/ and add to path
subprocess.call('pip install crowdstrike-falconpy -t /tmp/ --no-cache-dir'.split(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
sys.path.insert(1, '/tmp/')
from falconpy import CSPMRegistration

logger = logging.getLogger()
logger.setLevel(logging.INFO)

SECRET_STORE_NAME = os.environ['secret_name']
SECRET_STORE_REGION = os.environ['secret_region']
AWS_REGION = os.environ['AWS_REGION']
TIMESTAMP = os.environ['time_stamp']

VERSION = "1.0.0"
name = "crowdstrike-cloud-lab"
useragent = ("%s/%s" % (name, VERSION))

def get_secret(secret_name, secret_region):
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=secret_region
    )
    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'DecryptionFailureException':
            raise e
        elif e.response['Error']['Code'] == 'InternalServiceErrorException':
            raise e
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            raise e
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            raise e
        elif e.response['Error']['Code'] == 'ResourceNotFoundException':
            raise e
    else:
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
        else:
            secret = base64.b64decode(get_secret_value_response['SecretBinary'])
        return secret
    
def deregister(FalconClientId, FalconSecret, FalconCloud, aws_account_id):
    falcon = CSPMRegistration(client_id=FalconClientId,
                            client_secret=FalconSecret,
                            base_url=FalconCloud,
                            user_agent=useragent
                            )
    response = falcon.delete_aws_account(ids=aws_account_id,
                                        user_agent=useragent
                                        )
    logger.info('Response: {}'.format(response))
    return

def delete_stacks():
    session = boto3.session.Session()
    client = session.client(
        service_name='cloudformation',
        region_name=AWS_REGION
    )
    stacksResponse = client.list_stacks(
        StackStatusFilter=[
            'CREATE_FAILED', 'CREATE_COMPLETE', 'ROLLBACK_IN_PROGRESS', 'ROLLBACK_FAILED', 'ROLLBACK_COMPLETE', 'DELETE_FAILED', 'UPDATE_COMPLETE', 'UPDATE_FAILED', 'UPDATE_ROLLBACK_FAILED', 'UPDATE_ROLLBACK_COMPLETE',
        ]
    )
    stacks = stacksResponse['StackSummaries']
    stackNames = []
    for stack in stacks:
        stackNames += [stack['StackName']]
    for stackName in stackNames:
        logger.info('getting stacks')
        logger.info(stackName)
        client.delete_stack(
            StackName=stackName
        )
    return

def lambda_handler(event,context):
    logger.info('Got event {}'.format(event))
    logger.info('Context {}'.format(context))
    
    start = datetime.datetime.strptime(TIMESTAMP, '%Y%m%d%H%M%S')
    now = datetime.datetime.now()
    difference = now - start
    seconds = difference.total_seconds() 
    hours = seconds / (60 * 60)
    
    if hours < 8:
        logger.info('keep alive')
    else:
        logger.info('TTL exceeded, cleaning up...')
        aws_account_id = context.invoked_function_arn.split(":")[4]
        logger.info(aws_account_id)
    
        logger.info('Retrieving Secret...')
        secret_str = get_secret(SECRET_STORE_NAME, SECRET_STORE_REGION)
        if secret_str:
            secrets_dict = json.loads(secret_str)
        
        logger.info('Destroying CloudFormation Templates')
        delete_stacks()
        
        logger.info('Deregistering account...')
        FalconClientId = secrets_dict['FalconClientId']
        FalconSecret = secrets_dict['FalconSecret']
        FalconCloud = secrets_dict['FalconCloud']
        deregister(FalconClientId, FalconSecret, FalconCloud, aws_account_id)
