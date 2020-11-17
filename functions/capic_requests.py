'''
This lamdba creates VPC using cAPIC in newly vended account
'''

import ipaddress
import json
import logging
import os
import base64
from time import sleep
import requests
import urllib3
import boto3
from botocore.exceptions import ClientError

LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)
ERROR_CALLS = list()

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
try:
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ClientError as exe:
    pass

def get_az_list(region):
    '''Return availability zones list of a given region'''

    az_list = list()
    azs = boto3.client('ec2', region_name=region)

    try:
        for item in azs.describe_availability_zones()['AvailabilityZones']:
            az_list.append(item['ZoneName'])
    except ClientError as exe:
        LOGGER.error('Unable to list AZs: %s', str(exe))

    return az_list


def get_secret(secret_name):
    '''Return value for a secret key'''

    secret = None
    sm_client = boto3.client('secretsmanager')

    try:
        get_secret_value_response = sm_client.get_secret_value(SecretId=secret_name)
    except ClientError as exe:
        LOGGER.error('Unable to get Secret %s: %s', secret_name, str(exe))
        raise exe
    else:
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
        else:
            secret = base64.b64decode(get_secret_value_response['SecretBinary'])

    return secret


def get_parameter_value(param_name):
    '''Return parameter value'''

    param_value = None
    ssm_client = boto3.client('ssm')

    try:
        response = ssm_client.get_parameter(Name=param_name)
    except ClientError as exe:
        LOGGER.error("Unable to get SSM Parameter value: %s", str(exe))
    else:
        if 'Parameter' in response:
            param_value = response['Parameter']['Value']

    return param_value


def create_monitoring_role(account, region):
    '''Add a stack instance to a StackSet'''

    cfn = boto3.client('cloudformation')
    ss_status = 'RUNNING'
    ss_name = 'capic-cross-account-role-stackset'

    result = cfn.create_stack_instances(StackSetName=ss_name,
                                       Accounts=[account],
                                       Regions=[region])
    op_id = result['OperationId']
    #Wait for cross-account role creation completion
    while ss_status in ('RUNNING', 'QUEUED', 'STOPPING'):
        LOGGER.info('Creating cross-account role on %s, wait 10 sec: %s',
                    account, ss_status)
        result = cfn.describe_stack_set_operation(StackSetName=ss_name,
                                                  OperationId=op_id)
        ss_status = result['StackSetOperation']['Status']
        sleep(10)

def get_headers(url):
    '''Return API token annd cookies'''

    token = get_token(url)
    apic_token = 'Bearer ' + token
    apic_cookie = 'APIC-cookie=' + token
    header = {'Authorization' : apic_token,
              'Cookie': apic_cookie,
              'Content-Type': 'application/json'}

    return header


def get_token(url):
    '''Authenticate with cAPIC and get token'''

    api_url = url + '/api/aaaLogin.json'

    header = {'Content-Type': 'application/json'}
    creds = get_secret(os.environ['CAPIC_API_SECRET'])
    capic_creds = json.loads(creds)
    user = capic_creds['cpaic_admin_user']
    password = capic_creds['password']

    payload = {
              "aaaUser":{
                "attributes":{
                  "name":user,
                  "pwd":password
                }}}

    try:
        response = make_request(api_url, header, payload)
        token=response.json()['imdata'][0]['aaaLogin']['attributes']['token']
        return token
    except ClientError as exe:
        LOGGER.error('Unable to generate token: %s', str(exe))


def make_request(api_url, header, payload, verify=False, command='POST'):
    '''POST/GET a request to the URL, return response'''

    response = dict()

    response = requests.request(command, api_url, headers=header,
                                data = json.dumps(payload), verify=verify)

    LOGGER.info('RESPONSE: %s', str(response.json()))
    imdata = response.json()['imdata']
    if len(imdata) > 0 and 'error' in imdata[0].keys():
        ERROR_CALLS.append([api_url, str(response.json())])
        LOGGER.error('Error in %s command: %s', command, str(response.json()))

    return response


def get_ip_list(url):
    '''List CIDR ranges used'''

    api_url = url + '/api/class/cloudCidr.json'
    header = get_headers(url)
    payload = dict()
    result = list()

    try:
        output = make_request(api_url, header, payload, command='GET')
        for item in output.json()['imdata']:
            result.append(item['cloudCidr']['attributes']['addr'])
        return result
    except ClientError as exe:
        LOGGER.error('Unable to generate the IP List: %s', str(exe))


def get_next_available_cidr(network, mask_length, url):
    '''Return next non-overlapping CIDR'''

    consumed_cidrs = get_ip_list(url)
    consumed_cidrs = [ipaddress.ip_network(item) for item in consumed_cidrs if item]

    for next_cidr in ipaddress.ip_network(network).subnets(new_prefix=int(mask_length)):
        overlap = False
        for used_cidr in consumed_cidrs:
            if next_cidr.overlaps(used_cidr):
                overlap = True
                break
        if not overlap:
            return str(next_cidr)


def get_subnet_list(cidr, count):
    '''Return list of subnets for a given set of cidr/count'''

    subnet_list = list()
    if count > 4:
        count = 4
    for subnet in ipaddress.ip_network(cidr).subnets(prefixlen_diff=count):
        subnet_list.append(subnet.with_prefixlen)

    return subnet_list


def create_tenant(tenant_name, account_id, url):
    '''Create a tenant in cAPIC'''

    api_url = url + '/api/mo/uni.json'
    header = get_headers(url)
    payload = {
                "fvTenant" : {
                    "attributes" : {"name" : tenant_name},
                    "children": [{
                        "cloudAwsProvider": {
                            "attributes": {
                                "providerId": "aws-" + account_id,
                                "accountId": account_id,
                                "isTrusted": "yes",
                                "isAccountInOrg": "no"
                            },
                        "children": []
                    }}]
                }}

    try:
        response = make_request(api_url, header, payload)
        return response
    except ClientError as exe:
        LOGGER.error('Unable to create a Tenant: %s', str(exe))


def create_vrf(tenant_name, vrf_name, url):
    '''Create a vrf_name'''

    api_url = url + '/api/node/mo/uni/tn-'+ tenant_name +'.json'
    header = get_headers(url)
    payload = {
                "fvCtx": {
                    "attributes": {"name": vrf_name},
                    "children": []
                }}

    try:
        response = make_request(api_url, header, payload)
        return response
    except ClientError as exe:
        LOGGER.error('Unable to create VRF: %s', str(exe))


def associate_region(tenant_name, vrf_name, vpc_cidr, region, hub_name, url):
    '''Associate a region to a VRF'''

    api_url = url + '/api/node/mo/uni/tn-'+ tenant_name +'.json'
    tdn = 'uni/tn-infra/gwrouterp-' + hub_name
    header = get_headers(url)
    payload = {
            "cloudCtxProfile": {
                "attributes": {"name": vrf_name + "_" + region},
                "children": [{
                    "cloudCidr": {
                        "attributes": {
                            "addr": vpc_cidr,
                            "primary": "yes"
                        },
                        "children": []
                    }
                }, {
                    "cloudRsCtxProfileToGatewayRouterP": {
                        "attributes": {
                            "tDn": tdn
                        },
                        "children": []
                    }
                }, {
                    "cloudRsCtxProfileToRegion": {
                        "attributes": {
                            "tDn": "uni/clouddomp/provp-aws/region-" + region
                        },
                        "children": []
                    }
                }, {
                    "cloudRsToCtx": {
                        "attributes": {
                            "tnFvCtxName": vrf_name
                        },
                        "children": []
                    }}]
                }}

    try:
        response = make_request(api_url, header, payload)
        return response
    except ClientError as exe:
        LOGGER.error('Unable to generate token: %s', str(exe))


def create_subnet(tenant_name, vrf_cidr, subnet_range, region_name, az_name, url, subnet_type=''):
    '''Create a subnet in a given VRF'''

    vrf_name = tenant_name + '_VPC'
    ctxprofile = '/ctxprofile-' + vrf_name + '_' + region_name
    cidr_url = '/cidr-[' + vrf_cidr + '].json'
    url = url + '/api/node/mo/uni/tn-'+ tenant_name + ctxprofile + cidr_url

    header = get_headers(url)
    subnet_name = vrf_name + '_' + subnet_range.split('/')[0].replace('.','_') + '_' + az_name
    td_name = 'uni/clouddomp/provp-aws/region-' + region_name + '/zone-' + az_name
    payload = {
        "cloudSubnet": {
            "attributes": {
                "name": subnet_name,
                "ip": subnet_range,
                "usage": subnet_type
                },
            "children": [{
                "cloudRsZoneAttach": {
                    "attributes": {"tDn": td_name},
                    "children": []
                    }
                    }]
                    }}

    try:
        response = make_request(url, header, payload)
        return response
    except ClientError as exe:
        LOGGER.error('Unable to create subnet: %s', str(exe))


def create_vrf_and_associate(tenant_name, region, capic_url):
    '''Create VRF and associate a region'''

    capic_base_cidr = get_parameter_value(os.environ['CAPIC_BASE_CIDR'])
    capic_mask_length = get_parameter_value(os.environ['CAPIC_MASK_LENGTH'])
    hub_name = get_parameter_value(os.environ['CAPIC_HUB_NETWORK_NAME'])

    #Create VRF
    vrf_name = tenant_name + '_VPC'
    create_vrf(tenant_name, vrf_name, capic_url)
    #Associate VRF to a Region
    vpc_cidr = get_next_available_cidr(capic_base_cidr,
                                       capic_mask_length,
                                       capic_url)

    associate_region(tenant_name, vrf_name, vpc_cidr, region, hub_name, capic_url)
    #Create Subnets across multiple regions
    create_subnets_across_azs(tenant_name, vpc_cidr, region, capic_url)


def create_subnets_across_azs(tenant_name, vpc_cidr, region, capic_url):
    '''Create 2 Gateway Subnets and rotate across AZs if subnet count is higher than AZs/region'''

    #az_list = get_az_list(region) * 8
    az_list = [ region+'a', region+'b' ] * 16
    capic_subnet_count = int(get_parameter_value(os.environ['CAPIC_SUBNET_COUNT']))
    subnet_list = get_subnet_list(vpc_cidr, capic_subnet_count)
    gateway_subnet = list()
    while capic_subnet_count >= 1:
        capic_subnet_count -= 1
        subnet_range = subnet_list.pop(0)
        az_name = az_list.pop(0)
        if az_name not in gateway_subnet:
            gateway_subnet.append(az_name)
            create_subnet(tenant_name, vpc_cidr, subnet_range, region,
                          az_name, capic_url, subnet_type='gateway')
        else:
            create_subnet(tenant_name, vpc_cidr, subnet_range,
                          region, az_name, capic_url)


def lambda_handler(event, context):
    '''Handle life cycle event and trigger VPC creation on newly created account'''

    LOGGER.info('Control Tower Event Captured: %s', str(event))
    LOGGER.info('Context: %s', str(context))
    event_details = event['detail']
    event_name = event_details['eventName']

    capic_mgmt_ip = get_parameter_value(os.environ['CAPIC_MGMT_IP'])
    region_list = get_parameter_value(os.environ['VPC_REGION']).split(',')
    capic_url = 'https://' + capic_mgmt_ip

    if event_name == 'CreateManagedAccount':
        new_acc_info = event_details['serviceEventDetails']['createManagedAccountStatus']
        cmd_status = new_acc_info['state']
        if cmd_status == 'SUCCEEDED':
            try:
                region_name = event_details['awsRegion']
                acc_id = new_acc_info['account']['accountId']
                account_name = new_acc_info['account']['accountName']
                tenant_name = ''.join(e for e in account_name if e.isalnum())
                create_monitoring_role(acc_id, region_name)
                #Create Tenant in CAPIC
                create_tenant(tenant_name, acc_id, capic_url)
                for region in region_list:
                    region = ''.join(region.split())
                    #Create VRF, associate and create subnets
                    create_vrf_and_associate(tenant_name, region, capic_url)
                if len(ERROR_CALLS) == 0:
                    LOGGER.info('Completed: %s registered', acc_id)
                else:
                    LOGGER.warning('%s FAILURES DETECTED: %s', len(ERROR_CALLS), ERROR_CALLS)
            except ClientError as exe:
                LOGGER.error('Unable to configure: %s - %s', acc_id, str(exe))
        else:
            LOGGER.warning('%s event status recieved. Skipping', cmd_status)
    else:
        LOGGER.warning('Unexpected Event %s recieved, Skipping', event_name)
