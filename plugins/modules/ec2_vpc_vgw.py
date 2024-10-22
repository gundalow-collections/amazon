#!/usr/bin/python
# Copyright: Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['stableinterface'],
                    'supported_by': 'community'}


DOCUMENTATION = '''author: Nick Aslanidis (@naslanidis)
description:
- Creates AWS VPN Virtual Gateways
- Deletes AWS VPN Virtual Gateways
- Attaches Virtual Gateways to VPCs
- Detaches Virtual Gateways from VPCs
extends_documentation_fragment:
- ansible.amazon.ec2
- ansible.amazon.aws
module: ec2_vpc_vgw
options:
  asn:
    description:
    - the BGP ASN of the amazon side
    version_added: '2.6'
  name:
    description:
    - name of the vgw to be created or deleted
  state:
    choices:
    - present
    - absent
    default: present
    description:
    - present to ensure resource is created.
    - absent to remove resource
  tags:
    aliases:
    - resource_tags
    description:
    - dictionary of resource tags
  type:
    choices:
    - ipsec.1
    description:
    - type of the virtual gateway to be created
  vpc_id:
    description:
    - the vpc-id of a vpc to attach or detach
  vpn_gateway_id:
    description:
    - vpn gateway id of an existing virtual gateway
  wait_timeout:
    default: 320
    description:
    - number of seconds to wait for status during vpc attach and detach
requirements:
- boto3
short_description: Create and delete AWS VPN Virtual Gateways.
version_added: '2.2'
'''

EXAMPLES = '''
- name: Create a new vgw attached to a specific VPC
  ec2_vpc_vgw:
    state: present
    region: ap-southeast-2
    profile: personal
    vpc_id: vpc-12345678
    name: personal-testing
    type: ipsec.1
  register: created_vgw

- name: Create a new unattached vgw
  ec2_vpc_vgw:
    state: present
    region: ap-southeast-2
    profile: personal
    name: personal-testing
    type: ipsec.1
    tags:
      environment: production
      owner: ABC
  register: created_vgw

- name: Remove a new vgw using the name
  ec2_vpc_vgw:
    state: absent
    region: ap-southeast-2
    profile: personal
    name: personal-testing
    type: ipsec.1
  register: deleted_vgw

- name: Remove a new vgw using the vpn_gateway_id
  ec2_vpc_vgw:
    state: absent
    region: ap-southeast-2
    profile: personal
    vpn_gateway_id: vgw-3a9aa123
  register: deleted_vgw
'''

RETURN = '''
result:
  description: The result of the create, or delete action.
  returned: success
  type: dict
'''

import time
import traceback

try:
    import botocore
    import boto3
    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False

from ansible_collections.ansible.amazon.plugins.module_utils.aws.core import is_boto3_error_code
from ansible_collections.ansible.amazon.plugins.module_utils.aws.waiters import get_waiter
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.ansible.amazon.plugins.module_utils.ec2 import HAS_BOTO3, boto3_conn, ec2_argument_spec, get_aws_connection_info, AWSRetry
from ansible.module_utils._text import to_native


def get_vgw_info(vgws):
    if not isinstance(vgws, list):
        return

    for vgw in vgws:
        vgw_info = {
            'id': vgw['VpnGatewayId'],
            'type': vgw['Type'],
            'state': vgw['State'],
            'vpc_id': None,
            'tags': dict()
        }

        for tag in vgw['Tags']:
            vgw_info['tags'][tag['Key']] = tag['Value']

        if len(vgw['VpcAttachments']) != 0 and vgw['VpcAttachments'][0]['State'] == 'attached':
            vgw_info['vpc_id'] = vgw['VpcAttachments'][0]['VpcId']

        return vgw_info


def wait_for_status(client, module, vpn_gateway_id, status):
    polling_increment_secs = 15
    max_retries = (module.params.get('wait_timeout') // polling_increment_secs)
    status_achieved = False

    for x in range(0, max_retries):
        try:
            response = find_vgw(client, module, vpn_gateway_id)
            if response[0]['VpcAttachments'][0]['State'] == status:
                status_achieved = True
                break
            else:
                time.sleep(polling_increment_secs)
        except botocore.exceptions.ClientError as e:
            module.fail_json(msg=to_native(e), exception=traceback.format_exc())

    result = response
    return status_achieved, result


def attach_vgw(client, module, vpn_gateway_id):
    params = dict()
    params['VpcId'] = module.params.get('vpc_id')

    try:
        # Immediately after a detachment, the EC2 API sometimes will report the VpnGateways[0].State
        # as available several seconds before actually permitting a new attachment.
        # So we catch and retry that error.  See https://github.com/ansible/ansible/issues/53185
        response = AWSRetry.jittered_backoff(retries=5,
                                             catch_extra_error_codes=['InvalidParameterValue']
                                             )(client.attach_vpn_gateway)(VpnGatewayId=vpn_gateway_id,
                                                                          VpcId=params['VpcId'])
    except botocore.exceptions.ClientError as e:
        module.fail_json(msg=to_native(e), exception=traceback.format_exc())

    status_achieved, vgw = wait_for_status(client, module, [vpn_gateway_id], 'attached')
    if not status_achieved:
        module.fail_json(msg='Error waiting for vpc to attach to vgw - please check the AWS console')

    result = response
    return result


def detach_vgw(client, module, vpn_gateway_id, vpc_id=None):
    params = dict()
    params['VpcId'] = module.params.get('vpc_id')

    if vpc_id:
        try:
            response = client.detach_vpn_gateway(VpnGatewayId=vpn_gateway_id, VpcId=vpc_id)
        except botocore.exceptions.ClientError as e:
            module.fail_json(msg=to_native(e), exception=traceback.format_exc())
    else:
        try:
            response = client.detach_vpn_gateway(VpnGatewayId=vpn_gateway_id, VpcId=params['VpcId'])
        except botocore.exceptions.ClientError as e:
            module.fail_json(msg=to_native(e), exception=traceback.format_exc())

    status_achieved, vgw = wait_for_status(client, module, [vpn_gateway_id], 'detached')
    if not status_achieved:
        module.fail_json(msg='Error waiting for  vpc to detach from vgw - please check the AWS console')

    result = response
    return result


def create_vgw(client, module):
    params = dict()
    params['Type'] = module.params.get('type')
    if module.params.get('asn'):
        params['AmazonSideAsn'] = module.params.get('asn')

    try:
        response = client.create_vpn_gateway(**params)
        get_waiter(
            client, 'vpn_gateway_exists'
        ).wait(
            VpnGatewayIds=[response['VpnGateway']['VpnGatewayId']]
        )
    except botocore.exceptions.WaiterError as e:
        module.fail_json(msg="Failed to wait for Vpn Gateway {0} to be available".format(response['VpnGateway']['VpnGatewayId']),
                         exception=traceback.format_exc())
    except is_boto3_error_code('VpnGatewayLimitExceeded'):
        module.fail_json(msg="Too many VPN gateways exist in this account.", exception=traceback.format_exc())
    except botocore.exceptions.ClientError as e:  # pylint: disable=duplicate-except
        module.fail_json(msg=to_native(e), exception=traceback.format_exc())

    result = response
    return result


def delete_vgw(client, module, vpn_gateway_id):

    try:
        response = client.delete_vpn_gateway(VpnGatewayId=vpn_gateway_id)
    except botocore.exceptions.ClientError as e:
        module.fail_json(msg=to_native(e), exception=traceback.format_exc())

    # return the deleted VpnGatewayId as this is not included in the above response
    result = vpn_gateway_id
    return result


def create_tags(client, module, vpn_gateway_id):
    params = dict()

    try:
        response = client.create_tags(Resources=[vpn_gateway_id], Tags=load_tags(module))
    except botocore.exceptions.ClientError as e:
        module.fail_json(msg=to_native(e), exception=traceback.format_exc())

    result = response
    return result


def delete_tags(client, module, vpn_gateway_id, tags_to_delete=None):
    params = dict()

    if tags_to_delete:
        try:
            response = client.delete_tags(Resources=[vpn_gateway_id], Tags=tags_to_delete)
        except botocore.exceptions.ClientError as e:
            module.fail_json(msg=to_native(e), exception=traceback.format_exc())
    else:
        try:
            response = client.delete_tags(Resources=[vpn_gateway_id])
        except botocore.exceptions.ClientError as e:
            module.fail_json(msg=to_native(e), exception=traceback.format_exc())

    result = response
    return result


def load_tags(module):
    tags = []

    if module.params.get('tags'):
        for name, value in module.params.get('tags').items():
            tags.append({'Key': name, 'Value': str(value)})
        tags.append({'Key': "Name", 'Value': module.params.get('name')})
    else:
        tags.append({'Key': "Name", 'Value': module.params.get('name')})
    return tags


def find_tags(client, module, resource_id=None):

    if resource_id:
        try:
            response = client.describe_tags(Filters=[
                {'Name': 'resource-id', 'Values': [resource_id]}
            ])
        except botocore.exceptions.ClientError as e:
            module.fail_json(msg=to_native(e), exception=traceback.format_exc())

    result = response
    return result


def check_tags(client, module, existing_vgw, vpn_gateway_id):
    params = dict()
    params['Tags'] = module.params.get('tags')
    vgw = existing_vgw
    changed = False
    tags_list = {}

    # format tags for comparison
    for tags in existing_vgw[0]['Tags']:
        if tags['Key'] != 'Name':
            tags_list[tags['Key']] = tags['Value']

    # if existing tags don't match the tags arg, delete existing and recreate with new list
    if params['Tags'] is not None and tags_list != params['Tags']:
        delete_tags(client, module, vpn_gateway_id)
        create_tags(client, module, vpn_gateway_id)
        vgw = find_vgw(client, module)
        changed = True

    # if no tag args are supplied, delete any existing tags with the exception of the name tag
    if params['Tags'] is None and tags_list != {}:
        tags_to_delete = []
        for tags in existing_vgw[0]['Tags']:
            if tags['Key'] != 'Name':
                tags_to_delete.append(tags)

        delete_tags(client, module, vpn_gateway_id, tags_to_delete)
        vgw = find_vgw(client, module)
        changed = True

    return vgw, changed


def find_vpc(client, module):
    params = dict()
    params['vpc_id'] = module.params.get('vpc_id')

    if params['vpc_id']:
        try:
            response = client.describe_vpcs(VpcIds=[params['vpc_id']])
        except botocore.exceptions.ClientError as e:
            module.fail_json(msg=to_native(e), exception=traceback.format_exc())

    result = response
    return result


def find_vgw(client, module, vpn_gateway_id=None):
    params = dict()
    if vpn_gateway_id:
        params['VpnGatewayIds'] = vpn_gateway_id
    else:
        params['Filters'] = [
            {'Name': 'type', 'Values': [module.params.get('type')]},
            {'Name': 'tag:Name', 'Values': [module.params.get('name')]},
        ]
        if module.params.get('state') == 'present':
            params['Filters'].append({'Name': 'state', 'Values': ['pending', 'available']})
    try:
        response = client.describe_vpn_gateways(**params)
    except botocore.exceptions.ClientError as e:
        module.fail_json(msg=to_native(e), exception=traceback.format_exc())

    return sorted(response['VpnGateways'], key=lambda k: k['VpnGatewayId'])


def ensure_vgw_present(client, module):

    # If an existing vgw name and type matches our args, then a match is considered to have been
    # found and we will not create another vgw.

    changed = False
    params = dict()
    result = dict()
    params['Name'] = module.params.get('name')
    params['VpcId'] = module.params.get('vpc_id')
    params['Type'] = module.params.get('type')
    params['Tags'] = module.params.get('tags')
    params['VpnGatewayIds'] = module.params.get('vpn_gateway_id')

    # check that the vpc_id exists. If not, an exception is thrown
    if params['VpcId']:
        vpc = find_vpc(client, module)

    # check if a gateway matching our module args already exists
    existing_vgw = find_vgw(client, module)

    if existing_vgw != []:
        vpn_gateway_id = existing_vgw[0]['VpnGatewayId']
        vgw, changed = check_tags(client, module, existing_vgw, vpn_gateway_id)

        # if a vpc_id was provided, check if it exists and if it's attached
        if params['VpcId']:

            current_vpc_attachments = existing_vgw[0]['VpcAttachments']

            if current_vpc_attachments != [] and current_vpc_attachments[0]['State'] == 'attached':
                if current_vpc_attachments[0]['VpcId'] != params['VpcId'] or current_vpc_attachments[0]['State'] != 'attached':
                    # detach the existing vpc from the virtual gateway
                    vpc_to_detach = current_vpc_attachments[0]['VpcId']
                    detach_vgw(client, module, vpn_gateway_id, vpc_to_detach)
                    get_waiter(client, 'vpn_gateway_detached').wait(VpnGatewayIds=[vpn_gateway_id])
                    attached_vgw = attach_vgw(client, module, vpn_gateway_id)
                    changed = True
            else:
                # attach the vgw to the supplied vpc
                attached_vgw = attach_vgw(client, module, vpn_gateway_id)
                changed = True

        # if params['VpcId'] is not provided, check the vgw is attached to a vpc. if so, detach it.
        else:
            existing_vgw = find_vgw(client, module, [vpn_gateway_id])

            if existing_vgw[0]['VpcAttachments'] != []:
                if existing_vgw[0]['VpcAttachments'][0]['State'] == 'attached':
                    # detach the vpc from the vgw
                    vpc_to_detach = existing_vgw[0]['VpcAttachments'][0]['VpcId']
                    detach_vgw(client, module, vpn_gateway_id, vpc_to_detach)
                    changed = True

    else:
        # create a new vgw
        new_vgw = create_vgw(client, module)
        changed = True
        vpn_gateway_id = new_vgw['VpnGateway']['VpnGatewayId']

        # tag the new virtual gateway
        create_tags(client, module, vpn_gateway_id)

        # if a vpc-id was supplied, attempt to attach it to the vgw
        if params['VpcId']:
            attached_vgw = attach_vgw(client, module, vpn_gateway_id)
            changed = True

    # return current state of the vgw
    vgw = find_vgw(client, module, [vpn_gateway_id])
    result = get_vgw_info(vgw)
    return changed, result


def ensure_vgw_absent(client, module):

    # If an existing vgw name and type matches our args, then a match is considered to have been
    # found and we will take steps to delete it.

    changed = False
    params = dict()
    result = dict()
    params['Name'] = module.params.get('name')
    params['VpcId'] = module.params.get('vpc_id')
    params['Type'] = module.params.get('type')
    params['Tags'] = module.params.get('tags')
    params['VpnGatewayIds'] = module.params.get('vpn_gateway_id')

    # check if a gateway matching our module args already exists
    if params['VpnGatewayIds']:
        existing_vgw_with_id = find_vgw(client, module, [params['VpnGatewayIds']])
        if existing_vgw_with_id != [] and existing_vgw_with_id[0]['State'] != 'deleted':
            existing_vgw = existing_vgw_with_id
            if existing_vgw[0]['VpcAttachments'] != [] and existing_vgw[0]['VpcAttachments'][0]['State'] == 'attached':
                if params['VpcId']:
                    if params['VpcId'] != existing_vgw[0]['VpcAttachments'][0]['VpcId']:
                        module.fail_json(msg='The vpc-id provided does not match the vpc-id currently attached - please check the AWS console')

                    else:
                        # detach the vpc from the vgw
                        detach_vgw(client, module, params['VpnGatewayIds'], params['VpcId'])
                        deleted_vgw = delete_vgw(client, module, params['VpnGatewayIds'])
                        changed = True

                else:
                    # attempt to detach any attached vpcs
                    vpc_to_detach = existing_vgw[0]['VpcAttachments'][0]['VpcId']
                    detach_vgw(client, module, params['VpnGatewayIds'], vpc_to_detach)
                    deleted_vgw = delete_vgw(client, module, params['VpnGatewayIds'])
                    changed = True

            else:
                # no vpc's are attached so attempt to delete the vgw
                deleted_vgw = delete_vgw(client, module, params['VpnGatewayIds'])
                changed = True

        else:
            changed = False
            deleted_vgw = "Nothing to do"

    else:
        # Check that a name and type argument has been supplied if no vgw-id
        if not module.params.get('name') or not module.params.get('type'):
            module.fail_json(msg='A name and type is required when no vgw-id and a status of \'absent\' is supplied')

        existing_vgw = find_vgw(client, module)
        if existing_vgw != [] and existing_vgw[0]['State'] != 'deleted':
            vpn_gateway_id = existing_vgw[0]['VpnGatewayId']
            if existing_vgw[0]['VpcAttachments'] != [] and existing_vgw[0]['VpcAttachments'][0]['State'] == 'attached':
                if params['VpcId']:
                    if params['VpcId'] != existing_vgw[0]['VpcAttachments'][0]['VpcId']:
                        module.fail_json(msg='The vpc-id provided does not match the vpc-id currently attached - please check the AWS console')

                    else:
                        # detach the vpc from the vgw
                        detach_vgw(client, module, vpn_gateway_id, params['VpcId'])

                        # now that the vpc has been detached, delete the vgw
                        deleted_vgw = delete_vgw(client, module, vpn_gateway_id)
                        changed = True

                else:
                    # attempt to detach any attached vpcs
                    vpc_to_detach = existing_vgw[0]['VpcAttachments'][0]['VpcId']
                    detach_vgw(client, module, vpn_gateway_id, vpc_to_detach)
                    changed = True

                    # now that the vpc has been detached, delete the vgw
                    deleted_vgw = delete_vgw(client, module, vpn_gateway_id)

            else:
                # no vpc's are attached so attempt to delete the vgw
                deleted_vgw = delete_vgw(client, module, vpn_gateway_id)
                changed = True

        else:
            changed = False
            deleted_vgw = None

    result = deleted_vgw
    return changed, result


def main():
    argument_spec = ec2_argument_spec()
    argument_spec.update(dict(
        state=dict(default='present', choices=['present', 'absent']),
        region=dict(required=True),
        name=dict(),
        vpn_gateway_id=dict(),
        vpc_id=dict(),
        asn=dict(type='int'),
        wait_timeout=dict(type='int', default=320),
        type=dict(default='ipsec.1', choices=['ipsec.1']),
        tags=dict(default=None, required=False, type='dict', aliases=['resource_tags']),
    )
    )
    module = AnsibleModule(argument_spec=argument_spec,
                           required_if=[['state', 'present', ['name']]])

    if not HAS_BOTO3:
        module.fail_json(msg='json and boto3 is required.')

    state = module.params.get('state').lower()

    try:
        region, ec2_url, aws_connect_kwargs = get_aws_connection_info(module, boto3=True)
        client = boto3_conn(module, conn_type='client', resource='ec2', region=region, endpoint=ec2_url, **aws_connect_kwargs)
    except botocore.exceptions.NoCredentialsError as e:
        module.fail_json(msg="Can't authorize connection - %s" % to_native(e), exception=traceback.format_exc())

    if state == 'present':
        (changed, results) = ensure_vgw_present(client, module)
    else:
        (changed, results) = ensure_vgw_absent(client, module)
    module.exit_json(changed=changed, vgw=results)


if __name__ == '__main__':
    main()
