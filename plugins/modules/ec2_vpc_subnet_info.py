#!/usr/bin/python
#
# This is a free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This Ansible library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this library.  If not, see <http://www.gnu.org/licenses/>.

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['stableinterface'],
                    'supported_by': 'core'}


DOCUMENTATION = '''author: Rob White (@wimnat)
description:
- Gather information about ec2 VPC subnets in AWS
- This module was called C(ec2_vpc_subnet_facts) before Ansible 2.9. The usage did
  not change.
extends_documentation_fragment:
- ansible.amazon.aws
- ansible.amazon.ec2
module: ec2_vpc_subnet_info
options:
  filters:
    description:
    - A dict of filters to apply. Each dict item consists of a filter key and a filter
      value. See U(https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeSubnets.html)
      for possible filters.
  subnet_ids:
    aliases:
    - subnet_id
    description:
    - A list of subnet IDs to gather information for.
    version_added: '2.5'
requirements:
- boto3
- botocore
short_description: Gather information about ec2 VPC subnets in AWS
version_added: '2.1'
'''

EXAMPLES = '''
# Note: These examples do not set authentication details, see the AWS Guide for details.

# Gather information about all VPC subnets
- ec2_vpc_subnet_info:

# Gather information about a particular VPC subnet using ID
- ec2_vpc_subnet_info:
    subnet_ids: subnet-00112233

# Gather information about any VPC subnet with a tag key Name and value Example
- ec2_vpc_subnet_info:
    filters:
      "tag:Name": Example

# Gather information about any VPC subnet within VPC with ID vpc-abcdef00
- ec2_vpc_subnet_info:
    filters:
      vpc-id: vpc-abcdef00

# Gather information about a set of VPC subnets, publicA, publicB and publicC within a
# VPC with ID vpc-abcdef00 and then use the jinja map function to return the
# subnet_ids as a list.

- ec2_vpc_subnet_info:
    filters:
      vpc-id: vpc-abcdef00
      "tag:Name": "{{ item }}"
  loop:
    - publicA
    - publicB
    - publicC
  register: subnet_info

- set_fact:
    subnet_ids: "{{ subnet_info.subnets|map(attribute='id')|list }}"
'''

RETURN = '''
subnets:
    description: Returns an array of complex objects as described below.
    returned: success
    type: complex
    contains:
        subnet_id:
            description: The ID of the Subnet.
            returned: always
            type: str
        id:
            description: The ID of the Subnet (for backwards compatibility).
            returned: always
            type: str
        vpc_id:
            description: The ID of the VPC .
            returned: always
            type: str
        state:
            description: The state of the subnet.
            returned: always
            type: str
        tags:
            description: A dict of tags associated with the Subnet.
            returned: always
            type: dict
        map_public_ip_on_launch:
            description: True/False depending on attribute setting for public IP mapping.
            returned: always
            type: bool
        default_for_az:
            description: True if this is the default subnet for AZ.
            returned: always
            type: bool
        cidr_block:
            description: The IPv4 CIDR block assigned to the subnet.
            returned: always
            type: str
        available_ip_address_count:
            description: Count of available IPs in subnet.
            returned: always
            type: str
        availability_zone:
            description: The availability zone where the subnet exists.
            returned: always
            type: str
        assign_ipv6_address_on_creation:
            description: True/False depending on attribute setting for IPv6 address assignment.
            returned: always
            type: bool
        ipv6_cidr_block_association_set:
            description: An array of IPv6 cidr block association set information.
            returned: always
            type: complex
            contains:
                association_id:
                    description: The association ID
                    returned: always
                    type: str
                ipv6_cidr_block:
                    description: The IPv6 CIDR block that is associated with the subnet.
                    returned: always
                    type: str
                ipv6_cidr_block_state:
                    description: A hash/dict that contains a single item. The state of the cidr block association.
                    returned: always
                    type: dict
                    contains:
                        state:
                            description: The CIDR block association state.
                            returned: always
                            type: str
'''

import traceback
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.ansible.amazon.plugins.module_utils.ec2 import (
    boto3_conn,
    ec2_argument_spec,
    get_aws_connection_info,
    AWSRetry,
    HAS_BOTO3,
    boto3_tag_list_to_ansible_dict,
    camel_dict_to_snake_dict,
    ansible_dict_to_boto3_filter_list
)
from ansible.module_utils._text import to_native

try:
    import botocore
except ImportError:
    pass  # caught by imported HAS_BOTO3


@AWSRetry.exponential_backoff()
def describe_subnets_with_backoff(connection, subnet_ids, filters):
    """
    Describe Subnets with AWSRetry backoff throttling support.

    connection  : boto3 client connection object
    subnet_ids  : list of subnet ids for which to gather information
    filters     : additional filters to apply to request
    """
    return connection.describe_subnets(SubnetIds=subnet_ids, Filters=filters)


def describe_subnets(connection, module):
    """
    Describe Subnets.

    module  : AnsibleModule object
    connection  : boto3 client connection object
    """
    # collect parameters
    filters = ansible_dict_to_boto3_filter_list(module.params.get('filters'))
    subnet_ids = module.params.get('subnet_ids')

    if subnet_ids is None:
        # Set subnet_ids to empty list if it is None
        subnet_ids = []

    # init empty list for return vars
    subnet_info = list()

    # Get the basic VPC info
    try:
        response = describe_subnets_with_backoff(connection, subnet_ids, filters)
    except botocore.exceptions.ClientError as e:
        module.fail_json(msg=to_native(e), exception=traceback.format_exc(), **camel_dict_to_snake_dict(e.response))

    for subnet in response['Subnets']:
        # for backwards compatibility
        subnet['id'] = subnet['SubnetId']
        subnet_info.append(camel_dict_to_snake_dict(subnet))
        # convert tag list to ansible dict
        subnet_info[-1]['tags'] = boto3_tag_list_to_ansible_dict(subnet.get('Tags', []))

    module.exit_json(subnets=subnet_info)


def main():
    argument_spec = ec2_argument_spec()
    argument_spec.update(dict(
        subnet_ids=dict(type='list', default=[], aliases=['subnet_id']),
        filters=dict(type='dict', default={})
    ))

    module = AnsibleModule(argument_spec=argument_spec,
                           supports_check_mode=True)
    if module._name == 'ec2_vpc_subnet_facts':
        module.deprecate("The 'ec2_vpc_subnet_facts' module has been renamed to 'ec2_vpc_subnet_info'", version='2.13')

    if not HAS_BOTO3:
        module.fail_json(msg='boto3 is required for this module')

    region, ec2_url, aws_connect_params = get_aws_connection_info(module, boto3=True)

    if region:
        try:
            connection = boto3_conn(module, conn_type='client', resource='ec2', region=region, endpoint=ec2_url, **aws_connect_params)
        except (botocore.exceptions.NoCredentialsError, botocore.exceptions.ProfileNotFound) as e:
            module.fail_json(msg=to_native(e), exception=traceback.format_exc(), **camel_dict_to_snake_dict(e.response))
    else:
        module.fail_json(msg="Region must be specified")

    describe_subnets(connection, module)


if __name__ == '__main__':
    main()
