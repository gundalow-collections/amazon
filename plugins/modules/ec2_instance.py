#!/usr/bin/python
# Copyright: Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''author:
- Ryan Scott Brown (@ryansb)
description:
- Create and manage AWS EC2 instance
extends_documentation_fragment:
- ansible.amazon.aws
- ansible.amazon.ec2
module: ec2_instance
options:
  availability_zone:
    description:
    - Specify an availability zone to use the default subnet it. Useful if not specifying
      the I(vpc_subnet_id) parameter.
    - If no subnet, ENI, or availability zone is provided, the default subnet in the
      default VPC will be used in the first AZ (alphabetically sorted).
  cpu_credit_specification:
    choices:
    - unlimited
    - standard
    description:
    - For T2 series instances, choose whether to allow increased charges to buy CPU
      credits if the default pool is depleted.
    - Choose I(unlimited) to enable buying additional CPU credits.
  cpu_options:
    description:
    - Reduce the number of vCPU exposed to the instance.
    - Those parameters can only be set at instance launch. The two suboptions threads_per_core
      and core_count are mandatory.
    - See U(https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-optimize-cpu.html)
      for combinations available.
    - Requires botocore >= 1.10.16
    suboptions:
      core_count:
        description:
        - Set the number of core to enable.
        required: true
      threads_per_core:
        choices:
        - 1
        - 2
        description:
        - Select the number of threads per core to enable. Disable or Enable Intel
          HT.
        required: true
    version_added: 2.7
  detailed_monitoring:
    description:
    - Whether to allow detailed cloudwatch metrics to be collected, enabling more
      detailed alerting.
    type: bool
  ebs_optimized:
    description:
    - Whether instance is should use optimized EBS volumes, see U(https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSOptimized.html).
    type: bool
  filters:
    default:
      subnet-id: <provided-or-default subnet>
      tag:Name: <provided-Name-attribute>
    description:
    - A dict of filters to apply when deciding whether existing instances match and
      should be altered. Each dict item consists of a filter key and a filter value.
      See U(https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeInstances.html).
      for possible filters. Filter names and values are case sensitive. By default,
      instances are filtered for counting by their "Name" tag, base AMI, state (running,
      by default), and subnet ID. Any queryable filter can be used. Good candidates
      are specific tags, SSH keys, or security groups.
  image:
    description:
    - An image to use for the instance. The M(ec2_ami_info) module may be used to
      retrieve images. One of I(image) or I(image_id) are required when instance is
      not already present.
    - Complex object containing I(image.id), I(image.ramdisk), and I(image.kernel).
    - I(image.id) is the AMI ID.
    - I(image.ramdisk) overrides the AMI's default ramdisk ID.
    - I(image.kernel) is a string AKI to override the AMI kernel.
  image_id:
    description:
    - I(ami) ID to use for the instance. One of I(image) or I(image_id) are required
      when instance is not already present.
    - This is an alias for I(image.id).
  instance_ids:
    description:
    - If you specify one or more instance IDs, only instances that have the specified
      IDs are returned.
  instance_initiated_shutdown_behavior:
    choices:
    - stop
    - terminate
    description:
    - Whether to stop or terminate an instance upon shutdown.
  instance_role:
    description:
    - The ARN or name of an EC2-enabled instance role to be used. If a name is not
      provided in arn format then the ListInstanceProfiles permission must also be
      granted. U(https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListInstanceProfiles.html)
      If no full ARN is provided, the role with a matching name will be used from
      the active AWS account.
  instance_type:
    default: t2.micro
    description:
    - Instance type to use for the instance, see U(https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-types.html)
      Only required when instance is not already present.
  key_name:
    description:
    - Name of the SSH access key to assign to the instance - must exist in the region
      the instance is created.
  launch_template:
    description:
    - The EC2 launch template to base instance configuration on.
    - I(launch_template.id) the ID or the launch template (optional if name is specified).
    - I(launch_template.name) the pretty name of the launch template (optional if
      id is specified).
    - I(launch_template.version) the specific version of the launch template to use.
      If unspecified, the template default is chosen.
  name:
    description:
    - The Name tag for the instance.
  network:
    description:
    - Either a dictionary containing the key 'interfaces' corresponding to a list
      of network interface IDs or containing specifications for a single network interface.
    - If specifications for a single network are given, accepted keys are assign_public_ip
      (bool), private_ip_address (str), ipv6_addresses (list), source_dest_check (bool),
      description (str), delete_on_termination (bool), device_index (int), groups
      (list of security group IDs), private_ip_addresses (list), subnet_id (str).
    - I(network.interfaces) should be a list of ENI IDs (strings) or a list of objects
      containing the key I(id).
    - Use the ec2_eni to create ENIs with special settings.
  placement_group:
    description:
    - The placement group that needs to be assigned to the instance
    version_added: 2.8
  purge_tags:
    default: false
    description:
    - Delete any tags not specified in the task that are on the instance. This means
      you have to specify all the desired tags on each task affecting an instance.
    type: bool
  security_group:
    description:
    - A security group ID or name. Mutually exclusive with I(security_groups).
  security_groups:
    description:
    - A list of security group IDs or names (strings). Mutually exclusive with I(security_group).
  state:
    choices:
    - present
    - terminated
    - running
    - started
    - stopped
    - restarted
    - rebooted
    - absent
    default: present
    description:
    - Goal state for the instances.
  tags:
    description:
    - A hash/dictionary of tags to add to the new instance or to add/remove from an
      existing one.
  tenancy:
    choices:
    - dedicated
    - default
    description:
    - What type of tenancy to allow an instance to use. Default is shared tenancy.
      Dedicated tenancy will incur additional charges.
  termination_protection:
    description:
    - Whether to enable termination protection. This module will not terminate an
      instance with termination protection active, it must be turned off first.
    type: bool
  tower_callback:
    description:
    - Preconfigured user-data to enable an instance to perform a Tower callback (Linux
      only).
    - Mutually exclusive with I(user_data).
    - For Windows instances, to enable remote access via Ansible set I(tower_callback.windows)
      to true, and optionally set an admin password.
    - If using 'windows' and 'set_password', callback to Tower will not be performed
      but the instance will be ready to receive winrm connections from Ansible.
    suboptions:
      host_config_key:
        description:
        - Host configuration secret key generated by the Tower job template.
      job_template_id:
        description:
        - Either the integer ID of the Tower Job Template, or the name (name supported
          only for Tower 3.2+).
      tower_address:
        description:
        - IP address or DNS name of Tower server. Must be accessible via this address
          from the VPC that this instance will be launched in.
  user_data:
    description:
    - Opaque blob of data which is made available to the ec2 instance
  volumes:
    description:
    - A list of block device mappings, by default this will always use the AMI root
      device so the volumes option is primarily for adding more storage.
    - A mapping contains the (optional) keys device_name, virtual_name, ebs.volume_type,
      ebs.volume_size, ebs.kms_key_id, ebs.iops, and ebs.delete_on_termination.
    - For more information about each parameter, see U(https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_BlockDeviceMapping.html).
  vpc_subnet_id:
    aliases:
    - subnet_id
    description:
    - The subnet ID in which to launch the instance (VPC) If none is provided, ec2_instance
      will chose the default zone of the default VPC.
  wait:
    default: true
    description:
    - Whether or not to wait for the desired state (use wait_timeout to customize
      this).
    type: bool
  wait_timeout:
    default: 600
    description:
    - How long to wait (in seconds) for the instance to finish booting/terminating.
requirements:
- boto3
- botocore
short_description: Create & manage EC2 instances
version_added: '2.5'
'''

EXAMPLES = '''
# Note: These examples do not set authentication details, see the AWS Guide for details.

# Terminate every running instance in a region. Use with EXTREME caution.
- ec2_instance:
    state: absent
    filters:
      instance-state-name: running

# restart a particular instance by its ID
- ec2_instance:
    state: restarted
    instance_ids:
      - i-12345678

# start an instance with a public IP address
- ec2_instance:
    name: "public-compute-instance"
    key_name: "prod-ssh-key"
    vpc_subnet_id: subnet-5ca1ab1e
    instance_type: c5.large
    security_group: default
    network:
      assign_public_ip: true
    image_id: ami-123456
    tags:
      Environment: Testing

# start an instance and Add EBS
- ec2_instance:
    name: "public-withebs-instance"
    vpc_subnet_id: subnet-5ca1ab1e
    instance_type: t2.micro
    key_name: "prod-ssh-key"
    security_group: default
    volumes:
      - device_name: /dev/sda1
        ebs:
          volume_size: 16
          delete_on_termination: true

# start an instance with a cpu_options
- ec2_instance:
    name: "public-cpuoption-instance"
    vpc_subnet_id: subnet-5ca1ab1e
    tags:
      Environment: Testing
    instance_type: c4.large
    volumes:
    - device_name: /dev/sda1
      ebs:
        delete_on_termination: true
    cpu_options:
        core_count: 1
        threads_per_core: 1

# start an instance and have it begin a Tower callback on boot
- ec2_instance:
    name: "tower-callback-test"
    key_name: "prod-ssh-key"
    vpc_subnet_id: subnet-5ca1ab1e
    security_group: default
    tower_callback:
      # IP or hostname of tower server
      tower_address: 1.2.3.4
      job_template_id: 876
      host_config_key: '[secret config key goes here]'
    network:
      assign_public_ip: true
    image_id: ami-123456
    cpu_credit_specification: unlimited
    tags:
      SomeThing: "A value"

# start an instance with ENI (An existing ENI ID is required)
- ec2_instance:
    name: "public-eni-instance"
    key_name: "prod-ssh-key"
    vpc_subnet_id: subnet-5ca1ab1e
    network:
      interfaces:
        - id: "eni-12345"
    tags:
      Env: "eni_on"
    volumes:
    - device_name: /dev/sda1
      ebs:
        delete_on_termination: true
    instance_type: t2.micro
    image_id: ami-123456

# add second ENI interface
- ec2_instance:
    name: "public-eni-instance"
    network:
      interfaces:
        - id: "eni-12345"
        - id: "eni-67890"
    image_id: ami-123456
    tags:
      Env: "eni_on"
    instance_type: t2.micro
'''

RETURN = '''
instances:
    description: a list of ec2 instances
    returned: when wait == true
    type: complex
    contains:
        ami_launch_index:
            description: The AMI launch index, which can be used to find this instance in the launch group.
            returned: always
            type: int
            sample: 0
        architecture:
            description: The architecture of the image
            returned: always
            type: str
            sample: x86_64
        block_device_mappings:
            description: Any block device mapping entries for the instance.
            returned: always
            type: complex
            contains:
                device_name:
                    description: The device name exposed to the instance (for example, /dev/sdh or xvdh).
                    returned: always
                    type: str
                    sample: /dev/sdh
                ebs:
                    description: Parameters used to automatically set up EBS volumes when the instance is launched.
                    returned: always
                    type: complex
                    contains:
                        attach_time:
                            description: The time stamp when the attachment initiated.
                            returned: always
                            type: str
                            sample: "2017-03-23T22:51:24+00:00"
                        delete_on_termination:
                            description: Indicates whether the volume is deleted on instance termination.
                            returned: always
                            type: bool
                            sample: true
                        status:
                            description: The attachment state.
                            returned: always
                            type: str
                            sample: attached
                        volume_id:
                            description: The ID of the EBS volume
                            returned: always
                            type: str
                            sample: vol-12345678
        client_token:
            description: The idempotency token you provided when you launched the instance, if applicable.
            returned: always
            type: str
            sample: mytoken
        ebs_optimized:
            description: Indicates whether the instance is optimized for EBS I/O.
            returned: always
            type: bool
            sample: false
        hypervisor:
            description: The hypervisor type of the instance.
            returned: always
            type: str
            sample: xen
        iam_instance_profile:
            description: The IAM instance profile associated with the instance, if applicable.
            returned: always
            type: complex
            contains:
                arn:
                    description: The Amazon Resource Name (ARN) of the instance profile.
                    returned: always
                    type: str
                    sample: "arn:aws:iam::000012345678:instance-profile/myprofile"
                id:
                    description: The ID of the instance profile
                    returned: always
                    type: str
                    sample: JFJ397FDG400FG9FD1N
        image_id:
            description: The ID of the AMI used to launch the instance.
            returned: always
            type: str
            sample: ami-0011223344
        instance_id:
            description: The ID of the instance.
            returned: always
            type: str
            sample: i-012345678
        instance_type:
            description: The instance type size of the running instance.
            returned: always
            type: str
            sample: t2.micro
        key_name:
            description: The name of the key pair, if this instance was launched with an associated key pair.
            returned: always
            type: str
            sample: my-key
        launch_time:
            description: The time the instance was launched.
            returned: always
            type: str
            sample: "2017-03-23T22:51:24+00:00"
        monitoring:
            description: The monitoring for the instance.
            returned: always
            type: complex
            contains:
                state:
                    description: Indicates whether detailed monitoring is enabled. Otherwise, basic monitoring is enabled.
                    returned: always
                    type: str
                    sample: disabled
        network_interfaces:
            description: One or more network interfaces for the instance.
            returned: always
            type: complex
            contains:
                association:
                    description: The association information for an Elastic IPv4 associated with the network interface.
                    returned: always
                    type: complex
                    contains:
                        ip_owner_id:
                            description: The ID of the owner of the Elastic IP address.
                            returned: always
                            type: str
                            sample: amazon
                        public_dns_name:
                            description: The public DNS name.
                            returned: always
                            type: str
                            sample: ""
                        public_ip:
                            description: The public IP address or Elastic IP address bound to the network interface.
                            returned: always
                            type: str
                            sample: 1.2.3.4
                attachment:
                    description: The network interface attachment.
                    returned: always
                    type: complex
                    contains:
                        attach_time:
                            description: The time stamp when the attachment initiated.
                            returned: always
                            type: str
                            sample: "2017-03-23T22:51:24+00:00"
                        attachment_id:
                            description: The ID of the network interface attachment.
                            returned: always
                            type: str
                            sample: eni-attach-3aff3f
                        delete_on_termination:
                            description: Indicates whether the network interface is deleted when the instance is terminated.
                            returned: always
                            type: bool
                            sample: true
                        device_index:
                            description: The index of the device on the instance for the network interface attachment.
                            returned: always
                            type: int
                            sample: 0
                        status:
                            description: The attachment state.
                            returned: always
                            type: str
                            sample: attached
                description:
                    description: The description.
                    returned: always
                    type: str
                    sample: My interface
                groups:
                    description: One or more security groups.
                    returned: always
                    type: complex
                    contains:
                        - group_id:
                              description: The ID of the security group.
                              returned: always
                              type: str
                              sample: sg-abcdef12
                          group_name:
                              description: The name of the security group.
                              returned: always
                              type: str
                              sample: mygroup
                ipv6_addresses:
                    description: One or more IPv6 addresses associated with the network interface.
                    returned: always
                    type: complex
                    contains:
                        - ipv6_address:
                              description: The IPv6 address.
                              returned: always
                              type: str
                              sample: "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
                mac_address:
                    description: The MAC address.
                    returned: always
                    type: str
                    sample: "00:11:22:33:44:55"
                network_interface_id:
                    description: The ID of the network interface.
                    returned: always
                    type: str
                    sample: eni-01234567
                owner_id:
                    description: The AWS account ID of the owner of the network interface.
                    returned: always
                    type: str
                    sample: 01234567890
                private_ip_address:
                    description: The IPv4 address of the network interface within the subnet.
                    returned: always
                    type: str
                    sample: 10.0.0.1
                private_ip_addresses:
                    description: The private IPv4 addresses associated with the network interface.
                    returned: always
                    type: complex
                    contains:
                        - association:
                              description: The association information for an Elastic IP address (IPv4) associated with the network interface.
                              returned: always
                              type: complex
                              contains:
                                  ip_owner_id:
                                      description: The ID of the owner of the Elastic IP address.
                                      returned: always
                                      type: str
                                      sample: amazon
                                  public_dns_name:
                                      description: The public DNS name.
                                      returned: always
                                      type: str
                                      sample: ""
                                  public_ip:
                                      description: The public IP address or Elastic IP address bound to the network interface.
                                      returned: always
                                      type: str
                                      sample: 1.2.3.4
                          primary:
                              description: Indicates whether this IPv4 address is the primary private IP address of the network interface.
                              returned: always
                              type: bool
                              sample: true
                          private_ip_address:
                              description: The private IPv4 address of the network interface.
                              returned: always
                              type: str
                              sample: 10.0.0.1
                source_dest_check:
                    description: Indicates whether source/destination checking is enabled.
                    returned: always
                    type: bool
                    sample: true
                status:
                    description: The status of the network interface.
                    returned: always
                    type: str
                    sample: in-use
                subnet_id:
                    description: The ID of the subnet for the network interface.
                    returned: always
                    type: str
                    sample: subnet-0123456
                vpc_id:
                    description: The ID of the VPC for the network interface.
                    returned: always
                    type: str
                    sample: vpc-0123456
        placement:
            description: The location where the instance launched, if applicable.
            returned: always
            type: complex
            contains:
                availability_zone:
                    description: The Availability Zone of the instance.
                    returned: always
                    type: str
                    sample: ap-southeast-2a
                group_name:
                    description: The name of the placement group the instance is in (for cluster compute instances).
                    returned: always
                    type: str
                    sample: ""
                tenancy:
                    description: The tenancy of the instance (if the instance is running in a VPC).
                    returned: always
                    type: str
                    sample: default
        private_dns_name:
            description: The private DNS name.
            returned: always
            type: str
            sample: ip-10-0-0-1.ap-southeast-2.compute.internal
        private_ip_address:
            description: The IPv4 address of the network interface within the subnet.
            returned: always
            type: str
            sample: 10.0.0.1
        product_codes:
            description: One or more product codes.
            returned: always
            type: complex
            contains:
                - product_code_id:
                      description: The product code.
                      returned: always
                      type: str
                      sample: aw0evgkw8ef3n2498gndfgasdfsd5cce
                  product_code_type:
                      description: The type of product code.
                      returned: always
                      type: str
                      sample: marketplace
        public_dns_name:
            description: The public DNS name assigned to the instance.
            returned: always
            type: str
            sample:
        public_ip_address:
            description: The public IPv4 address assigned to the instance
            returned: always
            type: str
            sample: 52.0.0.1
        root_device_name:
            description: The device name of the root device
            returned: always
            type: str
            sample: /dev/sda1
        root_device_type:
            description: The type of root device used by the AMI.
            returned: always
            type: str
            sample: ebs
        security_groups:
            description: One or more security groups for the instance.
            returned: always
            type: complex
            contains:
                - group_id:
                      description: The ID of the security group.
                      returned: always
                      type: str
                      sample: sg-0123456
                - group_name:
                      description: The name of the security group.
                      returned: always
                      type: str
                      sample: my-security-group
        network.source_dest_check:
            description: Indicates whether source/destination checking is enabled.
            returned: always
            type: bool
            sample: true
        state:
            description: The current state of the instance.
            returned: always
            type: complex
            contains:
                code:
                    description: The low byte represents the state.
                    returned: always
                    type: int
                    sample: 16
                name:
                    description: The name of the state.
                    returned: always
                    type: str
                    sample: running
        state_transition_reason:
            description: The reason for the most recent state transition.
            returned: always
            type: str
            sample:
        subnet_id:
            description: The ID of the subnet in which the instance is running.
            returned: always
            type: str
            sample: subnet-00abcdef
        tags:
            description: Any tags assigned to the instance.
            returned: always
            type: dict
            sample:
        virtualization_type:
            description: The type of virtualization of the AMI.
            returned: always
            type: str
            sample: hvm
        vpc_id:
            description: The ID of the VPC the instance is in.
            returned: always
            type: dict
            sample: vpc-0011223344
'''

import re
import uuid
import string
import textwrap
import time
from collections import namedtuple

try:
    import boto3
    import botocore.exceptions
except ImportError:
    pass

from ansible.module_utils.six import text_type, string_types
from ansible.module_utils.six.moves.urllib import parse as urlparse
from ansible.module_utils._text import to_bytes, to_native
import ansible_collections.ansible.amazon.plugins.module_utils.ec2 as ec2_utils
from ansible_collections.ansible.amazon.plugins.module_utils.ec2 import (boto3_conn,
                                      ec2_argument_spec,
                                      get_aws_connection_info,
                                      AWSRetry,
                                      ansible_dict_to_boto3_filter_list,
                                      compare_aws_tags,
                                      boto3_tag_list_to_ansible_dict,
                                      ansible_dict_to_boto3_tag_list,
                                      camel_dict_to_snake_dict)

from ansible_collections.ansible.amazon.plugins.module_utils.aws.core import AnsibleAWSModule

module = None


def tower_callback_script(tower_conf, windows=False, passwd=None):
    script_url = 'https://raw.githubusercontent.com/ansible/ansible/devel/examples/scripts/ConfigureRemotingForAnsible.ps1'
    if windows and passwd is not None:
        script_tpl = """<powershell>
        $admin = [adsi]("WinNT://./administrator, user")
        $admin.PSBase.Invoke("SetPassword", "{PASS}")
        Invoke-Expression ((New-Object System.Net.Webclient).DownloadString('{SCRIPT}'))
        </powershell>
        """
        return to_native(textwrap.dedent(script_tpl).format(PASS=passwd, SCRIPT=script_url))
    elif windows and passwd is None:
        script_tpl = """<powershell>
        $admin = [adsi]("WinNT://./administrator, user")
        Invoke-Expression ((New-Object System.Net.Webclient).DownloadString('{SCRIPT}'))
        </powershell>
        """
        return to_native(textwrap.dedent(script_tpl).format(PASS=passwd, SCRIPT=script_url))
    elif not windows:
        for p in ['tower_address', 'job_template_id', 'host_config_key']:
            if p not in tower_conf:
                module.fail_json(msg="Incomplete tower_callback configuration. tower_callback.{0} not set.".format(p))

        if isinstance(tower_conf['job_template_id'], string_types):
            tower_conf['job_template_id'] = urlparse.quote(tower_conf['job_template_id'])
        tpl = string.Template(textwrap.dedent("""#!/bin/bash
        set -x

        retry_attempts=10
        attempt=0
        while [[ $attempt -lt $retry_attempts ]]
        do
          status_code=`curl --max-time 10 -v -k -s -i \
            --data "host_config_key=${host_config_key}" \
            'https://${tower_address}/api/v2/job_templates/${template_id}/callback/' \
            | head -n 1 \
            | awk '{print $2}'`
          if [[ $status_code == 404 ]]
            then
            status_code=`curl --max-time 10 -v -k -s -i \
              --data "host_config_key=${host_config_key}" \
              'https://${tower_address}/api/v1/job_templates/${template_id}/callback/' \
              | head -n 1 \
              | awk '{print $2}'`
            # fall back to using V1 API for Tower 3.1 and below, since v2 API will always 404
          fi
          if [[ $status_code == 201 ]]
            then
            exit 0
          fi
          attempt=$(( attempt + 1 ))
          echo "$${status_code} received... retrying in 1 minute. (Attempt $${attempt})"
          sleep 60
        done
        exit 1
        """))
        return tpl.safe_substitute(tower_address=tower_conf['tower_address'],
                                   template_id=tower_conf['job_template_id'],
                                   host_config_key=tower_conf['host_config_key'])
    raise NotImplementedError("Only windows with remote-prep or non-windows with tower job callback supported so far.")


@AWSRetry.jittered_backoff()
def manage_tags(match, new_tags, purge_tags, ec2):
    changed = False
    old_tags = boto3_tag_list_to_ansible_dict(match['Tags'])
    tags_to_set, tags_to_delete = compare_aws_tags(
        old_tags, new_tags,
        purge_tags=purge_tags,
    )
    if tags_to_set:
        ec2.create_tags(
            Resources=[match['InstanceId']],
            Tags=ansible_dict_to_boto3_tag_list(tags_to_set))
        changed |= True
    if tags_to_delete:
        delete_with_current_values = dict((k, old_tags.get(k)) for k in tags_to_delete)
        ec2.delete_tags(
            Resources=[match['InstanceId']],
            Tags=ansible_dict_to_boto3_tag_list(delete_with_current_values))
        changed |= True
    return changed


def build_volume_spec(params):
    volumes = params.get('volumes') or []
    for volume in volumes:
        if 'ebs' in volume:
            for int_value in ['volume_size', 'iops']:
                if int_value in volume['ebs']:
                    volume['ebs'][int_value] = int(volume['ebs'][int_value])
    return [ec2_utils.snake_dict_to_camel_dict(v, capitalize_first=True) for v in volumes]


def add_or_update_instance_profile(instance, desired_profile_name):
    instance_profile_setting = instance.get('IamInstanceProfile')
    if instance_profile_setting and desired_profile_name:
        if desired_profile_name in (instance_profile_setting.get('Name'), instance_profile_setting.get('Arn')):
            # great, the profile we asked for is what's there
            return False
        else:
            desired_arn = determine_iam_role(desired_profile_name)
            if instance_profile_setting.get('Arn') == desired_arn:
                return False
        # update association
        ec2 = module.client('ec2')
        try:
            association = ec2.describe_iam_instance_profile_associations(Filters=[{'Name': 'instance-id', 'Values': [instance['InstanceId']]}])
        except botocore.exceptions.ClientError as e:
            # check for InvalidAssociationID.NotFound
            module.fail_json_aws(e, "Could not find instance profile association")
        try:
            resp = ec2.replace_iam_instance_profile_association(
                AssociationId=association['IamInstanceProfileAssociations'][0]['AssociationId'],
                IamInstanceProfile={'Arn': determine_iam_role(desired_profile_name)}
            )
            return True
        except botocore.exceptions.ClientError as e:
            module.fail_json_aws(e, "Could not associate instance profile")

    if not instance_profile_setting and desired_profile_name:
        # create association
        ec2 = module.client('ec2')
        try:
            resp = ec2.associate_iam_instance_profile(
                IamInstanceProfile={'Arn': determine_iam_role(desired_profile_name)},
                InstanceId=instance['InstanceId']
            )
            return True
        except botocore.exceptions.ClientError as e:
            module.fail_json_aws(e, "Could not associate new instance profile")

    return False


def build_network_spec(params, ec2=None):
    """
    Returns list of interfaces [complex]
    Interface type: {
        'AssociatePublicIpAddress': True|False,
        'DeleteOnTermination': True|False,
        'Description': 'string',
        'DeviceIndex': 123,
        'Groups': [
            'string',
        ],
        'Ipv6AddressCount': 123,
        'Ipv6Addresses': [
            {
                'Ipv6Address': 'string'
            },
        ],
        'NetworkInterfaceId': 'string',
        'PrivateIpAddress': 'string',
        'PrivateIpAddresses': [
            {
                'Primary': True|False,
                'PrivateIpAddress': 'string'
            },
        ],
        'SecondaryPrivateIpAddressCount': 123,
        'SubnetId': 'string'
    },
    """
    if ec2 is None:
        ec2 = module.client('ec2')

    interfaces = []
    network = params.get('network') or {}
    if not network.get('interfaces'):
        # they only specified one interface
        spec = {
            'DeviceIndex': 0,
        }
        if network.get('assign_public_ip') is not None:
            spec['AssociatePublicIpAddress'] = network['assign_public_ip']

        if params.get('vpc_subnet_id'):
            spec['SubnetId'] = params['vpc_subnet_id']
        else:
            default_vpc = get_default_vpc(ec2)
            if default_vpc is None:
                raise module.fail_json(
                    msg="No default subnet could be found - you must include a VPC subnet ID (vpc_subnet_id parameter) to create an instance")
            else:
                sub = get_default_subnet(ec2, default_vpc)
                spec['SubnetId'] = sub['SubnetId']

        if network.get('private_ip_address'):
            spec['PrivateIpAddress'] = network['private_ip_address']

        if params.get('security_group') or params.get('security_groups'):
            groups = discover_security_groups(
                group=params.get('security_group'),
                groups=params.get('security_groups'),
                subnet_id=spec['SubnetId'],
                ec2=ec2
            )
            spec['Groups'] = [g['GroupId'] for g in groups]
        if network.get('description') is not None:
            spec['Description'] = network['description']
        # TODO more special snowflake network things

        return [spec]

    # handle list of `network.interfaces` options
    for idx, interface_params in enumerate(network.get('interfaces', [])):
        spec = {
            'DeviceIndex': idx,
        }

        if isinstance(interface_params, string_types):
            # naive case where user gave
            # network_interfaces: [eni-1234, eni-4567, ....]
            # put into normal data structure so we don't dupe code
            interface_params = {'id': interface_params}

        if interface_params.get('id') is not None:
            # if an ID is provided, we don't want to set any other parameters.
            spec['NetworkInterfaceId'] = interface_params['id']
            interfaces.append(spec)
            continue

        spec['DeleteOnTermination'] = interface_params.get('delete_on_termination', True)

        if interface_params.get('ipv6_addresses'):
            spec['Ipv6Addresses'] = [{'Ipv6Address': a} for a in interface_params.get('ipv6_addresses', [])]

        if interface_params.get('private_ip_address'):
            spec['PrivateIpAddress'] = interface_params.get('private_ip_address')

        if interface_params.get('description'):
            spec['Description'] = interface_params.get('description')

        if interface_params.get('subnet_id', params.get('vpc_subnet_id')):
            spec['SubnetId'] = interface_params.get('subnet_id', params.get('vpc_subnet_id'))
        elif not spec.get('SubnetId') and not interface_params['id']:
            # TODO grab a subnet from default VPC
            raise ValueError('Failed to assign subnet to interface {0}'.format(interface_params))

        interfaces.append(spec)
    return interfaces


def warn_if_public_ip_assignment_changed(instance):
    # This is a non-modifiable attribute.
    assign_public_ip = (module.params.get('network') or {}).get('assign_public_ip')
    if assign_public_ip is None:
        return

    # Check that public ip assignment is the same and warn if not
    public_dns_name = instance.get('PublicDnsName')
    if (public_dns_name and not assign_public_ip) or (assign_public_ip and not public_dns_name):
        module.warn(
            "Unable to modify public ip assignment to {0} for instance {1}. "
            "Whether or not to assign a public IP is determined during instance creation.".format(
                assign_public_ip, instance['InstanceId']))


def warn_if_cpu_options_changed(instance):
    # This is a non-modifiable attribute.
    cpu_options = module.params.get('cpu_options')
    if cpu_options is None:
        return

    # Check that the CpuOptions set are the same and warn if not
    core_count_curr = instance['CpuOptions'].get('CoreCount')
    core_count = cpu_options.get('core_count')
    threads_per_core_curr = instance['CpuOptions'].get('ThreadsPerCore')
    threads_per_core = cpu_options.get('threads_per_core')
    if core_count_curr != core_count:
        module.warn(
            "Unable to modify core_count from {0} to {1}. "
            "Assigning a number of core is determinted during instance creation".format(
                core_count_curr, core_count))

    if threads_per_core_curr != threads_per_core:
        module.warn(
            "Unable to modify threads_per_core from {0} to {1}. "
            "Assigning a number of threads per core is determined during instance creation.".format(
                threads_per_core_curr, threads_per_core))


def discover_security_groups(group, groups, parent_vpc_id=None, subnet_id=None, ec2=None):
    if ec2 is None:
        ec2 = module.client('ec2')

    if subnet_id is not None:
        try:
            sub = ec2.describe_subnets(SubnetIds=[subnet_id])
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'InvalidGroup.NotFound':
                module.fail_json(
                    "Could not find subnet {0} to associate security groups. Please check the vpc_subnet_id and security_groups parameters.".format(
                        subnet_id
                    )
                )
            module.fail_json_aws(e, msg="Error while searching for subnet {0} parent VPC.".format(subnet_id))
        except botocore.exceptions.BotoCoreError as e:
            module.fail_json_aws(e, msg="Error while searching for subnet {0} parent VPC.".format(subnet_id))
        parent_vpc_id = sub['Subnets'][0]['VpcId']

    vpc = {
        'Name': 'vpc-id',
        'Values': [parent_vpc_id]
    }

    # because filter lists are AND in the security groups API,
    # make two separate requests for groups by ID and by name
    id_filters = [vpc]
    name_filters = [vpc]

    if group:
        name_filters.append(
            dict(
                Name='group-name',
                Values=[group]
            )
        )
        if group.startswith('sg-'):
            id_filters.append(
                dict(
                    Name='group-id',
                    Values=[group]
                )
            )
    if groups:
        name_filters.append(
            dict(
                Name='group-name',
                Values=groups
            )
        )
        if [g for g in groups if g.startswith('sg-')]:
            id_filters.append(
                dict(
                    Name='group-id',
                    Values=[g for g in groups if g.startswith('sg-')]
                )
            )

    found_groups = []
    for f_set in (id_filters, name_filters):
        if len(f_set) > 1:
            found_groups.extend(ec2.get_paginator(
                'describe_security_groups'
            ).paginate(
                Filters=f_set
            ).search('SecurityGroups[]'))
    return list(dict((g['GroupId'], g) for g in found_groups).values())


def build_top_level_options(params):
    spec = {}
    if params.get('image_id'):
        spec['ImageId'] = params['image_id']
    elif isinstance(params.get('image'), dict):
        image = params.get('image', {})
        spec['ImageId'] = image.get('id')
        if 'ramdisk' in image:
            spec['RamdiskId'] = image['ramdisk']
        if 'kernel' in image:
            spec['KernelId'] = image['kernel']
    if not spec.get('ImageId') and not params.get('launch_template'):
        module.fail_json(msg="You must include an image_id or image.id parameter to create an instance, or use a launch_template.")

    if params.get('key_name') is not None:
        spec['KeyName'] = params.get('key_name')
    if params.get('user_data') is not None:
        spec['UserData'] = to_native(params.get('user_data'))
    elif params.get('tower_callback') is not None:
        spec['UserData'] = tower_callback_script(
            tower_conf=params.get('tower_callback'),
            windows=params.get('tower_callback').get('windows', False),
            passwd=params.get('tower_callback').get('set_password'),
        )

    if params.get('launch_template') is not None:
        spec['LaunchTemplate'] = {}
        if not params.get('launch_template').get('id') or params.get('launch_template').get('name'):
            module.fail_json(msg="Could not create instance with launch template. Either launch_template.name or launch_template.id parameters are required")

        if params.get('launch_template').get('id') is not None:
            spec['LaunchTemplate']['LaunchTemplateId'] = params.get('launch_template').get('id')
        if params.get('launch_template').get('name') is not None:
            spec['LaunchTemplate']['LaunchTemplateName'] = params.get('launch_template').get('name')
        if params.get('launch_template').get('version') is not None:
            spec['LaunchTemplate']['Version'] = to_native(params.get('launch_template').get('version'))

    if params.get('detailed_monitoring', False):
        spec['Monitoring'] = {'Enabled': True}
    if params.get('cpu_credit_specification') is not None:
        spec['CreditSpecification'] = {'CpuCredits': params.get('cpu_credit_specification')}
    if params.get('tenancy') is not None:
        spec['Placement'] = {'Tenancy': params.get('tenancy')}
    if params.get('placement_group'):
        spec.setdefault('Placement', {'GroupName': str(params.get('placement_group'))})
    if params.get('ebs_optimized') is not None:
        spec['EbsOptimized'] = params.get('ebs_optimized')
    if params.get('instance_initiated_shutdown_behavior'):
        spec['InstanceInitiatedShutdownBehavior'] = params.get('instance_initiated_shutdown_behavior')
    if params.get('termination_protection') is not None:
        spec['DisableApiTermination'] = params.get('termination_protection')
    if params.get('cpu_options') is not None:
        spec['CpuOptions'] = {}
        spec['CpuOptions']['ThreadsPerCore'] = params.get('cpu_options').get('threads_per_core')
        spec['CpuOptions']['CoreCount'] = params.get('cpu_options').get('core_count')
    return spec


def build_instance_tags(params, propagate_tags_to_volumes=True):
    tags = params.get('tags', {})
    if params.get('name') is not None:
        if tags is None:
            tags = {}
        tags['Name'] = params.get('name')
    return [
        {
            'ResourceType': 'volume',
            'Tags': ansible_dict_to_boto3_tag_list(tags),
        },
        {
            'ResourceType': 'instance',
            'Tags': ansible_dict_to_boto3_tag_list(tags),
        },
    ]


def build_run_instance_spec(params, ec2=None):
    if ec2 is None:
        ec2 = module.client('ec2')

    spec = dict(
        ClientToken=uuid.uuid4().hex,
        MaxCount=1,
        MinCount=1,
    )
    # network parameters
    spec['NetworkInterfaces'] = build_network_spec(params, ec2)
    spec['BlockDeviceMappings'] = build_volume_spec(params)
    spec.update(**build_top_level_options(params))
    spec['TagSpecifications'] = build_instance_tags(params)

    # IAM profile
    if params.get('instance_role'):
        spec['IamInstanceProfile'] = dict(Arn=determine_iam_role(params.get('instance_role')))

    spec['InstanceType'] = params['instance_type']
    return spec


def await_instances(ids, state='OK'):
    if not module.params.get('wait', True):
        # the user asked not to wait for anything
        return

    if module.check_mode:
        # In check mode, there is no change even if you wait.
        return

    state_opts = {
        'OK': 'instance_status_ok',
        'STOPPED': 'instance_stopped',
        'TERMINATED': 'instance_terminated',
        'EXISTS': 'instance_exists',
        'RUNNING': 'instance_running',
    }
    if state not in state_opts:
        module.fail_json(msg="Cannot wait for state {0}, invalid state".format(state))
    waiter = module.client('ec2').get_waiter(state_opts[state])
    try:
        waiter.wait(
            InstanceIds=ids,
            WaiterConfig={
                'Delay': 15,
                'MaxAttempts': module.params.get('wait_timeout', 600) // 15,
            }
        )
    except botocore.exceptions.WaiterConfigError as e:
        module.fail_json(msg="{0}. Error waiting for instances {1} to reach state {2}".format(
            to_native(e), ', '.join(ids), state))
    except botocore.exceptions.WaiterError as e:
        module.warn("Instances {0} took too long to reach state {1}. {2}".format(
            ', '.join(ids), state, to_native(e)))


def diff_instance_and_params(instance, params, ec2=None, skip=None):
    """boto3 instance obj, module params"""
    if ec2 is None:
        ec2 = module.client('ec2')

    if skip is None:
        skip = []

    changes_to_apply = []
    id_ = instance['InstanceId']

    ParamMapper = namedtuple('ParamMapper', ['param_key', 'instance_key', 'attribute_name', 'add_value'])

    def value_wrapper(v):
        return {'Value': v}

    param_mappings = [
        ParamMapper('ebs_optimized', 'EbsOptimized', 'ebsOptimized', value_wrapper),
        ParamMapper('termination_protection', 'DisableApiTermination', 'disableApiTermination', value_wrapper),
        # user data is an immutable property
        # ParamMapper('user_data', 'UserData', 'userData', value_wrapper),
    ]

    for mapping in param_mappings:
        if params.get(mapping.param_key) is not None and mapping.instance_key not in skip:
            value = AWSRetry.jittered_backoff()(ec2.describe_instance_attribute)(Attribute=mapping.attribute_name, InstanceId=id_)
            if params.get(mapping.param_key) is not None and value[mapping.instance_key]['Value'] != params.get(mapping.param_key):
                arguments = dict(
                    InstanceId=instance['InstanceId'],
                    # Attribute=mapping.attribute_name,
                )
                arguments[mapping.instance_key] = mapping.add_value(params.get(mapping.param_key))
                changes_to_apply.append(arguments)

    if (params.get('network') or {}).get('source_dest_check') is not None:
        # network.source_dest_check is nested, so needs to be treated separately
        check = bool(params.get('network').get('source_dest_check'))
        if instance['SourceDestCheck'] != check:
            changes_to_apply.append(dict(
                InstanceId=instance['InstanceId'],
                SourceDestCheck={'Value': check},
            ))

    return changes_to_apply


def change_network_attachments(instance, params, ec2):
    if (params.get('network') or {}).get('interfaces') is not None:
        new_ids = []
        for inty in params.get('network').get('interfaces'):
            if isinstance(inty, dict) and 'id' in inty:
                new_ids.append(inty['id'])
            elif isinstance(inty, string_types):
                new_ids.append(inty)
        # network.interfaces can create the need to attach new interfaces
        old_ids = [inty['NetworkInterfaceId'] for inty in instance['NetworkInterfaces']]
        to_attach = set(new_ids) - set(old_ids)
        for eni_id in to_attach:
            ec2.attach_network_interface(
                DeviceIndex=new_ids.index(eni_id),
                InstanceId=instance['InstanceId'],
                NetworkInterfaceId=eni_id,
            )
        return bool(len(to_attach))
    return False


def find_instances(ec2, ids=None, filters=None):
    paginator = ec2.get_paginator('describe_instances')
    if ids:
        return list(paginator.paginate(
            InstanceIds=ids,
        ).search('Reservations[].Instances[]'))
    elif filters is None:
        module.fail_json(msg="No filters provided when they were required")
    elif filters is not None:
        for key in filters.keys():
            if not key.startswith("tag:"):
                filters[key.replace("_", "-")] = filters.pop(key)
        return list(paginator.paginate(
            Filters=ansible_dict_to_boto3_filter_list(filters)
        ).search('Reservations[].Instances[]'))
    return []


@AWSRetry.jittered_backoff()
def get_default_vpc(ec2):
    vpcs = ec2.describe_vpcs(Filters=ansible_dict_to_boto3_filter_list({'isDefault': 'true'}))
    if len(vpcs.get('Vpcs', [])):
        return vpcs.get('Vpcs')[0]
    return None


@AWSRetry.jittered_backoff()
def get_default_subnet(ec2, vpc, availability_zone=None):
    subnets = ec2.describe_subnets(
        Filters=ansible_dict_to_boto3_filter_list({
            'vpc-id': vpc['VpcId'],
            'state': 'available',
            'default-for-az': 'true',
        })
    )
    if len(subnets.get('Subnets', [])):
        if availability_zone is not None:
            subs_by_az = dict((subnet['AvailabilityZone'], subnet) for subnet in subnets.get('Subnets'))
            if availability_zone in subs_by_az:
                return subs_by_az[availability_zone]

        # to have a deterministic sorting order, we sort by AZ so we'll always pick the `a` subnet first
        # there can only be one default-for-az subnet per AZ, so the AZ key is always unique in this list
        by_az = sorted(subnets.get('Subnets'), key=lambda s: s['AvailabilityZone'])
        return by_az[0]
    return None


def ensure_instance_state(state, ec2=None):
    if ec2 is None:
        module.client('ec2')
    if state in ('running', 'started'):
        changed, failed, instances, failure_reason = change_instance_state(filters=module.params.get('filters'), desired_state='RUNNING')

        if failed:
            module.fail_json(
                msg="Unable to start instances: {0}".format(failure_reason),
                reboot_success=list(changed),
                reboot_failed=failed)

        module.exit_json(
            msg='Instances started',
            reboot_success=list(changed),
            changed=bool(len(changed)),
            reboot_failed=[],
            instances=[pretty_instance(i) for i in instances],
        )
    elif state in ('restarted', 'rebooted'):
        changed, failed, instances, failure_reason = change_instance_state(
            filters=module.params.get('filters'),
            desired_state='STOPPED')
        changed, failed, instances, failure_reason = change_instance_state(
            filters=module.params.get('filters'),
            desired_state='RUNNING')

        if failed:
            module.fail_json(
                msg="Unable to restart instances: {0}".format(failure_reason),
                reboot_success=list(changed),
                reboot_failed=failed)

        module.exit_json(
            msg='Instances restarted',
            reboot_success=list(changed),
            changed=bool(len(changed)),
            reboot_failed=[],
            instances=[pretty_instance(i) for i in instances],
        )
    elif state in ('stopped',):
        changed, failed, instances, failure_reason = change_instance_state(
            filters=module.params.get('filters'),
            desired_state='STOPPED')

        if failed:
            module.fail_json(
                msg="Unable to stop instances: {0}".format(failure_reason),
                stop_success=list(changed),
                stop_failed=failed)

        module.exit_json(
            msg='Instances stopped',
            stop_success=list(changed),
            changed=bool(len(changed)),
            stop_failed=[],
            instances=[pretty_instance(i) for i in instances],
        )
    elif state in ('absent', 'terminated'):
        terminated, terminate_failed, instances, failure_reason = change_instance_state(
            filters=module.params.get('filters'),
            desired_state='TERMINATED')

        if terminate_failed:
            module.fail_json(
                msg="Unable to terminate instances: {0}".format(failure_reason),
                terminate_success=list(terminated),
                terminate_failed=terminate_failed)
        module.exit_json(
            msg='Instances terminated',
            terminate_success=list(terminated),
            changed=bool(len(terminated)),
            terminate_failed=[],
            instances=[pretty_instance(i) for i in instances],
        )


@AWSRetry.jittered_backoff()
def change_instance_state(filters, desired_state, ec2=None):
    """Takes STOPPED/RUNNING/TERMINATED"""
    if ec2 is None:
        ec2 = module.client('ec2')

    changed = set()
    instances = find_instances(ec2, filters=filters)
    to_change = set(i['InstanceId'] for i in instances if i['State']['Name'].upper() != desired_state)
    unchanged = set()
    failure_reason = ""

    for inst in instances:
        try:
            if desired_state == 'TERMINATED':
                if module.check_mode:
                    changed.add(inst['InstanceId'])
                    continue

                # TODO use a client-token to prevent double-sends of these start/stop/terminate commands
                # https://docs.aws.amazon.com/AWSEC2/latest/APIReference/Run_Instance_Idempotency.html
                resp = ec2.terminate_instances(InstanceIds=[inst['InstanceId']])
                [changed.add(i['InstanceId']) for i in resp['TerminatingInstances']]
            if desired_state == 'STOPPED':
                if inst['State']['Name'] in ('stopping', 'stopped'):
                    unchanged.add(inst['InstanceId'])
                    continue

                if module.check_mode:
                    changed.add(inst['InstanceId'])
                    continue

                resp = ec2.stop_instances(InstanceIds=[inst['InstanceId']])
                [changed.add(i['InstanceId']) for i in resp['StoppingInstances']]
            if desired_state == 'RUNNING':
                if module.check_mode:
                    changed.add(inst['InstanceId'])
                    continue

                resp = ec2.start_instances(InstanceIds=[inst['InstanceId']])
                [changed.add(i['InstanceId']) for i in resp['StartingInstances']]
        except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
            try:
                failure_reason = to_native(e.message)
            except AttributeError:
                failure_reason = to_native(e)

    if changed:
        await_instances(ids=list(changed) + list(unchanged), state=desired_state)

    change_failed = list(to_change - changed)
    instances = find_instances(ec2, ids=list(i['InstanceId'] for i in instances))
    return changed, change_failed, instances, failure_reason


def pretty_instance(i):
    instance = camel_dict_to_snake_dict(i, ignore_list=['Tags'])
    instance['tags'] = boto3_tag_list_to_ansible_dict(i['Tags'])
    return instance


def determine_iam_role(name_or_arn):
    if re.match(r'^arn:aws:iam::\d+:instance-profile/[\w+=/,.@-]+$', name_or_arn):
        return name_or_arn
    iam = module.client('iam', retry_decorator=AWSRetry.jittered_backoff())
    try:
        role = iam.get_instance_profile(InstanceProfileName=name_or_arn, aws_retry=True)
        return role['InstanceProfile']['Arn']
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchEntity':
            module.fail_json_aws(e, msg="Could not find instance_role {0}".format(name_or_arn))
        module.fail_json_aws(e, msg="An error occurred while searching for instance_role {0}. Please try supplying the full ARN.".format(name_or_arn))


def handle_existing(existing_matches, changed, ec2, state):
    if state in ('running', 'started') and [i for i in existing_matches if i['State']['Name'] != 'running']:
        ins_changed, failed, instances, failure_reason = change_instance_state(filters=module.params.get('filters'), desired_state='RUNNING')
        if failed:
            module.fail_json(msg="Couldn't start instances: {0}. Failure reason: {1}".format(instances, failure_reason))
        module.exit_json(
            changed=bool(len(ins_changed)) or changed,
            instances=[pretty_instance(i) for i in instances],
            instance_ids=[i['InstanceId'] for i in instances],
        )
    changes = diff_instance_and_params(existing_matches[0], module.params)
    for c in changes:
        AWSRetry.jittered_backoff()(ec2.modify_instance_attribute)(**c)
    changed |= bool(changes)
    changed |= add_or_update_instance_profile(existing_matches[0], module.params.get('instance_role'))
    changed |= change_network_attachments(existing_matches[0], module.params, ec2)
    altered = find_instances(ec2, ids=[i['InstanceId'] for i in existing_matches])
    module.exit_json(
        changed=bool(len(changes)) or changed,
        instances=[pretty_instance(i) for i in altered],
        instance_ids=[i['InstanceId'] for i in altered],
        changes=changes,
    )


def ensure_present(existing_matches, changed, ec2, state):
    if len(existing_matches):
        try:
            handle_existing(existing_matches, changed, ec2, state)
        except (botocore.exceptions.BotoCoreError, botocore.exceptions.ClientError) as e:
            module.fail_json_aws(
                e, msg="Failed to handle existing instances {0}".format(', '.join([i['InstanceId'] for i in existing_matches])),
                # instances=[pretty_instance(i) for i in existing_matches],
                # instance_ids=[i['InstanceId'] for i in existing_matches],
            )
    try:
        instance_spec = build_run_instance_spec(module.params)
        # If check mode is enabled,suspend 'ensure function'.
        if module.check_mode:
            module.exit_json(
                changed=True,
                spec=instance_spec,
            )
        instance_response = run_instances(ec2, **instance_spec)
        instances = instance_response['Instances']
        instance_ids = [i['InstanceId'] for i in instances]

        for ins in instances:
            changes = diff_instance_and_params(ins, module.params, skip=['UserData', 'EbsOptimized'])
            for c in changes:
                try:
                    AWSRetry.jittered_backoff()(ec2.modify_instance_attribute)(**c)
                except botocore.exceptions.ClientError as e:
                    module.fail_json_aws(e, msg="Could not apply change {0} to new instance.".format(str(c)))

        if not module.params.get('wait'):
            module.exit_json(
                changed=True,
                instance_ids=instance_ids,
                spec=instance_spec,
            )
        await_instances(instance_ids)
        instances = ec2.get_paginator('describe_instances').paginate(
            InstanceIds=instance_ids
        ).search('Reservations[].Instances[]')

        module.exit_json(
            changed=True,
            instances=[pretty_instance(i) for i in instances],
            instance_ids=instance_ids,
            spec=instance_spec,
        )
    except (botocore.exceptions.BotoCoreError, botocore.exceptions.ClientError) as e:
        module.fail_json_aws(e, msg="Failed to create new EC2 instance")


@AWSRetry.jittered_backoff()
def run_instances(ec2, **instance_spec):
    try:
        return ec2.run_instances(**instance_spec)
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'InvalidParameterValue' and "Invalid IAM Instance Profile ARN" in e.response['Error']['Message']:
            # If the instance profile has just been created, it takes some time to be visible by ec2
            # So we wait 10 second and retry the run_instances
            time.sleep(10)
            return ec2.run_instances(**instance_spec)
        else:
            raise e


def main():
    global module
    argument_spec = ec2_argument_spec()
    argument_spec.update(dict(
        state=dict(default='present', choices=['present', 'started', 'running', 'stopped', 'restarted', 'rebooted', 'terminated', 'absent']),
        wait=dict(default=True, type='bool'),
        wait_timeout=dict(default=600, type='int'),
        # count=dict(default=1, type='int'),
        image=dict(type='dict'),
        image_id=dict(type='str'),
        instance_type=dict(default='t2.micro', type='str'),
        user_data=dict(type='str'),
        tower_callback=dict(type='dict'),
        ebs_optimized=dict(type='bool'),
        vpc_subnet_id=dict(type='str', aliases=['subnet_id']),
        availability_zone=dict(type='str'),
        security_groups=dict(default=[], type='list'),
        security_group=dict(type='str'),
        instance_role=dict(type='str'),
        name=dict(type='str'),
        tags=dict(type='dict'),
        purge_tags=dict(type='bool', default=False),
        filters=dict(type='dict', default=None),
        launch_template=dict(type='dict'),
        key_name=dict(type='str'),
        cpu_credit_specification=dict(type='str', choices=['standard', 'unlimited']),
        cpu_options=dict(type='dict', options=dict(
            core_count=dict(type='int', required=True),
            threads_per_core=dict(type='int', choices=[1, 2], required=True)
        )),
        tenancy=dict(type='str', choices=['dedicated', 'default']),
        placement_group=dict(type='str'),
        instance_initiated_shutdown_behavior=dict(type='str', choices=['stop', 'terminate']),
        termination_protection=dict(type='bool'),
        detailed_monitoring=dict(type='bool'),
        instance_ids=dict(default=[], type='list'),
        network=dict(default=None, type='dict'),
        volumes=dict(default=None, type='list'),
    ))
    # running/present are synonyms
    # as are terminated/absent
    module = AnsibleAWSModule(
        argument_spec=argument_spec,
        mutually_exclusive=[
            ['security_groups', 'security_group'],
            ['availability_zone', 'vpc_subnet_id'],
            ['tower_callback', 'user_data'],
            ['image_id', 'image'],
        ],
        supports_check_mode=True
    )

    if module.params.get('network'):
        if module.params.get('network').get('interfaces'):
            if module.params.get('security_group'):
                module.fail_json(msg="Parameter network.interfaces can't be used with security_group")
            if module.params.get('security_groups'):
                module.fail_json(msg="Parameter network.interfaces can't be used with security_groups")

    state = module.params.get('state')
    ec2 = module.client('ec2')
    if module.params.get('filters') is None:
        filters = {
            # all states except shutting-down and terminated
            'instance-state-name': ['pending', 'running', 'stopping', 'stopped']
        }
        if state == 'stopped':
            # only need to change instances that aren't already stopped
            filters['instance-state-name'] = ['stopping', 'pending', 'running']

        if isinstance(module.params.get('instance_ids'), string_types):
            filters['instance-id'] = [module.params.get('instance_ids')]
        elif isinstance(module.params.get('instance_ids'), list) and len(module.params.get('instance_ids')):
            filters['instance-id'] = module.params.get('instance_ids')
        else:
            if not module.params.get('vpc_subnet_id'):
                if module.params.get('network'):
                    # grab AZ from one of the ENIs
                    ints = module.params.get('network').get('interfaces')
                    if ints:
                        filters['network-interface.network-interface-id'] = []
                        for i in ints:
                            if isinstance(i, dict):
                                i = i['id']
                            filters['network-interface.network-interface-id'].append(i)
                else:
                    sub = get_default_subnet(ec2, get_default_vpc(ec2), availability_zone=module.params.get('availability_zone'))
                    filters['subnet-id'] = sub['SubnetId']
            else:
                filters['subnet-id'] = [module.params.get('vpc_subnet_id')]

            if module.params.get('name'):
                filters['tag:Name'] = [module.params.get('name')]

            if module.params.get('image_id'):
                filters['image-id'] = [module.params.get('image_id')]
            elif (module.params.get('image') or {}).get('id'):
                filters['image-id'] = [module.params.get('image', {}).get('id')]

        module.params['filters'] = filters

    if module.params.get('cpu_options') and not module.botocore_at_least('1.10.16'):
        module.fail_json(msg="cpu_options is only supported with botocore >= 1.10.16")

    existing_matches = find_instances(ec2, filters=module.params.get('filters'))
    changed = False

    if state not in ('terminated', 'absent') and existing_matches:
        for match in existing_matches:
            warn_if_public_ip_assignment_changed(match)
            warn_if_cpu_options_changed(match)
            tags = module.params.get('tags') or {}
            name = module.params.get('name')
            if name:
                tags['Name'] = name
            changed |= manage_tags(match, tags, module.params.get('purge_tags', False), ec2)

    if state in ('present', 'running', 'started'):
        ensure_present(existing_matches=existing_matches, changed=changed, ec2=ec2, state=state)
    elif state in ('restarted', 'rebooted', 'stopped', 'absent', 'terminated'):
        if existing_matches:
            ensure_instance_state(state, ec2)
        else:
            module.exit_json(
                msg='No matching instances found',
                changed=False,
                instances=[],
            )
    else:
        module.fail_json(msg="We don't handle the state {0}".format(state))


if __name__ == '__main__':
    main()
