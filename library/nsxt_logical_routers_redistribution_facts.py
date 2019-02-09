#!/usr/bin/env python
#
# Copyright 2018 Facilitylive OpCo S.r.l
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING,
# BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
# EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''TODO
author: Manuel Bovo
'''

EXAMPLES = '''
- nsxt_logical_routers_redistribution_facts:
      hostname: "10.192.167.137"
      username: "admin"
      password: "Admin!23Admin"
      validate_certs: False
'''

RETURN = '''# '''

import json
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.vmware import vmware_argument_spec, request
from ansible.module_utils._text import to_native


def get_id_from_display_name(module, manager_url, mgr_username, mgr_password, validate_certs, endpoint,
                             display_name):
  try:
    (rc, resp) = request(manager_url + endpoint, headers=dict(Accept='application/json'),
                         url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs,
                         ignore_errors=True)
  except Exception as err:
    return None

  for result in resp['results']:
    if result.__contains__('display_name') and result['display_name'] == display_name:
      return result['id']
  return None


def main():
  argument_spec = vmware_argument_spec()
  argument_spec.update(logical_router_id=dict(required=False, type='str'),
                       logical_router_name=dict(required=False, type='str'))

  module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

  mgr_hostname = module.params['hostname']
  mgr_username = module.params['username']
  mgr_password = module.params['password']
  validate_certs = module.params['validate_certs']

  manager_url = 'https://{}/api/v1'.format(mgr_hostname)

  changed = False
  try:

    lr_id = get_id_from_display_name(module, manager_url, mgr_username, mgr_password, validate_certs,
                                     '/logical-routers',
                                     module.params['logical_router_name'])
    if lr_id:
      module.params['logical_router_id'] = lr_id

    (rc, resp) = request(manager_url + '/logical-routers/' + lr_id + '/routing/redistribution',
                         headers=dict(Accept='application/json'),
                         url_username=mgr_username, url_password=mgr_password, validate_certs=validate_certs,
                         ignore_errors=True)
  except Exception as err:
    module.fail_json(msg='Error accessing list of logical routers. Error [%s]' % (to_native(err)))

  module.exit_json(changed=changed, **resp)


if __name__ == '__main__':
  main()
