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
- nsxt_logical_routers_distribution:
      hostname: "10.192.167.137"
      username: "admin"
      password: "Admin!23Admin"
      validate_certs: False
      resource_type: LogicalRouter
      description: "Router West"
      display_name: "tier-0"
      edge_cluster_name: edge-cluster-1
      router_type: TIER0
      high_availability_mode: ACTIVE_ACTIVE
'''

RETURN = '''# '''

import json, time
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.vmware import vmware_argument_spec, get_params, api_call
from ansible.module_utils._text import to_native


def get_logical_routers(module, display_name=None):
    rc, resp = api_call(module, '/logical-routers')
    if display_name is not None:
        for logical_router in resp['results']:
            if 'display_name' in logical_router and logical_router['display_name'] == display_name:
                return logical_router
    return resp['results']


def get_router_id_from_name(module, display_name):
    routers = get_logical_routers(module, display_name)
    if routers is not None and 'id' in routers:
        return routers['id']
    module.fail_json(msg='No id exists with display name %s' % display_name)


def get_distribution_rule(module, router_id):
    (rc, resp) = api_call(module, api_path='/logical-routers/' + router_id + '/routing/redistribution/rules')
    return resp


def check_for_update(module, new_object, router_id):

    resp = get_distribution_rule(module, router_id)
    if 'results' in resp:
        existing_object = resp['results']
    else:
        return False

    if 'description' in existing_object and existing_object['description'] != new_object['description']:
        return True

    # i don't care about nested objects sorting / values :D just compare names
    if 'rules' in existing_object and 'rules' in new_object:
        for oldrule in existing_object['rules']:
            for newrule in new_object['rules']:
                if 'display_name' in oldrule and 'display_name' in newrule and \
                        oldrule['display_name'] != newrule['display_name']:
                    return True

    return False


def main():
    argument_spec = vmware_argument_spec()
    argument_spec.update(display_name=dict(required=False, type='str'),
                         logical_router_name=dict(required=True, type='str'),
                         description=dict(required=False, type='str'),
                         bgp_enabled=dict(required=True, type='bool'),
                         rules=dict(required=False, type='list'),
                         state=dict(required=True, choices=['present', 'absent']),
                         tags=dict(required=False, type='list'))
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    # Access variabiles local copy
    state = module.params['state']

    params_redistribution = get_params(module.params.copy(),
                                       args_to_remove= vmware_argument_spec().keys() +
                                                       ['logical_router_name', 'rules', 'state'])
    params_redistribution_rule = get_params(module.params.copy(),
                                            args_to_remove=vmware_argument_spec().keys() +
                                                           ['logical_router_name', 'state', 'bgp_enabled'])
    # Get router id from its name
    router_id = get_router_id_from_name(module, module.params['logical_router_name'])

    if state == 'present':
        updated = check_for_update(module, json.dumps(params_redistribution_rule), router_id)

        if not updated:
            # add the router if not dry run
            if module.check_mode:
                module.exit_json(changed=True, debug_out=str(json.dumps(body)), id='12345')

            params_redistribution['_revision'] = "0"
            params_redistribution_rule['_revision'] = "0"
            request_data = json.dumps(params_redistribution)
            try:
                # enable bgp flag
                (rc, resp) = api_call(module=module,
                                      method='PUT',
                                      data=request_data,
                                      api_path='/logical-routers/' + router_id + '/routing/redistribution/')

                request_data = json.dumps(params_redistribution_rule)
                (rc, resp) = api_call(module=module,
                                      method='PUT',
                                      data=request_data,
                                      api_path='/logical-routers/' + router_id + '/routing/redistribution/rules')

            except Exception as err:
                module.fail_json(
                    msg="Failed to add logical router redistribution. Request body [%s]. Error[%s]." % (
                        request_data, to_native(err)))

            module.exit_json(changed=True, id=resp["id"], body=str(resp),
                             message="Logical router distribution %s created." % module.params['display_name'])
        else:
            if module.check_mode:
                module.exit_json(changed=True, debug_out=str(json.dumps(body)), id=router_id)

            oldrule = get_distribution_rule(module, router_id)

            params_redistribution['_revision'] = oldrule['_revision']
            params_redistribution_rule['_revision'] = oldrule['_revision']  # update current revision
            params_redistribution_rule['id'] = oldrule['id']

            request_data = json.dumps(params_redistribution)
            try:
                # enable bgp flag
                (rc, resp) = api_call(module=module,
                                      method='PUT',
                                      data=request_data,
                                      api_path='/logical-routers/' + router_id + '/routing/redistribution/')
                # update rule
                request_data = json.dumps(params_redistribution_rule)
                (rc, resp) = api_call(module=module,
                                      method='PUT',
                                      data=request_data,
                                      api_path='/logical-routers/' + router_id + '/routing/redistribution/rules')

            except Exception as err:
                module.fail_json(
                    msg="Failed to add logical router redistribution. Request body [%s]. Error[%s]." % (
                        request_data, to_native(err)))

            module.exit_json(changed=True, id=resp["id"], body=str(resp),
                             message="logical router with id %s updated." % id)

    elif state == 'absent':
        #cannot delete this, the api is missed?
        module.fail_json(msg="Failed to delete logical router redistribution with id %s. Error[%s]." % (router_id, to_native(err)))


if __name__ == '__main__':
    main()
