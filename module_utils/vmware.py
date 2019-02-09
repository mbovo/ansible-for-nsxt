#!/usr/bin/env python
#
# Copyright 2018 VMware, Inc.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING,
# BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
# EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import json
from ansible.module_utils.urls import open_url, fetch_url
from ansible.module_utils.six.moves.urllib.error import HTTPError
from ansible.module_utils._text import to_native
import requests, ssl
from pyVim.connect import SmartConnect

def find_morefId(obj_name, obj_list):
    """
    Gets an object out of a list (obj_list) whos name matches obj_name.
    """
    for o in obj_list:
        if o.name == obj_name:
            return o._moId
    raise Exception("Unable to find object ", obj_name)

def find_moref_ids_for_deployment(vm_deployment_config, vc_host, vc_username, vc_password, vc_datacenter):
    requests.packages.urllib3.disable_warnings()
    ssl._create_default_https_context = ssl._create_unverified_context
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    deploy_config = dict()

    si = SmartConnect(host=vc_host, user=vc_username, pwd=vc_password)
    content = si.RetrieveContent()
    datacenter_obj = None

    # select the right datacenter using its name
    datacenter_list = content.rootFolder.childEntity
    for datacenter in datacenter_list:
        if datacenter.name == vc_datacenter:
            datacenter_obj = datacenter
        else:
            raise Exception("Datacenter not found", vm_deployment_config['compute_id'])

    # translate datastore name
    datastore_list = datacenter_obj.datastoreFolder.childEntity
    deploy_config['storage_id'] = find_morefId(vm_deployment_config['storage_id'], datastore_list)

    # translate cluster name (compute_id)
    cluster_list = datacenter_obj.hostFolder.childEntity
    deploy_config['compute_id'] = find_morefId(vm_deployment_config['compute_id'], cluster_list)

    # translate all data networks
    deploy_config['data_network_ids'] = []
    network_list = datacenter_obj.networkFolder.childEntity

    if 'data_network_ids' in vm_deployment_config: 
        for network in vm_deployment_config['data_network_ids']:
            deploy_config['data_network_ids'].append(find_morefId(network, network_list))
            #data_network_ids.append(find_morefId(network, network_list))

    # translate management network
    deploy_config['management_network_id'] = find_morefId(vm_deployment_config['management_network_id'], network_list)

    return deploy_config

def vmware_argument_spec():
    return dict(
        hostname=dict(type='str', required=True),
        username=dict(type='str', required=True),
        password=dict(type='str', required=True, no_log=True),
        port=dict(type='int', default=443),
        validate_certs=dict(type='bool', requried=False, default=True),
    )


def request(url, data=None, headers=None, method='GET', use_proxy=True,
            force=False, last_mod_time=None, timeout=300, validate_certs=True,
            url_username=None, url_password=None, http_agent=None, force_basic_auth=True, ignore_errors=False):
    try:
        r = open_url(url=url, data=data, headers=headers, method=method, use_proxy=use_proxy,
                     force=force, last_mod_time=last_mod_time, timeout=timeout, validate_certs=validate_certs,
                     url_username=url_username, url_password=url_password, http_agent=http_agent,
                     force_basic_auth=force_basic_auth)
    except HTTPError as err:
        r = err.fp

    try:
        raw_data = r.read()
        if raw_data:
            data = json.loads(raw_data)
        else:
            raw_data = None
    except:
        if ignore_errors:
            pass
        else:
            raise Exception(raw_data)

    resp_code = r.getcode()

    if resp_code >= 400: #and not ignore_errors:
        raise Exception(resp_code, data)
    if not (data is None) and data.__contains__('error_code'):
        raise Exception (data['error_code'], data)
    else:
        return resp_code, data


def get_params(args={}, args_to_remove=[]):
    for key in args_to_remove:
        args.pop(key, None)
    for key, value in args.copy().items():
        if value is None:
            args.pop(key, None)
    return args



def api_call(module, api_path, method='GET', data=None, headers={}):

    hostname, username, password, validate_certs = module.params['hostname'], \
                                                   module.params['username'], \
                                                   module.params['password'], \
                                                   module.params['validate_certs']
    manager_url = 'https://{}/api/v1'.format(hostname)
    headers['Accept'] = 'application/json'
    if method != 'GET':
        headers['Content-Type'] = 'application/json'
    try:
        (rc, resp) = request(manager_url + api_path, headers=headers,
                             method=method,
                             data=data,
                             url_username=username,
                             url_password=password,
                             validate_certs=validate_certs,
                             ignore_errors=True)
    except Exception as err:
        module.fail_json(msg='Error accessing %s Error [%s]' % (api_path, to_native(err)))
    return rc, resp