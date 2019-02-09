# Ansible for NSX-T

# Overview
This repository contains NSX-T Ansible Modules, which one can use with Ansible to work with [VMware NSX-T Data Center][vmware-nsxt]. [vmware-nsxt]: https://www.vmware.com/products/nsx.html
For general information about Ansible, visit the [GitHub project page][an-github]. [an-github]: https://github.com/ansible/ansible
Documentation on the NSX platform can be found at the [NSX-T Documentation page](https://docs.vmware.com/en/VMware-NSX-T/index.html)

This repository is a fork of the original one in order to give the community fast access to some features VMWare forgot or was too lazy to implement.... for examples support for NSX-T 2.3.x, tagging, router reditributions and so on. It also provide better automatic integration in the case you want to build a Kubernetes Cluster on top of NSX-T networking.

### Supported NSX Objects/Workflows
The modules in this repository are focused on enabling automation of installation workflows of NSX-T.

#### Deployment and installation modules

* nsxt_deploy_ova
* nsxt_licenses
* nsxt_manager_status
* nsxt_licenses_facts
* nsxt_controllers
* nsxt_controllers_facts
* nsxt_edge_clusters
* nsxt_edge_clusters_facts
* nsxt_compute_managers
* nsxt_compute_managers_facts
* nsxt_fabric_nodes
* nsxt_fabric_nodes_facts
* nsxt_compute_collection_fabric_templates
* nsxt_compute_collection_fabric_templates_facts
* nsxt_ip_pools
* nsxt_ip_pools_facts
* nsxt_uplink_profiles
* nsxt_uplink_profiles_facts
* nsxt_transport_zones
* nsxt_transport_zones_facts
* nsxt_transport_nodes
* nsxt_transport_nodes_facts
* nsxt_compute_collection_transport_templates
* nsxt_compute_collection_transport_templates_facts

##### Logical networking modules
* nsxt_logical_ports
* nsxt_logical_ports_facts
* nsxt_logical_routers
* nsxt_logical_routers_facts
* nsxt_logical_routers_ports
* nsxt_logical_routers_ports_facts
* nsxt_logical_router_static_routes
* nsxt_logical_switches
* nsxt_logical_switches_facts
* nsxt_ip_blocks
* nsxt_ip_blocks_facts


# Prerequisites
We assume that ansible is already installed. 
These modules support ansible version 2.6 and onwards. 

* PyVmOmi - Python library for vCenter api.

* OVF Tools - Ovftool is used for ovf deployment. 


# Build & Run

Install PyVmOmi
```
pip install --upgrade pyvmomi pyvim requests ssl
```
Download and Install Ovf tool - [Ovftool](https://my.vmware.com/web/vmware/details?downloadGroup=OVFTOOL400&productId=353)

Download [ansible-for-nsxt](https://github.com/vmware/ansible-for-nsxt/archive/master.zip).
```
unzip ansible-for-nsxt-master.zip
cd ansible-for-nsxt-master
```
To run a sample Ansible playbook - To create a sample test topology using deployments and install module.

Edit test_basic_topology.yml and answerfile.yml to match values to your environment.
```
ansible-playbook test_basic_topology.yml -vvv
```
# Interoperability

The following versions of NSX are supported:

 * NSX-T 2.3.*
 * Ansible 2.6+


# License
NSX and NSX-T are Copyright (c) 2018 VMware, Inc.  All rights reserved

The NSX-T Ansible modules in this repository are available under [BSD-2 license](https://github.com/vmware/ansible-for-nsxt/blob/master/LICENSE.txt) applies to all parts of the ansible-for-nsxt.
You may not use them except in compliance with the License.†
