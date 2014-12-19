Ironic-UCS
==========
This is Cisco Systems's Juno version of Ironic project. Added support
for the Cisco UCS B/C-series servers. This code is not available in
community for Juno rlease. It will be available in Kilo release through
community.

Installation instructions
=========================


Ironic
======

Ironic is an Incubated OpenStack project which aims to provision
bare metal machines instead of virtual machines, forked from the
Nova Baremetal driver. It is best thought of as a bare metal
hypervisor **API** and a set of plugins which interact with
the bare metal hypervisors. By default, it will use PXE and IPMI
in concert to provision and turn on/off machines, but Ironic
also supports vendor-specific plugins which may implement additional
functionality.

-----------------
Project Resources
-----------------

Project status, bugs, and blueprints are tracked on Launchpad:

  http://launchpad.net/ironic

Developer documentation can be found here:

  http://docs.openstack.org/developer/ironic

Additional resources are linked from the project wiki page:

  https://wiki.openstack.org/wiki/Ironic

Anyone wishing to contribute to an OpenStack project should
find plenty of helpful resources here:

  https://wiki.openstack.org/wiki/HowToContribute

All OpenStack projects use Gerrit for code reviews.
A good reference for that is here:

  https://wiki.openstack.org/wiki/GerritWorkflow
