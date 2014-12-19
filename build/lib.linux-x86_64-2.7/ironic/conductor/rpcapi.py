# coding=utf-8

# Copyright 2013 Hewlett-Packard Development Company, L.P.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
"""
Client side of the conductor RPC API.
"""

import random

from oslo import messaging

from ironic.common import exception
from ironic.common import hash_ring
from ironic.common.i18n import _
from ironic.common import rpc
from ironic.conductor import manager
from ironic.objects import base as objects_base


class ConductorAPI(object):
    """Client side of the conductor RPC API.

    API version history:

        1.0 - Initial version.
              Included get_node_power_status
        1.1 - Added update_node and start_power_state_change.
        1.2 - Added vendor_passhthru.
        1.3 - Rename start_power_state_change to change_node_power_state.
        1.4 - Added do_node_deploy and do_node_tear_down.
        1.5 - Added validate_driver_interfaces.
        1.6 - change_node_power_state, do_node_deploy and do_node_tear_down
              accept node id instead of node object.
        1.7 - Added topic parameter to RPC methods.
        1.8 - Added change_node_maintenance_mode.
        1.9 - Added destroy_node.
        1.10 - Remove get_node_power_state
        1.11 - Added get_console_information, set_console_mode.
        1.12 - validate_vendor_action, do_vendor_action replaced by single
              vendor_passthru method.
        1.13 - Added update_port.
        1.14 - Added driver_vendor_passthru.
        1.15 - Added rebuild parameter to do_node_deploy.
        1.16 - Added get_driver_properties.
        1.17 - Added set_boot_device, get_boot_device and
               get_supported_boot_devices.

    """

    # NOTE(rloo): This must be in sync with manager.ConductorManager's.
    RPC_API_VERSION = '1.17'

    def __init__(self, topic=None):
        super(ConductorAPI, self).__init__()
        self.topic = topic
        if self.topic is None:
            self.topic = manager.MANAGER_TOPIC

        target = messaging.Target(topic=self.topic,
                                  version='1.0')
        serializer = objects_base.IronicObjectSerializer()
        self.client = rpc.get_client(target,
                                     version_cap=self.RPC_API_VERSION,
                                     serializer=serializer)
        # NOTE(deva): this is going to be buggy
        self.ring_manager = hash_ring.HashRingManager()

    def get_topic_for(self, node):
        """Get the RPC topic for the conductor service which the node
        is mapped to.

        :param node: a node object.
        :returns: an RPC topic string.
        :raises: NoValidHost

        """
        self.ring_manager.reset()

        try:
            ring = self.ring_manager[node.driver]
            dest = ring.get_hosts(node.uuid)
            return self.topic + "." + dest[0]
        except exception.DriverNotFound:
            reason = (_('No conductor service registered which supports '
                        'driver %s.') % node.driver)
            raise exception.NoValidHost(reason=reason)

    def get_topic_for_driver(self, driver_name):
        """Get an RPC topic which will route messages to a conductor which
        supports the specified driver. A conductor is selected at
        random from the set of qualified conductors.

        :param driver_name: the name of the driver to route to.
        :returns: an RPC topic string.
        :raises: DriverNotFound

        """
        self.ring_manager.reset()

        hash_ring = self.ring_manager[driver_name]
        host = random.choice(list(hash_ring.hosts))
        return self.topic + "." + host

    def update_node(self, context, node_obj, topic=None):
        """Synchronously, have a conductor update the node's information.

        Update the node's information in the database and return a node object.
        The conductor will lock the node while it validates the supplied
        information. If driver_info is passed, it will be validated by
        the core drivers. If instance_uuid is passed, it will be set or unset
        only if the node is properly configured.

        Note that power_state should not be passed via this method.
        Use change_node_power_state for initiating driver actions.

        :param context: request context.
        :param node_obj: a changed (but not saved) node object.
        :param topic: RPC topic. Defaults to self.topic.
        :returns: updated node object, including all fields.

        """
        cctxt = self.client.prepare(topic=topic or self.topic, version='1.1')
        return cctxt.call(context, 'update_node', node_obj=node_obj)

    def change_node_power_state(self, context, node_id, new_state, topic=None):
        """Synchronously, acquire lock and start the conductor background task
        to change power state of a node.

        :param context: request context.
        :param node_id: node id or uuid.
        :param new_state: one of ironic.common.states power state values
        :param topic: RPC topic. Defaults to self.topic.
        :raises: NoFreeConductorWorker when there is no free worker to start
                 async task.

        """
        cctxt = self.client.prepare(topic=topic or self.topic, version='1.6')
        return cctxt.call(context, 'change_node_power_state', node_id=node_id,
                          new_state=new_state)

    def vendor_passthru(self, context, node_id, driver_method, info,
                        topic=None):
        """Synchronously, acquire lock, validate given parameters and start
        the conductor background task for specified vendor action.

        :param context: request context.
        :param node_id: node id or uuid.
        :param driver_method: name of method for driver.
        :param info: info for node driver.
        :param topic: RPC topic. Defaults to self.topic.
        :raises: InvalidParameterValue if supplied info is not valid.
        :raises: MissingParameterValue if a required parameter is missing
        :raises: UnsupportedDriverExtension if current driver does not have
                 vendor interface.
        :raises: NoFreeConductorWorker when there is no free worker to start
                 async task.

        """
        cctxt = self.client.prepare(topic=topic or self.topic, version='1.12')
        return cctxt.call(context, 'vendor_passthru', node_id=node_id,
                          driver_method=driver_method, info=info)

    def driver_vendor_passthru(self, context, driver_name, driver_method, info,
                        topic=None):
        """Pass vendor-specific calls which don't specify a node to a driver.

        :param context: request context.
        :param driver_name: name of the driver on which to call the method.
        :param driver_method: name of the vendor method, for use by the driver.
        :param info: data to pass through to the driver.
        :param topic: RPC topic. Defaults to self.topic.
        :raises: InvalidParameterValue for parameter errors.
        :raises: MissingParameterValue if a required parameter is missing
        :raises: UnsupportedDriverExtension if the driver doesn't have a vendor
                 interface, or if the vendor interface does not support the
                 specified driver_method.

        """
        cctxt = self.client.prepare(topic=topic or self.topic, version='1.14')
        return cctxt.call(context, 'driver_vendor_passthru',
                          driver_name=driver_name,
                          driver_method=driver_method,
                          info=info)

    def do_node_deploy(self, context, node_id, rebuild, topic=None):
        """Signal to conductor service to perform a deployment.

        :param context: request context.
        :param node_id: node id or uuid.
        :param rebuild: True if this is a rebuild request.
        :param topic: RPC topic. Defaults to self.topic.
        :raises: InstanceDeployFailure
        :raises: InvalidParameterValue if validation fails
        :raises: MissingParameterValue if a required parameter is missing
        :raises: NoFreeConductorWorker when there is no free worker to start
                 async task.

        The node must already be configured and in the appropriate
        undeployed state before this method is called.

        """
        cctxt = self.client.prepare(topic=topic or self.topic, version='1.15')
        return cctxt.call(context, 'do_node_deploy', node_id=node_id,
                          rebuild=rebuild)

    def do_node_tear_down(self, context, node_id, topic=None):
        """Signal to conductor service to tear down a deployment.

        :param context: request context.
        :param node_id: node id or uuid.
        :param topic: RPC topic. Defaults to self.topic.
        :raises: InstanceDeployFailure
        :raises: InvalidParameterValue if validation fails
        :raises: MissingParameterValue if a required parameter is missing
        :raises: NoFreeConductorWorker when there is no free worker to start
                 async task.

        The node must already be configured and in the appropriate
        deployed state before this method is called.

        """
        cctxt = self.client.prepare(topic=topic or self.topic, version='1.6')
        return cctxt.call(context, 'do_node_tear_down', node_id=node_id)

    def validate_driver_interfaces(self, context, node_id, topic=None):
        """Validate the `core` and `standardized` interfaces for drivers.

        :param context: request context.
        :param node_id: node id or uuid.
        :param topic: RPC topic. Defaults to self.topic.
        :returns: a dictionary containing the results of each
                  interface validation.

        """
        cctxt = self.client.prepare(topic=topic or self.topic, version='1.5')
        return cctxt.call(context, 'validate_driver_interfaces',
                          node_id=node_id)

    def change_node_maintenance_mode(self, context, node_id, mode, topic=None):
        """Set node maintenance mode on or off.

        :param context: request context.
        :param node_id: node id or uuid.
        :param mode: True or False.
        :param topic: RPC topic. Defaults to self.topic.
        :returns: a node object.
        :raises: NodeMaintenanceFailure.

        """
        cctxt = self.client.prepare(topic=topic or self.topic, version='1.8')
        return cctxt.call(context, 'change_node_maintenance_mode',
                          node_id=node_id, mode=mode)

    def destroy_node(self, context, node_id, topic=None):
        """Delete a node.

        :param context: request context.
        :param node_id: node id or uuid.
        :raises: NodeLocked if node is locked by another conductor.
        :raises: NodeAssociated if the node contains an instance
            associated with it.
        :raises: NodeInWrongPowerState if the node is not powered off.

        """
        cctxt = self.client.prepare(topic=topic or self.topic, version='1.9')
        return cctxt.call(context, 'destroy_node', node_id=node_id)

    def get_console_information(self, context, node_id, topic=None):
        """Get connection information about the console.

        :param context: request context.
        :param node_id: node id or uuid.
        :param topic: RPC topic. Defaults to self.topic.
        :raises: UnsupportedDriverExtension if the node's driver doesn't
                 support console.
        :raises: InvalidParameterValue when the wrong driver info is specified.
        :raises: MissingParameterValue if a required parameter is missing
        """
        cctxt = self.client.prepare(topic=topic or self.topic, version='1.11')
        return cctxt.call(context, 'get_console_information', node_id=node_id)

    def set_console_mode(self, context, node_id, enabled, topic=None):
        """Enable/Disable the console.

        :param context: request context.
        :param node_id: node id or uuid.
        :param topic: RPC topic. Defaults to self.topic.
        :param enabled: Boolean value; whether the console is enabled or
                        disabled.
        :raises: UnsupportedDriverExtension if the node's driver doesn't
                 support console.
        :raises: InvalidParameterValue when the wrong driver info is specified.
        :raises: MissingParameterValue if a required parameter is missing
        :raises: NoFreeConductorWorker when there is no free worker to start
                 async task.
        """
        cctxt = self.client.prepare(topic=topic or self.topic, version='1.11')
        return cctxt.call(context, 'set_console_mode', node_id=node_id,
                          enabled=enabled)

    def get_vendor_passthru(self, context, node_id, driver_method, topic=None):
        """Synchronously, acquire lock, validate given parameters and call
        the conductor vendor specific get action.

        :param context: request context.
        :param node_id: node id or uuid.
        :param driver_method: name of method for driver.
        :param topic: RPC topic. Defaults to self.topic.
        :raises: InvalidParameterValue if supplied info is not valid.
        :raises: UnsupportedDriverExtension if current driver does not have
                 vendor interface.
        :raises: NoFreeConductorWorker when there is no free worker to start
                 async task.

        """
        topic = topic or self.topic
        return self.call(context,
                         self.make_msg('get_vendor_passthru',
                                       node_id=node_id,
                                       driver_method=driver_method),
                         topic=topic)

    def update_port(self, context, port_obj, topic=None):
        """Synchronously, have a conductor update the port's information.

        Update the port's information in the database and return a port object.
        The conductor will lock related node and trigger specific driver
        actions if they are needed.

        :param context: request context.
        :param port_obj: a changed (but not saved) port object.
        :param topic: RPC topic. Defaults to self.topic.
        :returns: updated port object, including all fields.

        """
        cctxt = self.client.prepare(topic=topic or self.topic, version='1.13')
        return cctxt.call(context, 'update_port', port_obj=port_obj)

    def get_driver_properties(self, context, driver_name, topic=None):
        """Get the properties of the driver.

        :param context: request context.
        :param driver_name: name of the driver.
        :param topic: RPC topic. Defaults to self.topic.
        :returns: a dictionary with <property name>:<property description>
                  entries.
        :raises: DriverNotFound.

        """
        cctxt = self.client.prepare(topic=topic or self.topic, version='1.16')
        return cctxt.call(context, 'get_driver_properties',
                          driver_name=driver_name)

    def set_boot_device(self, context, node_id, device, persistent=False,
                        topic=None):
        """Set the boot device for a node.

        Set the boot device to use on next reboot of the node. Be aware
        that not all drivers support this.

        :param context: request context.
        :param node_id: node id or uuid.
        :param device: the boot device, one of
                       :mod:`ironic.common.boot_devices`.
        :param persistent: Whether to set next-boot, or make the change
                           permanent. Default: False.
        :raises: NodeLocked if node is locked by another conductor.
        :raises: UnsupportedDriverExtension if the node's driver doesn't
                 support management.
        :raises: InvalidParameterValue when the wrong driver info is
                 specified or an invalid boot device is specified.
        :raises: MissingParameterValue if missing supplied info.
        """
        cctxt = self.client.prepare(topic=topic or self.topic, version='1.17')
        return cctxt.call(context, 'set_boot_device', node_id=node_id,
                          device=device, persistent=persistent)

    def get_boot_device(self, context, node_id, topic=None):
        """Get the current boot device.

        Returns the current boot device of a node.

        :param context: request context.
        :param node_id: node id or uuid.
        :raises: NodeLocked if node is locked by another conductor.
        :raises: UnsupportedDriverExtension if the node's driver doesn't
                 support management.
        :raises: InvalidParameterValue when the wrong driver info is
                 specified.
        :raises: MissingParameterValue if missing supplied info.
        :returns: a dictionary containing:

            :boot_device: the boot device, one of
                :mod:`ironic.common.boot_devices` or None if it is unknown.
            :persistent: Whether the boot device will persist to all
                future boots or not, None if it is unknown.

        """
        cctxt = self.client.prepare(topic=topic or self.topic, version='1.17')
        return cctxt.call(context, 'get_boot_device', node_id=node_id)

    def get_supported_boot_devices(self, context, node_id, topic=None):
        """Get the list of supported devices.

        Returns the list of supported boot devices of a node.

        :param context: request context.
        :param node_id: node id or uuid.
        :raises: NodeLocked if node is locked by another conductor.
        :raises: UnsupportedDriverExtension if the node's driver doesn't
                 support management.
        :raises: InvalidParameterValue when the wrong driver info is
                 specified.
        :raises: MissingParameterValue if missing supplied info.
        :returns: A list with the supported boot devices defined
                  in :mod:`ironic.common.boot_devices`.

        """
        cctxt = self.client.prepare(topic=topic or self.topic, version='1.17')
        return cctxt.call(context, 'get_supported_boot_devices',
                          node_id=node_id)
