# coding=utf-8
#
# Copyright 2014 Red Hat, Inc.
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

"""Short term workaround for friction in the Nova compute manager with  Ironic.

https://etherpad.openstack.org/p/ironic-nova-friction contains current design
work. The goal here is to generalise the areas where n-c talking to a clustered
hypervisor has issues, and long term fold them into the main ComputeManager.
"""

from nova.openstack.common import lockutils
from nova.compute import manager
import nova.context


CCM_SEMAPHORE='clustered_compute_manager'


class ClusteredComputeManager(manager.ComputeManager):

    def init_host(self):
        """Initialization for a clustered compute service."""
        self.driver.init_host(host=self.host)
        # Not used currently.
        # context = nova.context.get_admin_context()
        # instances = instance_obj.InstanceList.get_by_host(
        #     context, self.host, expected_attrs=['info_cache'])

        # defer_iptables_apply is moot for clusters - no local iptables
        # if CONF.defer_iptables_apply:
        #     self.driver.filter_defer_apply_on()

        self.init_virt_events()

        # try:
            # evacuation is moot for a clustered hypervisor
            # # checking that instance was not already evacuated to other host
            # self._destroy_evacuated_instances(context)
            # Don't run _init_instance until we solve the partitioning problem
            # - with N n-cpu's all claiming the same hostname, running
            # _init_instance here would lead to race conditions where each runs
            # _init_instance concurrently.
            # for instance in instances:
            #     self._init_instance(context, instance)
        # finally:
            # defer_iptables_apply is moot for clusters - no local iptables
            # if CONF.defer_iptables_apply:
            #     self.driver.filter_defer_apply_off()

    def pre_start_hook(self):
        """After the service is initialized, but before we fully bring
        the service up by listening on RPC queues, make sure to update
        our available resources (and indirectly our available nodes).
        """
        # This is an optimisation to immediately advertise resources but
        # the periodic task will update them eventually anyway, so ignore
        # errors as they may be transient (e.g. the scheduler isn't
        # available...). XXX(lifeless) this applies to all ComputeManagers
        # and once I feature freeze is over we should push that to nova
        # directly.
        try:
            self.update_available_resource(nova.context.get_admin_context())
        except Exception:
            pass

    @lockutils.synchronized(CCM_SEMAPHORE, 'ironic-')
    def _update_resources(self):
        """Updates resources while protecting against a race on
        self._resource_tracker_dict.
        """
        self.update_available_resource(nova.context.get_admin_context())

    def terminate_instance(self, context, instance, bdms, reservations):
        """Terminate an instance on a node.

        We override this method and force a post-termination update to Nova's
        resources. This avoids having to wait for a Nova periodic task tick
        before nodes can be reused.
        """
        super(ClusteredComputeManager, self).terminate_instance(context,
                                                                instance,
                                                                bdms,
                                                                reservations)
        self._update_resources()
