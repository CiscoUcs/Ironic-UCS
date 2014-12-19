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
Unit Tests for :py:class:`ironic.conductor.rpcapi.ConductorAPI`.
"""

import copy

import mock
from oslo.config import cfg

from ironic.common import boot_devices
from ironic.common import exception
from ironic.common import states
from ironic.conductor import manager as conductor_manager
from ironic.conductor import rpcapi as conductor_rpcapi
from ironic.db import api as dbapi
from ironic import objects
from ironic.tests import base as tests_base
from ironic.tests.db import base
from ironic.tests.db import utils as dbutils

CONF = cfg.CONF


class ConductorRPCAPITestCase(tests_base.TestCase):

    def test_versions_in_sync(self):
        self.assertEqual(
            conductor_manager.ConductorManager.RPC_API_VERSION,
            conductor_rpcapi.ConductorAPI.RPC_API_VERSION)


class RPCAPITestCase(base.DbTestCase):

    def setUp(self):
        super(RPCAPITestCase, self).setUp()
        self.dbapi = dbapi.get_instance()
        self.fake_node = dbutils.get_test_node(driver='fake-driver')
        self.fake_node_obj = objects.Node._from_db_object(
                                                    objects.Node(self.context),
                                                    self.fake_node)

    def test_serialized_instance_has_uuid(self):
        self.assertTrue('uuid' in self.fake_node)

    def test_get_topic_for_known_driver(self):
        CONF.set_override('host', 'fake-host')
        self.dbapi.register_conductor({'hostname': 'fake-host',
                                       'drivers': ['fake-driver']})

        rpcapi = conductor_rpcapi.ConductorAPI(topic='fake-topic')
        expected_topic = 'fake-topic.fake-host'
        self.assertEqual(expected_topic,
                         rpcapi.get_topic_for(self.fake_node_obj))

    def test_get_topic_for_unknown_driver(self):
        CONF.set_override('host', 'fake-host')
        self.dbapi.register_conductor({'hostname': 'fake-host',
                                       'drivers': ['other-driver']})

        rpcapi = conductor_rpcapi.ConductorAPI(topic='fake-topic')
        self.assertRaises(exception.NoValidHost,
                         rpcapi.get_topic_for,
                         self.fake_node_obj)

    def test_get_topic_doesnt_cache(self):
        CONF.set_override('host', 'fake-host')

        rpcapi = conductor_rpcapi.ConductorAPI(topic='fake-topic')
        self.assertRaises(exception.NoValidHost,
                         rpcapi.get_topic_for,
                         self.fake_node_obj)

        self.dbapi.register_conductor({'hostname': 'fake-host',
                                       'drivers': ['fake-driver']})

        rpcapi = conductor_rpcapi.ConductorAPI(topic='fake-topic')
        expected_topic = 'fake-topic.fake-host'
        self.assertEqual(expected_topic,
                         rpcapi.get_topic_for(self.fake_node_obj))

    def test_get_topic_for_driver_known_driver(self):
        CONF.set_override('host', 'fake-host')
        self.dbapi.register_conductor({
            'hostname': 'fake-host',
            'drivers': ['fake-driver'],
        })
        rpcapi = conductor_rpcapi.ConductorAPI(topic='fake-topic')
        self.assertEqual('fake-topic.fake-host',
                         rpcapi.get_topic_for_driver('fake-driver'))

    def test_get_topic_for_driver_unknown_driver(self):
        CONF.set_override('host', 'fake-host')
        self.dbapi.register_conductor({
            'hostname': 'fake-host',
            'drivers': ['other-driver'],
        })
        rpcapi = conductor_rpcapi.ConductorAPI(topic='fake-topic')
        self.assertRaises(exception.DriverNotFound,
                          rpcapi.get_topic_for_driver,
                          'fake-driver')

    def test_get_topic_for_driver_doesnt_cache(self):
        CONF.set_override('host', 'fake-host')
        rpcapi = conductor_rpcapi.ConductorAPI(topic='fake-topic')
        self.assertRaises(exception.DriverNotFound,
                          rpcapi.get_topic_for_driver,
                          'fake-driver')

        self.dbapi.register_conductor({
            'hostname': 'fake-host',
            'drivers': ['fake-driver'],
        })
        rpcapi = conductor_rpcapi.ConductorAPI(topic='fake-topic')
        self.assertEqual('fake-topic.fake-host',
                         rpcapi.get_topic_for_driver('fake-driver'))

    def _test_rpcapi(self, method, rpc_method, **kwargs):
        rpcapi = conductor_rpcapi.ConductorAPI(topic='fake-topic')

        expected_retval = 'hello world' if rpc_method == 'call' else None

        expected_topic = 'fake-topic'
        if 'host' in kwargs:
            expected_topic += ".%s" % kwargs['host']

        target = {
            "topic": expected_topic,
            "version": kwargs.pop('version', rpcapi.RPC_API_VERSION)
        }
        expected_msg = copy.deepcopy(kwargs)

        self.fake_args = None
        self.fake_kwargs = None

        def _fake_prepare_method(*args, **kwargs):
            for kwd in kwargs:
                self.assertEqual(kwargs[kwd], target[kwd])
            return rpcapi.client

        def _fake_rpc_method(*args, **kwargs):
            self.fake_args = args
            self.fake_kwargs = kwargs
            if expected_retval:
                return expected_retval

        with mock.patch.object(rpcapi.client, "prepare") as mock_prepared:
            mock_prepared.side_effect = _fake_prepare_method

            with mock.patch.object(rpcapi.client, rpc_method) as mock_method:
                mock_method.side_effect = _fake_rpc_method
                retval = getattr(rpcapi, method)(self.context, **kwargs)
                self.assertEqual(retval, expected_retval)
                expected_args = [self.context, method, expected_msg]
                for arg, expected_arg in zip(self.fake_args, expected_args):
                    self.assertEqual(arg, expected_arg)

    def test_update_node(self):
        self._test_rpcapi('update_node',
                          'call',
                          version='1.1',
                          node_obj=self.fake_node)

    def test_change_node_power_state(self):
        self._test_rpcapi('change_node_power_state',
                          'call',
                          version='1.6',
                          node_id=self.fake_node['uuid'],
                          new_state=states.POWER_ON)

    def test_pass_vendor_info(self):
        self._test_rpcapi('vendor_passthru',
                          'call',
                          version='1.12',
                          node_id=self.fake_node['uuid'],
                          driver_method='test-driver-method',
                          info={"test_info": "test_value"})

    def test_driver_vendor_passthru(self):
        self._test_rpcapi('driver_vendor_passthru',
                          'call',
                          version='1.14',
                          driver_name='test-driver-name',
                          driver_method='test-driver-method',
                          info={'test_key': 'test_value'})

    def test_do_node_deploy(self):
        self._test_rpcapi('do_node_deploy',
                          'call',
                          version='1.15',
                          node_id=self.fake_node['uuid'],
                          rebuild=False)

    def test_do_node_tear_down(self):
        self._test_rpcapi('do_node_tear_down',
                          'call',
                          version='1.6',
                          node_id=self.fake_node['uuid'])

    def test_validate_driver_interfaces(self):
        self._test_rpcapi('validate_driver_interfaces',
                          'call',
                          version='1.5',
                          node_id=self.fake_node['uuid'])

    def test_change_node_maintenance_mode(self):
        self._test_rpcapi('change_node_maintenance_mode',
                          'call',
                          version='1.8',
                          node_id=self.fake_node['uuid'],
                          mode=True)

    def test_destroy_node(self):
        self._test_rpcapi('destroy_node',
                          'call',
                          version='1.9',
                          node_id=self.fake_node['uuid'])

    def test_get_console_information(self):
        self._test_rpcapi('get_console_information',
                          'call',
                          version='1.11',
                          node_id=self.fake_node['uuid'])

    def test_set_console_mode(self):
        self._test_rpcapi('set_console_mode',
                          'call',
                          version='1.11',
                          node_id=self.fake_node['uuid'],
                          enabled=True)

    def test_update_port(self):
        fake_port = dbutils.get_test_port()
        self._test_rpcapi('update_port',
                          'call',
                          version='1.13',
                          port_obj=fake_port)

    def test_get_driver_properties(self):
        self._test_rpcapi('get_driver_properties',
                          'call',
                          version='1.16',
                          driver_name='fake-driver')

    def test_set_boot_device(self):
        self._test_rpcapi('set_boot_device',
                          'call',
                          version='1.17',
                          node_id=self.fake_node['uuid'],
                          device=boot_devices.DISK,
                          persistent=False)

    def test_get_boot_device(self):
        self._test_rpcapi('get_boot_device',
                          'call',
                          version='1.17',
                          node_id=self.fake_node['uuid'])

    def test_get_supported_boot_devices(self):
        self._test_rpcapi('get_supported_boot_devices',
                          'call',
                          version='1.17',
                          node_id=self.fake_node['uuid'])
