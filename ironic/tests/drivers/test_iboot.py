# -*- coding: utf-8 -*-
#
# Copyright 2014 Red Hat, Inc.
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

"""Test class for iBoot PDU driver module."""

import mock

from ironic.common import driver_factory
from ironic.common import exception
from ironic.common import states
from ironic.conductor import task_manager
from ironic.db import api as dbapi
from ironic.drivers.modules import iboot
from ironic.tests.conductor import utils as mgr_utils
from ironic.tests.db import base as db_base
from ironic.tests.db import utils as db_utils
from ironic.tests.objects import utils as obj_utils


INFO_DICT = db_utils.get_test_iboot_info()


class IBootPrivateMethodTestCase(db_base.DbTestCase):

    def setUp(self):
        super(IBootPrivateMethodTestCase, self).setUp()
        self.dbapi = dbapi.get_instance()

    def test__parse_driver_info_good(self):
        node = obj_utils.create_test_node(
                self.context,
                driver='fake_iboot',
                driver_info=INFO_DICT)
        info = iboot._parse_driver_info(node)
        self.assertIsNotNone(info.get('address'))
        self.assertIsNotNone(info.get('username'))
        self.assertIsNotNone(info.get('password'))
        self.assertIsNotNone(info.get('port'))
        self.assertIsNotNone(info.get('relay_id'))

    def test__parse_driver_info_good_with_explicit_port(self):
        info = dict(INFO_DICT)
        info['iboot_port'] = '1234'
        node = obj_utils.create_test_node(
                self.context,
                driver='fake_iboot',
                driver_info=info)
        info = iboot._parse_driver_info(node)
        self.assertEqual(1234, info.get('port'))

    def test__parse_driver_info_good_with_explicit_relay_id(self):
        info = dict(INFO_DICT)
        info['iboot_relay_id'] = '2'
        node = obj_utils.create_test_node(
                self.context,
                driver='fake_iboot',
                driver_info=info)
        info = iboot._parse_driver_info(node)
        self.assertEqual(2, info.get('relay_id'))

    def test__parse_driver_info_missing_address(self):
        info = dict(INFO_DICT)
        del info['iboot_address']
        node = obj_utils.create_test_node(
                self.context,
                driver='fake_iboot',
                driver_info=info)
        self.assertRaises(exception.MissingParameterValue,
                          iboot._parse_driver_info,
                          node)

    def test__parse_driver_info_missing_username(self):
        info = dict(INFO_DICT)
        del info['iboot_username']
        node = obj_utils.create_test_node(
                self.context,
                driver='fake_iboot',
                driver_info=info)
        self.assertRaises(exception.MissingParameterValue,
                          iboot._parse_driver_info,
                          node)

    def test__parse_driver_info_missing_password(self):
        info = dict(INFO_DICT)
        del info['iboot_password']
        node = obj_utils.create_test_node(
                self.context,
                driver='fake_iboot',
                driver_info=info)
        self.assertRaises(exception.MissingParameterValue,
                          iboot._parse_driver_info,
                          node)

    def test__parse_driver_info_bad_port(self):
        info = dict(INFO_DICT)
        info['iboot_port'] = 'not-integer'
        node = obj_utils.create_test_node(
                self.context,
                driver='fake_iboot',
                driver_info=info)
        self.assertRaises(exception.InvalidParameterValue,
                          iboot._parse_driver_info,
                          node)

    def test__parse_driver_info_bad_relay_id(self):
        info = dict(INFO_DICT)
        info['iboot_relay_id'] = 'not-integer'
        node = obj_utils.create_test_node(
                self.context,
                driver='fake_iboot',
                driver_info=info)
        self.assertRaises(exception.InvalidParameterValue,
                          iboot._parse_driver_info,
                          node)

    @mock.patch.object(iboot, '_get_connection')
    def test__power_status_on(self, mock_get_conn):
        mock_connection = mock.Mock()
        mock_connection.get_relays.return_value = [True]
        mock_get_conn.return_value = mock_connection
        node = obj_utils.create_test_node(
                self.context,
                driver='fake_iboot',
                driver_info=INFO_DICT)
        info = iboot._parse_driver_info(node)

        status = iboot._power_status(info)

        self.assertEqual(states.POWER_ON, status)
        mock_get_conn.assert_called_once_with(info)
        mock_connection.get_relays.assert_called_once_with()

    @mock.patch.object(iboot, '_get_connection')
    def test__power_status_off(self, mock_get_conn):
        mock_connection = mock.Mock()
        mock_connection.get_relays.return_value = [False]
        mock_get_conn.return_value = mock_connection
        node = obj_utils.create_test_node(
                self.context,
                driver='fake_iboot',
                driver_info=INFO_DICT)
        info = iboot._parse_driver_info(node)

        status = iboot._power_status(info)

        self.assertEqual(states.POWER_OFF, status)
        mock_get_conn.assert_called_once_with(info)
        mock_connection.get_relays.assert_called_once_with()

    @mock.patch.object(iboot, '_get_connection')
    def test__power_status_exception(self, mock_get_conn):
        mock_connection = mock.Mock()
        mock_connection.get_relays.return_value = None
        mock_get_conn.return_value = mock_connection
        node = obj_utils.create_test_node(
                self.context,
                driver='fake_iboot',
                driver_info=INFO_DICT)
        info = iboot._parse_driver_info(node)

        self.assertRaises(exception.IBootOperationError,
                          iboot._power_status,
                          info)

        mock_get_conn.assert_called_once_with(info)
        mock_connection.get_relays.assert_called_once_with()

    @mock.patch.object(iboot, '_get_connection')
    def test__power_status_error(self, mock_get_conn):
        mock_connection = mock.Mock()
        mock_connection.get_relays.return_value = list()
        mock_get_conn.return_value = mock_connection
        node = obj_utils.create_test_node(
                self.context,
                driver='fake_iboot',
                driver_info=INFO_DICT)
        info = iboot._parse_driver_info(node)

        status = iboot._power_status(info)

        self.assertEqual(states.ERROR, status)
        mock_get_conn.assert_called_once_with(info)
        mock_connection.get_relays.assert_called_once_with()


class IBootDriverTestCase(db_base.DbTestCase):

    def setUp(self):
        super(IBootDriverTestCase, self).setUp()
        self.dbapi = dbapi.get_instance()
        mgr_utils.mock_the_extension_manager(driver='fake_iboot')
        self.driver = driver_factory.get_driver('fake_iboot')
        self.node = obj_utils.create_test_node(
                self.context,
                driver='fake_iboot',
                driver_info=INFO_DICT)
        self.info = iboot._parse_driver_info(self.node)

    def test_get_properties(self):
        expected = iboot.COMMON_PROPERTIES
        with task_manager.acquire(self.context, self.node.uuid,
                shared=True) as task:
            self.assertEqual(expected, task.driver.get_properties())

    @mock.patch.object(iboot, '_power_status')
    @mock.patch.object(iboot, '_switch')
    def test_set_power_state_good(self, mock_switch, mock_power_status):
        mock_power_status.return_value = states.POWER_ON

        with task_manager.acquire(self.context, self.node.uuid) as task:
            task.driver.power.set_power_state(task, states.POWER_ON)

        # ensure functions were called with the valid parameters
        mock_switch.assert_called_once_with(self.info, True)
        mock_power_status.assert_called_once_with(self.info)

    @mock.patch.object(iboot, '_power_status')
    @mock.patch.object(iboot, '_switch')
    def test_set_power_state_bad(self, mock_switch, mock_power_status):
        mock_power_status.return_value = states.POWER_OFF

        with task_manager.acquire(self.context, self.node.uuid) as task:
            self.assertRaises(exception.PowerStateFailure,
                              task.driver.power.set_power_state,
                              task, states.POWER_ON)

        # ensure functions were called with the valid parameters
        mock_switch.assert_called_once_with(self.info, True)
        mock_power_status.assert_called_once_with(self.info)

    @mock.patch.object(iboot, '_power_status')
    @mock.patch.object(iboot, '_switch')
    def test_set_power_state_invalid_parameter(self, mock_switch,
                                               mock_power_status):
        mock_power_status.return_value = states.POWER_ON

        with task_manager.acquire(self.context, self.node.uuid) as task:
            self.assertRaises(exception.InvalidParameterValue,
                              task.driver.power.set_power_state,
                              task, states.NOSTATE)

    @mock.patch.object(iboot, '_power_status')
    @mock.patch.object(iboot, '_switch')
    def test_reboot_good(self, mock_switch, mock_power_status):
        manager = mock.MagicMock()
        mock_power_status.return_value = states.POWER_ON

        manager.attach_mock(mock_switch, 'switch')
        expected = [mock.call.switch(self.info, False),
                    mock.call.switch(self.info, True)]

        with task_manager.acquire(self.context, self.node.uuid) as task:
            task.driver.power.reboot(task)

        self.assertEqual(manager.mock_calls, expected)

    @mock.patch.object(iboot, '_power_status')
    @mock.patch.object(iboot, '_switch')
    def test_reboot_bad(self, mock_switch, mock_power_status):
        manager = mock.MagicMock()
        mock_power_status.return_value = states.POWER_OFF

        manager.attach_mock(mock_switch, 'switch')
        expected = [mock.call.switch(self.info, False),
                    mock.call.switch(self.info, True)]

        with task_manager.acquire(self.context, self.node.uuid) as task:
            self.assertRaises(exception.PowerStateFailure,
                              task.driver.power.reboot, task)

        self.assertEqual(manager.mock_calls, expected)

    @mock.patch.object(iboot, '_power_status')
    def test_get_power_state(self, mock_power_status):
        mock_power_status.return_value = states.POWER_ON

        with task_manager.acquire(self.context, self.node.uuid) as task:
            state = task.driver.power.get_power_state(task)
            self.assertEqual(state, states.POWER_ON)

        # ensure functions were called with the valid parameters
        mock_power_status.assert_called_once_with(self.info)

    @mock.patch.object(iboot, '_parse_driver_info')
    def test_validate_good(self, parse_drv_info_mock):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            task.driver.power.validate(task)
        self.assertEqual(1, parse_drv_info_mock.call_count)

    @mock.patch.object(iboot, '_parse_driver_info')
    def test_validate_fails(self, parse_drv_info_mock):
        side_effect = exception.InvalidParameterValue("Bad input")
        parse_drv_info_mock.side_effect = side_effect
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            self.assertRaises(exception.InvalidParameterValue,
                              task.driver.power.validate, task)
        self.assertEqual(1, parse_drv_info_mock.call_count)
