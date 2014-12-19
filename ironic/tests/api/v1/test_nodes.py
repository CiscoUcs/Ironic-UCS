# -*- encoding: utf-8 -*-
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
Tests for the API /nodes/ methods.
"""

import datetime

import mock
from oslo.config import cfg
from oslo.utils import timeutils
from six.moves.urllib import parse as urlparse
from testtools.matchers import HasLength

from ironic.common import boot_devices
from ironic.common import exception
from ironic.common import states
from ironic.common import utils
from ironic.conductor import rpcapi
from ironic import objects
from ironic.tests.api import base
from ironic.tests.api import utils as apiutils
from ironic.tests.db import utils as dbutils
from ironic.tests.objects import utils as obj_utils


# NOTE(lucasagomes): When creating a node via API (POST)
#                    we have to use chassis_uuid
def post_get_test_node(**kw):
    node = apiutils.node_post_data(**kw)
    chassis = dbutils.get_test_chassis()
    node['chassis_id'] = None
    node['chassis_uuid'] = kw.get('chassis_uuid', chassis['uuid'])
    return node


class TestListNodes(base.FunctionalTest):

    def setUp(self):
        super(TestListNodes, self).setUp()
        self.chassis = obj_utils.create_test_chassis(self.context)
        p = mock.patch.object(rpcapi.ConductorAPI, 'get_topic_for')
        self.mock_gtf = p.start()
        self.mock_gtf.return_value = 'test-topic'
        self.addCleanup(p.stop)

    def _create_association_test_nodes(self):
        #create some unassociated nodes
        unassociated_nodes = []
        for id in range(3):
            node = obj_utils.create_test_node(self.context,
                                              id=id,
                                              uuid=utils.generate_uuid())
            unassociated_nodes.append(node.uuid)

        #created some associated nodes
        associated_nodes = []
        for id in range(3, 7):
            node = obj_utils.create_test_node(
                    self.context, id=id, uuid=utils.generate_uuid(),
                    instance_uuid=utils.generate_uuid())
            associated_nodes.append(node['uuid'])
        return {'associated': associated_nodes,
                'unassociated': unassociated_nodes}

    def test_empty(self):
        data = self.get_json('/nodes')
        self.assertEqual([], data['nodes'])

    def test_one(self):
        node = obj_utils.create_test_node(self.context)
        data = self.get_json('/nodes')
        self.assertIn('instance_uuid', data['nodes'][0])
        self.assertIn('maintenance', data['nodes'][0])
        self.assertIn('power_state', data['nodes'][0])
        self.assertIn('provision_state', data['nodes'][0])
        self.assertIn('uuid', data['nodes'][0])
        self.assertEqual(node['uuid'], data['nodes'][0]["uuid"])
        self.assertNotIn('driver', data['nodes'][0])
        self.assertNotIn('driver_info', data['nodes'][0])
        self.assertNotIn('extra', data['nodes'][0])
        self.assertNotIn('properties', data['nodes'][0])
        self.assertNotIn('chassis_uuid', data['nodes'][0])
        self.assertNotIn('reservation', data['nodes'][0])
        self.assertNotIn('console_enabled', data['nodes'][0])
        self.assertNotIn('target_power_state', data['nodes'][0])
        self.assertNotIn('target_provision_state', data['nodes'][0])
        self.assertNotIn('provision_updated_at', data['nodes'][0])
        # never expose the chassis_id
        self.assertNotIn('chassis_id', data['nodes'][0])

    def test_get_one(self):
        node = obj_utils.create_test_node(self.context)
        data = self.get_json('/nodes/%s' % node['uuid'])
        self.assertEqual(node.uuid, data['uuid'])
        self.assertIn('driver', data)
        self.assertIn('driver_info', data)
        self.assertIn('extra', data)
        self.assertIn('properties', data)
        self.assertIn('chassis_uuid', data)
        self.assertIn('reservation', data)
        # never expose the chassis_id
        self.assertNotIn('chassis_id', data)

    def test_detail(self):
        node = obj_utils.create_test_node(self.context)
        data = self.get_json('/nodes/detail')
        self.assertEqual(node['uuid'], data['nodes'][0]["uuid"])
        self.assertIn('driver', data['nodes'][0])
        self.assertIn('driver_info', data['nodes'][0])
        self.assertIn('extra', data['nodes'][0])
        self.assertIn('properties', data['nodes'][0])
        self.assertIn('chassis_uuid', data['nodes'][0])
        self.assertIn('reservation', data['nodes'][0])
        self.assertIn('maintenance', data['nodes'][0])
        self.assertIn('console_enabled', data['nodes'][0])
        self.assertIn('target_power_state', data['nodes'][0])
        self.assertIn('target_provision_state', data['nodes'][0])
        self.assertIn('provision_updated_at', data['nodes'][0])
        # never expose the chassis_id
        self.assertNotIn('chassis_id', data['nodes'][0])

    def test_detail_against_single(self):
        node = obj_utils.create_test_node(self.context)
        response = self.get_json('/nodes/%s/detail' % node['uuid'],
                                 expect_errors=True)
        self.assertEqual(404, response.status_int)

    def test_many(self):
        nodes = []
        for id in range(5):
            node = obj_utils.create_test_node(self.context, id=id,
                                              uuid=utils.generate_uuid())
            nodes.append(node.uuid)
        data = self.get_json('/nodes')
        self.assertEqual(len(nodes), len(data['nodes']))

        uuids = [n['uuid'] for n in data['nodes']]
        self.assertEqual(sorted(nodes), sorted(uuids))

    def test_links(self):
        uuid = utils.generate_uuid()
        obj_utils.create_test_node(self.context, id=1, uuid=uuid)
        data = self.get_json('/nodes/%s' % uuid)
        self.assertIn('links', data.keys())
        self.assertEqual(2, len(data['links']))
        self.assertIn(uuid, data['links'][0]['href'])
        for l in data['links']:
            bookmark = l['rel'] == 'bookmark'
            self.assertTrue(self.validate_link(l['href'], bookmark=bookmark))

    def test_collection_links(self):
        nodes = []
        for id in range(5):
            node = obj_utils.create_test_node(self.context, id=id,
                                              uuid=utils.generate_uuid())
            nodes.append(node.uuid)
        data = self.get_json('/nodes/?limit=3')
        self.assertEqual(3, len(data['nodes']))

        next_marker = data['nodes'][-1]['uuid']
        self.assertIn(next_marker, data['next'])

    def test_collection_links_default_limit(self):
        cfg.CONF.set_override('max_limit', 3, 'api')
        nodes = []
        for id in range(5):
            node = obj_utils.create_test_node(self.context, id=id,
                                              uuid=utils.generate_uuid())
            nodes.append(node.uuid)
        data = self.get_json('/nodes')
        self.assertEqual(3, len(data['nodes']))

        next_marker = data['nodes'][-1]['uuid']
        self.assertIn(next_marker, data['next'])

    def test_ports_subresource_link(self):
        node = obj_utils.create_test_node(self.context)
        data = self.get_json('/nodes/%s' % node.uuid)
        self.assertIn('ports', data.keys())

    def test_ports_subresource(self):
        node = obj_utils.create_test_node(self.context)

        for id_ in range(2):
            obj_utils.create_test_port(self.context, id=id_, node_id=node.id,
                                       uuid=utils.generate_uuid(),
                                       address='52:54:00:cf:2d:3%s' % id_)

        data = self.get_json('/nodes/%s/ports' % node.uuid)
        self.assertEqual(2, len(data['ports']))
        self.assertNotIn('next', data.keys())

        # Test collection pagination
        data = self.get_json('/nodes/%s/ports?limit=1' % node.uuid)
        self.assertEqual(1, len(data['ports']))
        self.assertIn('next', data.keys())

    def test_ports_subresource_noid(self):
        node = obj_utils.create_test_node(self.context)
        obj_utils.create_test_port(self.context, node_id=node.id)
        # No node id specified
        response = self.get_json('/nodes/ports', expect_errors=True)
        self.assertEqual(400, response.status_int)

    def test_ports_subresource_node_not_found(self):
        non_existent_uuid = 'eeeeeeee-cccc-aaaa-bbbb-cccccccccccc'
        response = self.get_json('/nodes/%s/ports' % non_existent_uuid,
                                 expect_errors=True)
        self.assertEqual(404, response.status_int)

    @mock.patch.object(timeutils, 'utcnow')
    def test_node_states(self, mock_utcnow):
        fake_state = 'fake-state'
        fake_error = 'fake-error'
        test_time = datetime.datetime(2000, 1, 1, 0, 0)
        mock_utcnow.return_value = test_time
        node = obj_utils.create_test_node(self.context,
                                          power_state=fake_state,
                                          target_power_state=fake_state,
                                          provision_state=fake_state,
                                          target_provision_state=fake_state,
                                          provision_updated_at=test_time,
                                          last_error=fake_error)
        data = self.get_json('/nodes/%s/states' % node.uuid)
        self.assertEqual(fake_state, data['power_state'])
        self.assertEqual(fake_state, data['target_power_state'])
        self.assertEqual(fake_state, data['provision_state'])
        self.assertEqual(fake_state, data['target_provision_state'])
        prov_up_at = timeutils.parse_isotime(
                        data['provision_updated_at']).replace(tzinfo=None)
        self.assertEqual(test_time, prov_up_at)
        self.assertEqual(fake_error, data['last_error'])
        self.assertFalse(data['console_enabled'])

    def test_node_by_instance_uuid(self):
        node = obj_utils.create_test_node(self.context,
                                          uuid=utils.generate_uuid(),
                                          instance_uuid=utils.generate_uuid())
        instance_uuid = node.instance_uuid

        data = self.get_json('/nodes?instance_uuid=%s' % instance_uuid)

        self.assertThat(data['nodes'], HasLength(1))
        self.assertEqual(node['instance_uuid'],
                         data['nodes'][0]["instance_uuid"])

    def test_node_by_instance_uuid_wrong_uuid(self):
        obj_utils.create_test_node(self.context, uuid=utils.generate_uuid(),
                                   instance_uuid=utils.generate_uuid())
        wrong_uuid = utils.generate_uuid()

        data = self.get_json('/nodes?instance_uuid=%s' % wrong_uuid)

        self.assertThat(data['nodes'], HasLength(0))

    def test_node_by_instance_uuid_invalid_uuid(self):
        response = self.get_json('/nodes?instance_uuid=fake',
                                 expect_errors=True)

        self.assertEqual('application/json', response.content_type)
        self.assertEqual(400, response.status_code)

    def test_associated_nodes_insensitive(self):
        associated_nodes = self._create_association_test_nodes().\
                get('associated')

        data = self.get_json('/nodes?associated=true')
        data1 = self.get_json('/nodes?associated=True')

        uuids = [n['uuid'] for n in data['nodes']]
        uuids1 = [n['uuid'] for n in data1['nodes']]
        self.assertEqual(sorted(associated_nodes), sorted(uuids1))
        self.assertEqual(sorted(associated_nodes), sorted(uuids))

    def test_associated_nodes_error(self):
        self._create_association_test_nodes()
        response = self.get_json('/nodes?associated=blah', expect_errors=True)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(400, response.status_code)
        self.assertTrue(response.json['error_message'])

    def test_unassociated_nodes_insensitive(self):
        unassociated_nodes = self._create_association_test_nodes().\
                get('unassociated')

        data = self.get_json('/nodes?associated=false')
        data1 = self.get_json('/nodes?associated=FALSE')

        uuids = [n['uuid'] for n in data['nodes']]
        uuids1 = [n['uuid'] for n in data1['nodes']]
        self.assertEqual(sorted(unassociated_nodes), sorted(uuids1))
        self.assertEqual(sorted(unassociated_nodes), sorted(uuids))

    def test_unassociated_nodes_with_limit(self):
        unassociated_nodes = self._create_association_test_nodes().\
                get('unassociated')

        data = self.get_json('/nodes?associated=False&limit=2')

        self.assertThat(data['nodes'], HasLength(2))
        self.assertTrue(data['nodes'][0]['uuid'] in unassociated_nodes)

    def test_next_link_with_association(self):
        self._create_association_test_nodes()
        data = self.get_json('/nodes/?limit=3&associated=True')
        self.assertThat(data['nodes'], HasLength(3))
        self.assertIn('associated=True', data['next'])

    def test_detail_with_association_filter(self):
        associated_nodes = self._create_association_test_nodes().\
                get('associated')
        data = self.get_json('/nodes/detail?associated=true')
        self.assertIn('driver', data['nodes'][0])
        self.assertEqual(len(associated_nodes), len(data['nodes']))

    def test_next_link_with_association_with_detail(self):
        self._create_association_test_nodes()
        data = self.get_json('/nodes/detail?limit=3&associated=true')
        self.assertThat(data['nodes'], HasLength(3))
        self.assertIn('driver', data['nodes'][0])
        self.assertIn('associated=True', data['next'])

    def test_detail_with_instance_uuid(self):
        node = obj_utils.create_test_node(self.context,
                                          uuid=utils.generate_uuid(),
                                          instance_uuid=utils.generate_uuid())
        instance_uuid = node.instance_uuid

        data = self.get_json('/nodes/detail?instance_uuid=%s' % instance_uuid)

        self.assertEqual(node['instance_uuid'],
                         data['nodes'][0]["instance_uuid"])
        self.assertIn('driver', data['nodes'][0])
        self.assertIn('driver_info', data['nodes'][0])
        self.assertIn('extra', data['nodes'][0])
        self.assertIn('properties', data['nodes'][0])
        self.assertIn('chassis_uuid', data['nodes'][0])
        # never expose the chassis_id
        self.assertNotIn('chassis_id', data['nodes'][0])

    def test_maintenance_nodes(self):
        nodes = []
        for id in range(5):
            node = obj_utils.create_test_node(self.context, id=id,
                                              uuid=utils.generate_uuid(),
                                              maintenance=id % 2)
            nodes.append(node)

        data = self.get_json('/nodes?maintenance=true')
        uuids = [n['uuid'] for n in data['nodes']]
        test_uuids_1 = [n.uuid for n in nodes if n.maintenance]
        self.assertEqual(sorted(test_uuids_1), sorted(uuids))

        data = self.get_json('/nodes?maintenance=false')
        uuids = [n['uuid'] for n in data['nodes']]
        test_uuids_0 = [n.uuid for n in nodes if not n.maintenance]
        self.assertEqual(sorted(test_uuids_0), sorted(uuids))

    def test_maintenance_nodes_error(self):
        response = self.get_json('/nodes?associated=true&maintenance=blah',
                                 expect_errors=True)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(400, response.status_code)
        self.assertTrue(response.json['error_message'])

    def test_maintenance_nodes_associated(self):
        self._create_association_test_nodes()
        node = obj_utils.create_test_node(self.context,
                                          instance_uuid=utils.generate_uuid(),
                                          maintenance=True)

        data = self.get_json('/nodes?associated=true&maintenance=false')
        uuids = [n['uuid'] for n in data['nodes']]
        self.assertNotIn(node.uuid, uuids)
        data = self.get_json('/nodes?associated=true&maintenance=true')
        uuids = [n['uuid'] for n in data['nodes']]
        self.assertIn(node.uuid, uuids)
        data = self.get_json('/nodes?associated=true&maintenance=TruE')
        uuids = [n['uuid'] for n in data['nodes']]
        self.assertIn(node.uuid, uuids)

    def test_get_console_information(self):
        node = obj_utils.create_test_node(self.context)
        expected_console_info = {'test': 'test-data'}
        expected_data = {'console_enabled': True,
                         'console_info': expected_console_info}
        with mock.patch.object(rpcapi.ConductorAPI,
                               'get_console_information') as mock_gci:
            mock_gci.return_value = expected_console_info
            data = self.get_json('/nodes/%s/states/console' % node.uuid)
            self.assertEqual(expected_data, data)
            mock_gci.assert_called_once_with(mock.ANY, node.uuid, 'test-topic')

    def test_get_console_information_console_disabled(self):
        node = obj_utils.create_test_node(self.context)
        expected_data = {'console_enabled': False,
                         'console_info': None}
        with mock.patch.object(rpcapi.ConductorAPI,
                               'get_console_information') as mock_gci:
            mock_gci.side_effect = exception.NodeConsoleNotEnabled(
                    node=node.uuid)
            data = self.get_json('/nodes/%s/states/console' % node.uuid)
            self.assertEqual(expected_data, data)
            mock_gci.assert_called_once_with(mock.ANY, node.uuid, 'test-topic')

    def test_get_console_information_not_supported(self):
        node = obj_utils.create_test_node(self.context)
        with mock.patch.object(rpcapi.ConductorAPI,
                               'get_console_information') as mock_gci:
            mock_gci.side_effect = exception.UnsupportedDriverExtension(
                                   extension='console', driver='test-driver')
            ret = self.get_json('/nodes/%s/states/console' % node.uuid,
                                expect_errors=True)
            self.assertEqual(400, ret.status_code)
            mock_gci.assert_called_once_with(mock.ANY, node.uuid, 'test-topic')

    @mock.patch.object(rpcapi.ConductorAPI, 'get_boot_device')
    def test_get_boot_device(self, mock_gbd):
        node = obj_utils.create_test_node(self.context)
        expected_data = {'boot_device': boot_devices.PXE, 'persistent': True}
        mock_gbd.return_value = expected_data
        data = self.get_json('/nodes/%s/management/boot_device' % node.uuid)
        self.assertEqual(expected_data, data)
        mock_gbd.assert_called_once_with(mock.ANY, node.uuid, 'test-topic')

    @mock.patch.object(rpcapi.ConductorAPI, 'get_boot_device')
    def test_get_boot_device_iface_not_supported(self, mock_gbd):
        node = obj_utils.create_test_node(self.context)
        mock_gbd.side_effect = exception.UnsupportedDriverExtension(
                                  extension='management', driver='test-driver')
        ret = self.get_json('/nodes/%s/management/boot_device' % node.uuid,
                            expect_errors=True)
        self.assertEqual(400, ret.status_code)
        self.assertTrue(ret.json['error_message'])
        mock_gbd.assert_called_once_with(mock.ANY, node.uuid, 'test-topic')

    @mock.patch.object(rpcapi.ConductorAPI, 'get_supported_boot_devices')
    def test_get_supported_boot_devices(self, mock_gsbd):
        mock_gsbd.return_value = [boot_devices.PXE]
        node = obj_utils.create_test_node(self.context)
        data = self.get_json('/nodes/%s/management/boot_device/supported'
                             % node.uuid)
        expected_data = {'supported_boot_devices': [boot_devices.PXE]}
        self.assertEqual(expected_data, data)
        mock_gsbd.assert_called_once_with(mock.ANY, node.uuid, 'test-topic')

    @mock.patch.object(rpcapi.ConductorAPI, 'get_supported_boot_devices')
    def test_get_supported_boot_devices_iface_not_supported(self, mock_gsbd):
        node = obj_utils.create_test_node(self.context)
        mock_gsbd.side_effect = exception.UnsupportedDriverExtension(
                                  extension='management', driver='test-driver')
        ret = self.get_json('/nodes/%s/management/boot_device/supported' %
                            node.uuid, expect_errors=True)
        self.assertEqual(400, ret.status_code)
        self.assertTrue(ret.json['error_message'])
        mock_gsbd.assert_called_once_with(mock.ANY, node.uuid, 'test-topic')


class TestPatch(base.FunctionalTest):

    def setUp(self):
        super(TestPatch, self).setUp()
        self.chassis = obj_utils.create_test_chassis(self.context)
        self.node = obj_utils.create_test_node(self.context)
        p = mock.patch.object(rpcapi.ConductorAPI, 'get_topic_for')
        self.mock_gtf = p.start()
        self.mock_gtf.return_value = 'test-topic'
        self.addCleanup(p.stop)
        p = mock.patch.object(rpcapi.ConductorAPI, 'update_node')
        self.mock_update_node = p.start()
        self.addCleanup(p.stop)
        p = mock.patch.object(rpcapi.ConductorAPI, 'change_node_power_state')
        self.mock_cnps = p.start()
        self.addCleanup(p.stop)

    def test_update_ok(self):
        self.mock_update_node.return_value = self.node
        self.mock_update_node.return_value.updated_at = \
                                   "2013-12-03T06:20:41.184720+00:00"
        response = self.patch_json('/nodes/%s' % self.node['uuid'],
                             [{'path': '/instance_uuid',
                               'value': 'aaaaaaaa-1111-bbbb-2222-cccccccccccc',
                               'op': 'replace'}])
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(200, response.status_code)
        self.assertEqual(self.mock_update_node.return_value.updated_at,
                         timeutils.parse_isotime(response.json['updated_at']))
        self.mock_update_node.assert_called_once_with(
                mock.ANY, mock.ANY, 'test-topic')

    def test_update_state(self):
        response = self.patch_json('/nodes/%s' % self.node['uuid'],
                                   [{'power_state': 'new state'}],
                                   expect_errors=True)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(400, response.status_code)
        self.assertTrue(response.json['error_message'])

    def test_update_fails_bad_driver_info(self):
        fake_err = 'Fake Error Message'
        self.mock_update_node.side_effect = exception.InvalidParameterValue(
                                                fake_err)

        response = self.patch_json('/nodes/%s' % self.node['uuid'],
                                   [{'path': '/driver_info/this',
                                     'value': 'foo',
                                     'op': 'add'},
                                    {'path': '/driver_info/that',
                                     'value': 'bar',
                                     'op': 'add'}],
                                   expect_errors=True)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(400, response.status_code)

        self.mock_update_node.assert_called_once_with(
                mock.ANY, mock.ANY, 'test-topic')

    def test_update_fails_bad_driver(self):
        self.mock_gtf.side_effect = exception.NoValidHost('Fake Error')

        response = self.patch_json('/nodes/%s' % self.node['uuid'],
                                   [{'path': '/driver',
                                     'value': 'bad-driver',
                                     'op': 'replace'}],
                                   expect_errors=True)

        self.assertEqual('application/json', response.content_type)
        self.assertEqual(400, response.status_code)

    def test_update_fails_bad_state(self):
        fake_err = 'Fake Power State'
        self.mock_update_node.side_effect = exception.NodeInWrongPowerState(
                    node=self.node['uuid'], pstate=fake_err)

        response = self.patch_json('/nodes/%s' % self.node['uuid'],
                             [{'path': '/instance_uuid',
                               'value': 'aaaaaaaa-1111-bbbb-2222-cccccccccccc',
                               'op': 'replace'}],
                                expect_errors=True)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(409, response.status_code)

        self.mock_update_node.assert_called_once_with(
                mock.ANY, mock.ANY, 'test-topic')

    def test_add_ok(self):
        self.mock_update_node.return_value = self.node

        response = self.patch_json('/nodes/%s' % self.node['uuid'],
                                   [{'path': '/extra/foo',
                                     'value': 'bar',
                                     'op': 'add'}])
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(200, response.status_code)

        self.mock_update_node.assert_called_once_with(
                mock.ANY, mock.ANY, 'test-topic')

    def test_add_root(self):
        self.mock_update_node.return_value = self.node
        response = self.patch_json('/nodes/%s' % self.node['uuid'],
                             [{'path': '/instance_uuid',
                               'value': 'aaaaaaaa-1111-bbbb-2222-cccccccccccc',
                               'op': 'add'}])
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(200, response.status_code)
        self.mock_update_node.assert_called_once_with(
                mock.ANY, mock.ANY, 'test-topic')

    def test_add_root_non_existent(self):
        response = self.patch_json('/nodes/%s' % self.node['uuid'],
                               [{'path': '/foo', 'value': 'bar', 'op': 'add'}],
                               expect_errors=True)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(400, response.status_code)
        self.assertTrue(response.json['error_message'])

    def test_remove_ok(self):
        self.mock_update_node.return_value = self.node

        response = self.patch_json('/nodes/%s' % self.node['uuid'],
                                   [{'path': '/extra',
                                     'op': 'remove'}])
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(200, response.status_code)

        self.mock_update_node.assert_called_once_with(
                mock.ANY, mock.ANY, 'test-topic')

    def test_remove_non_existent_property_fail(self):
        response = self.patch_json('/nodes/%s' % self.node['uuid'],
                             [{'path': '/extra/non-existent', 'op': 'remove'}],
                             expect_errors=True)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(400, response.status_code)
        self.assertTrue(response.json['error_message'])

    def test_update_state_in_progress(self):
        node = obj_utils.create_test_node(self.context, id=99,
                                          uuid=utils.generate_uuid(),
                                          target_power_state=states.POWER_OFF)
        response = self.patch_json('/nodes/%s' % node.uuid,
                                   [{'path': '/extra/foo', 'value': 'bar',
                                     'op': 'add'}], expect_errors=True)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(409, response.status_code)
        self.assertTrue(response.json['error_message'])

    def test_patch_ports_subresource(self):
        response = self.patch_json('/nodes/%s/ports' % self.node['uuid'],
                                   [{'path': '/extra/foo', 'value': 'bar',
                                     'op': 'add'}], expect_errors=True)
        self.assertEqual(403, response.status_int)

    def test_remove_uuid(self):
        response = self.patch_json('/nodes/%s' % self.node.uuid,
                                   [{'path': '/uuid', 'op': 'remove'}],
                                   expect_errors=True)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(400, response.status_code)
        self.assertTrue(response.json['error_message'])

    def test_remove_mandatory_field(self):
        response = self.patch_json('/nodes/%s' % self.node['uuid'],
                                   [{'path': '/driver', 'op': 'remove'}],
                                   expect_errors=True)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(400, response.status_code)
        self.assertTrue(response.json['error_message'])

    def test_replace_chassis_uuid(self):
        self.mock_update_node.return_value = self.node
        response = self.patch_json('/nodes/%s' % self.node.uuid,
                             [{'path': '/chassis_uuid',
                               'value': self.chassis.uuid,
                               'op': 'replace'}])
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(200, response.status_code)

    def test_add_chassis_uuid(self):
        self.mock_update_node.return_value = self.node
        response = self.patch_json('/nodes/%s' % self.node.uuid,
                             [{'path': '/chassis_uuid',
                               'value': self.chassis.uuid,
                               'op': 'add'}])
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(200, response.status_code)

    def test_add_chassis_id(self):
        response = self.patch_json('/nodes/%s' % self.node.uuid,
                             [{'path': '/chassis_id',
                               'value': '1',
                               'op': 'add'}],
                               expect_errors=True)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(400, response.status_code)
        self.assertTrue(response.json['error_message'])

    def test_replace_chassis_id(self):
        response = self.patch_json('/nodes/%s' % self.node.uuid,
                             [{'path': '/chassis_id',
                               'value': '1',
                               'op': 'replace'}],
                               expect_errors=True)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(400, response.status_code)
        self.assertTrue(response.json['error_message'])

    def test_remove_chassis_id(self):
        response = self.patch_json('/nodes/%s' % self.node.uuid,
                             [{'path': '/chassis_id',
                               'op': 'remove'}],
                               expect_errors=True)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(400, response.status_code)
        self.assertTrue(response.json['error_message'])

    def test_replace_non_existent_chassis_uuid(self):
        response = self.patch_json('/nodes/%s' % self.node['uuid'],
                             [{'path': '/chassis_uuid',
                               'value': 'eeeeeeee-dddd-cccc-bbbb-aaaaaaaaaaaa',
                               'op': 'replace'}], expect_errors=True)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(400, response.status_code)
        self.assertTrue(response.json['error_message'])

    def test_remove_internal_field(self):
        response = self.patch_json('/nodes/%s' % self.node['uuid'],
                                   [{'path': '/last_error', 'op': 'remove'}],
                                   expect_errors=True)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(400, response.status_code)
        self.assertTrue(response.json['error_message'])

    def test_replace_internal_field(self):
        response = self.patch_json('/nodes/%s' % self.node['uuid'],
                                   [{'path': '/power_state', 'op': 'replace',
                                     'value': 'fake-state'}],
                                   expect_errors=True)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(400, response.status_code)
        self.assertTrue(response.json['error_message'])

    def test_replace_maintenance(self):
        self.mock_update_node.return_value = self.node

        response = self.patch_json('/nodes/%s' % self.node.uuid,
                                   [{'path': '/maintenance', 'op': 'replace',
                                     'value': 'true'}])
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(200, response.status_code)

        self.mock_update_node.assert_called_once_with(
                mock.ANY, mock.ANY, 'test-topic')

    def test_replace_consoled_enabled(self):
        response = self.patch_json('/nodes/%s' % self.node['uuid'],
                                   [{'path': '/console_enabled',
                                     'op': 'replace', 'value': True}],
                                   expect_errors=True)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(400, response.status_code)
        self.assertTrue(response.json['error_message'])

    def test_replace_provision_updated_at(self):
        test_time = '2000-01-01 00:00:00'
        response = self.patch_json('/nodes/%s' % self.node['uuid'],
                                   [{'path': '/provision_updated_at',
                                     'op': 'replace', 'value': test_time}],
                                   expect_errors=True)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(400, response.status_code)
        self.assertTrue(response.json['error_message'])


class TestPost(base.FunctionalTest):

    def setUp(self):
        super(TestPost, self).setUp()
        self.chassis = obj_utils.create_test_chassis(self.context)
        p = mock.patch.object(rpcapi.ConductorAPI, 'get_topic_for')
        self.mock_gtf = p.start()
        self.mock_gtf.return_value = 'test-topic'
        self.addCleanup(p.stop)

    @mock.patch.object(timeutils, 'utcnow')
    def test_create_node(self, mock_utcnow):
        ndict = post_get_test_node()
        test_time = datetime.datetime(2000, 1, 1, 0, 0)
        mock_utcnow.return_value = test_time
        response = self.post_json('/nodes', ndict)
        self.assertEqual(201, response.status_int)
        result = self.get_json('/nodes/%s' % ndict['uuid'])
        self.assertEqual(ndict['uuid'], result['uuid'])
        self.assertFalse(result['updated_at'])
        return_created_at = timeutils.parse_isotime(
                result['created_at']).replace(tzinfo=None)
        self.assertEqual(test_time, return_created_at)
        # Check location header
        self.assertIsNotNone(response.location)
        expected_location = '/v1/nodes/%s' % ndict['uuid']
        self.assertEqual(urlparse.urlparse(response.location).path,
                         expected_location)

    def test_create_node_doesnt_contain_id(self):
        # FIXME(comstud): I'd like to make this test not use the
        # dbapi, however, no matter what I do when trying to mock
        # Node.create(), the API fails to convert the objects.Node
        # into the API Node object correctly (it leaves all fields
        # as Unset).
        with mock.patch.object(self.dbapi, 'create_node',
                               wraps=self.dbapi.create_node) as cn_mock:
            ndict = post_get_test_node(extra={'foo': 123})
            self.post_json('/nodes', ndict)
            result = self.get_json('/nodes/%s' % ndict['uuid'])
            self.assertEqual(ndict['extra'], result['extra'])
            cn_mock.assert_called_once_with(mock.ANY)
            # Check that 'id' is not in first arg of positional args
            self.assertNotIn('id', cn_mock.call_args[0][0])

    def test_create_node_valid_extra(self):
        ndict = post_get_test_node(extra={'foo': 123})
        self.post_json('/nodes', ndict)
        result = self.get_json('/nodes/%s' % ndict['uuid'])
        self.assertEqual(ndict['extra'], result['extra'])

    def test_create_node_invalid_extra(self):
        ndict = post_get_test_node(extra={'foo': 0.123})
        response = self.post_json('/nodes', ndict, expect_errors=True)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(400, response.status_code)
        self.assertTrue(response.json['error_message'])

    def test_vendor_passthru_ok(self):
        node = obj_utils.create_test_node(self.context)
        uuid = node.uuid
        info = {'foo': 'bar'}

        with mock.patch.object(
                rpcapi.ConductorAPI, 'vendor_passthru') as mock_vendor:
            mock_vendor.return_value = 'OK'
            response = self.post_json('/nodes/%s/vendor_passthru/test' % uuid,
                                      info, expect_errors=False)
            mock_vendor.assert_called_once_with(
                    mock.ANY, uuid, 'test', info, 'test-topic')
            self.assertEqual('"OK"', response.body)
            self.assertEqual(202, response.status_code)

    def test_vendor_passthru_no_such_method(self):
        node = obj_utils.create_test_node(self.context)
        uuid = node.uuid
        info = {'foo': 'bar'}

        with mock.patch.object(
                rpcapi.ConductorAPI, 'vendor_passthru') as mock_vendor:
            mock_vendor.side_effect = exception.UnsupportedDriverExtension(
                                        {'driver': node.driver,
                                         'node': uuid,
                                         'extension': 'test'})
            response = self.post_json('/nodes/%s/vendor_passthru/test' % uuid,
                                      info, expect_errors=True)
            mock_vendor.assert_called_once_with(
                    mock.ANY, uuid, 'test', info, 'test-topic')
            self.assertEqual(400, response.status_code)

    def test_vendor_passthru_without_method(self):
        node = obj_utils.create_test_node(self.context)
        response = self.post_json('/nodes/%s/vendor_passthru' % node.uuid,
                                  {'foo': 'bar'}, expect_errors=True)
        self.assertEqual('application/json', response.content_type, )
        self.assertEqual(400, response.status_code)
        self.assertTrue(response.json['error_message'])

    def test_post_ports_subresource(self):
        node = obj_utils.create_test_node(self.context)
        pdict = apiutils.port_post_data(node_id=None)
        pdict['node_uuid'] = node.uuid
        response = self.post_json('/nodes/ports', pdict,
                                  expect_errors=True)
        self.assertEqual(403, response.status_int)

    def test_create_node_no_mandatory_field_driver(self):
        ndict = post_get_test_node()
        del ndict['driver']
        response = self.post_json('/nodes', ndict, expect_errors=True)
        self.assertEqual(400, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertTrue(response.json['error_message'])

    def test_create_node_invalid_driver(self):
        ndict = post_get_test_node()
        self.mock_gtf.side_effect = exception.NoValidHost('Fake Error')
        response = self.post_json('/nodes', ndict, expect_errors=True)
        self.assertEqual(400, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertTrue(response.json['error_message'])

    def test_create_node_no_chassis_uuid(self):
        ndict = post_get_test_node()
        del ndict['chassis_uuid']
        response = self.post_json('/nodes', ndict)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(201, response.status_int)
        # Check location header
        self.assertIsNotNone(response.location)
        expected_location = '/v1/nodes/%s' % ndict['uuid']
        self.assertEqual(urlparse.urlparse(response.location).path,
                         expected_location)

    def test_create_node_with_chassis_uuid(self):
        ndict = post_get_test_node(chassis_uuid=self.chassis.uuid)
        response = self.post_json('/nodes', ndict)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(201, response.status_int)
        result = self.get_json('/nodes/%s' % ndict['uuid'])
        self.assertEqual(ndict['chassis_uuid'], result['chassis_uuid'])
        # Check location header
        self.assertIsNotNone(response.location)
        expected_location = '/v1/nodes/%s' % ndict['uuid']
        self.assertEqual(urlparse.urlparse(response.location).path,
                         expected_location)

    def test_create_node_chassis_uuid_not_found(self):
        ndict = post_get_test_node(
                           chassis_uuid='1a1a1a1a-2b2b-3c3c-4d4d-5e5e5e5e5e5e')
        response = self.post_json('/nodes', ndict, expect_errors=True)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(400, response.status_int)
        self.assertTrue(response.json['error_message'])

    def test_create_node_with_internal_field(self):
        ndict = post_get_test_node()
        ndict['reservation'] = 'fake'
        response = self.post_json('/nodes', ndict, expect_errors=True)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(400, response.status_int)
        self.assertTrue(response.json['error_message'])


class TestDelete(base.FunctionalTest):

    def setUp(self):
        super(TestDelete, self).setUp()
        self.chassis = obj_utils.create_test_chassis(self.context)
        p = mock.patch.object(rpcapi.ConductorAPI, 'get_topic_for')
        self.mock_gtf = p.start()
        self.mock_gtf.return_value = 'test-topic'
        self.addCleanup(p.stop)

    @mock.patch.object(rpcapi.ConductorAPI, 'destroy_node')
    def test_delete_node(self, mock_dn):
        node = obj_utils.create_test_node(self.context)
        self.delete('/nodes/%s' % node.uuid)
        mock_dn.assert_called_once_with(mock.ANY, node.uuid, 'test-topic')

    @mock.patch.object(objects.Node, 'get_by_uuid')
    def test_delete_node_not_found(self, mock_gbu):
        node = obj_utils.get_test_node(self.context)
        mock_gbu.side_effect = exception.NodeNotFound(node=node.uuid)

        response = self.delete('/nodes/%s' % node.uuid, expect_errors=True)
        self.assertEqual(404, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertTrue(response.json['error_message'])
        mock_gbu.assert_called_once_with(mock.ANY, node.uuid)

    def test_delete_ports_subresource(self):
        node = obj_utils.create_test_node(self.context)
        response = self.delete('/nodes/%s/ports' % node.uuid,
                               expect_errors=True)
        self.assertEqual(403, response.status_int)

    @mock.patch.object(rpcapi.ConductorAPI, 'destroy_node')
    def test_delete_associated(self, mock_dn):
        node = obj_utils.create_test_node(
                self.context,
                instance_uuid='aaaaaaaa-1111-bbbb-2222-cccccccccccc')
        mock_dn.side_effect = exception.NodeAssociated(node=node.uuid,
                                                   instance=node.instance_uuid)

        response = self.delete('/nodes/%s' % node.uuid, expect_errors=True)
        self.assertEqual(409, response.status_int)
        mock_dn.assert_called_once_with(mock.ANY, node.uuid, 'test-topic')


class TestPut(base.FunctionalTest):

    def setUp(self):
        super(TestPut, self).setUp()
        self.chassis = obj_utils.create_test_chassis(self.context)
        self.node = obj_utils.create_test_node(self.context)
        p = mock.patch.object(rpcapi.ConductorAPI, 'get_topic_for')
        self.mock_gtf = p.start()
        self.mock_gtf.return_value = 'test-topic'
        self.addCleanup(p.stop)
        p = mock.patch.object(rpcapi.ConductorAPI, 'change_node_power_state')
        self.mock_cnps = p.start()
        self.addCleanup(p.stop)
        p = mock.patch.object(rpcapi.ConductorAPI, 'do_node_deploy')
        self.mock_dnd = p.start()
        self.addCleanup(p.stop)
        p = mock.patch.object(rpcapi.ConductorAPI, 'do_node_tear_down')
        self.mock_dntd = p.start()
        self.addCleanup(p.stop)

    def test_power_state(self):
        response = self.put_json('/nodes/%s/states/power' % self.node['uuid'],
                                 {'target': states.POWER_ON})
        self.assertEqual(202, response.status_code)
        self.assertEqual('', response.body)
        self.mock_cnps.assert_called_once_with(mock.ANY,
                                               self.node['uuid'],
                                               states.POWER_ON,
                                               'test-topic')
        # Check location header
        self.assertIsNotNone(response.location)
        expected_location = '/v1/nodes/%s/states' % self.node.uuid
        self.assertEqual(urlparse.urlparse(response.location).path,
                         expected_location)

    def test_power_invalid_state_request(self):
        ret = self.put_json('/nodes/%s/states/power' % self.node.uuid,
                            {'target': 'not-supported'}, expect_errors=True)
        self.assertEqual(400, ret.status_code)

    def test_provision_with_deploy(self):
        ret = self.put_json('/nodes/%s/states/provision' % self.node.uuid,
                            {'target': states.ACTIVE})
        self.assertEqual(202, ret.status_code)
        self.assertEqual('', ret.body)
        self.mock_dnd.assert_called_once_with(
                mock.ANY, self.node.uuid, False, 'test-topic')
        # Check location header
        self.assertIsNotNone(ret.location)
        expected_location = '/v1/nodes/%s/states' % self.node.uuid
        self.assertEqual(urlparse.urlparse(ret.location).path,
                         expected_location)

    def test_provision_with_tear_down(self):
        ret = self.put_json('/nodes/%s/states/provision' % self.node.uuid,
                            {'target': states.DELETED})
        self.assertEqual(202, ret.status_code)
        self.assertEqual('', ret.body)
        self.mock_dntd.assert_called_once_with(
                mock.ANY, self.node.uuid, 'test-topic')
        # Check location header
        self.assertIsNotNone(ret.location)
        expected_location = '/v1/nodes/%s/states' % self.node.uuid
        self.assertEqual(urlparse.urlparse(ret.location).path,
                         expected_location)

    def test_provision_invalid_state_request(self):
        ret = self.put_json('/nodes/%s/states/provision' % self.node.uuid,
                            {'target': 'not-supported'}, expect_errors=True)
        self.assertEqual(400, ret.status_code)

    def test_provision_already_in_progress(self):
        node = obj_utils.create_test_node(self.context, id=1,
                                          uuid=utils.generate_uuid(),
                                          target_provision_state=states.ACTIVE)
        ret = self.put_json('/nodes/%s/states/provision' % node.uuid,
                            {'target': states.ACTIVE},
                            expect_errors=True)
        self.assertEqual(409, ret.status_code)  # Conflict

    def test_provision_with_tear_down_in_progress_deploywait(self):
        node = obj_utils.create_test_node(
                self.context, id=1, uuid=utils.generate_uuid(),
                provision_state=states.DEPLOYWAIT,
                target_provision_state=states.DEPLOYDONE)
        ret = self.put_json('/nodes/%s/states/provision' % node.uuid,
                            {'target': states.DELETED})
        self.assertEqual(202, ret.status_code)
        self.assertEqual('', ret.body)
        self.mock_dntd.assert_called_once_with(
                mock.ANY, node.uuid, 'test-topic')
        # Check location header
        self.assertIsNotNone(ret.location)
        expected_location = '/v1/nodes/%s/states' % node.uuid
        self.assertEqual(urlparse.urlparse(ret.location).path,
                         expected_location)

    def test_provision_already_in_state(self):
        node = obj_utils.create_test_node(
                self.context, id=1, uuid=utils.generate_uuid(),
                target_provision_state=states.NOSTATE,
                provision_state=states.ACTIVE)
        ret = self.put_json('/nodes/%s/states/provision' % node.uuid,
                            {'target': states.ACTIVE},
                            expect_errors=True)
        self.assertEqual(400, ret.status_code)

    def test_set_console_mode_enabled(self):
        with mock.patch.object(rpcapi.ConductorAPI, 'set_console_mode') \
                as mock_scm:
            ret = self.put_json('/nodes/%s/states/console' % self.node.uuid,
                                {'enabled': "true"})
            self.assertEqual(202, ret.status_code)
            self.assertEqual('', ret.body)
            mock_scm.assert_called_once_with(mock.ANY, self.node.uuid,
                                             True, 'test-topic')
            # Check location header
            self.assertIsNotNone(ret.location)
            expected_location = '/v1/nodes/%s/states/console' % self.node.uuid
            self.assertEqual(urlparse.urlparse(ret.location).path,
                             expected_location)

    def test_set_console_mode_disabled(self):
        with mock.patch.object(rpcapi.ConductorAPI, 'set_console_mode') \
                as mock_scm:
            ret = self.put_json('/nodes/%s/states/console' % self.node.uuid,
                                {'enabled': "false"})
            self.assertEqual(202, ret.status_code)
            self.assertEqual('', ret.body)
            mock_scm.assert_called_once_with(mock.ANY, self.node.uuid,
                                             False, 'test-topic')
            # Check location header
            self.assertIsNotNone(ret.location)
            expected_location = '/v1/nodes/%s/states/console' % self.node.uuid
            self.assertEqual(urlparse.urlparse(ret.location).path,
                             expected_location)

    def test_set_console_mode_bad_request(self):
        with mock.patch.object(rpcapi.ConductorAPI, 'set_console_mode') \
                as mock_scm:
            ret = self.put_json('/nodes/%s/states/console' % self.node.uuid,
                                {'enabled': "invalid-value"},
                                expect_errors=True)
            self.assertEqual(400, ret.status_code)
            # assert set_console_mode wasn't called
            assert not mock_scm.called

    def test_set_console_mode_bad_request_missing_parameter(self):
        with mock.patch.object(rpcapi.ConductorAPI, 'set_console_mode') \
                as mock_scm:
            ret = self.put_json('/nodes/%s/states/console' % self.node.uuid,
                                {}, expect_errors=True)
            self.assertEqual(400, ret.status_code)
            # assert set_console_mode wasn't called
            assert not mock_scm.called

    def test_set_console_mode_console_not_supported(self):
        with mock.patch.object(rpcapi.ConductorAPI, 'set_console_mode') \
                as mock_scm:
            mock_scm.side_effect = exception.UnsupportedDriverExtension(
                                   extension='console', driver='test-driver')
            ret = self.put_json('/nodes/%s/states/console' % self.node.uuid,
                                {'enabled': "true"}, expect_errors=True)
            self.assertEqual(400, ret.status_code)
            mock_scm.assert_called_once_with(mock.ANY, self.node.uuid,
                                             True, 'test-topic')

    def test_provision_node_in_maintenance_fail(self):
        with mock.patch.object(rpcapi.ConductorAPI, 'do_node_deploy') as dnd:
            node = obj_utils.create_test_node(self.context, id=1,
                                              uuid=utils.generate_uuid(),
                                              maintenance=True)
            dnd.side_effect = exception.NodeInMaintenance(op='provisioning',
                                                          node=node.uuid)

            ret = self.put_json('/nodes/%s/states/provision' % node.uuid,
                                {'target': states.ACTIVE},
                                expect_errors=True)
            self.assertEqual(400, ret.status_code)
            self.assertTrue(ret.json['error_message'])

    @mock.patch.object(rpcapi.ConductorAPI, 'set_boot_device')
    def test_set_boot_device(self, mock_sbd):
        device = boot_devices.PXE
        ret = self.put_json('/nodes/%s/management/boot_device'
                            % self.node.uuid, {'boot_device': device})
        self.assertEqual(204, ret.status_code)
        self.assertEqual('', ret.body)
        mock_sbd.assert_called_once_with(mock.ANY, self.node.uuid,
                                         device, persistent=False,
                                         topic='test-topic')

    @mock.patch.object(rpcapi.ConductorAPI, 'set_boot_device')
    def test_set_boot_device_not_supported(self, mock_sbd):
        mock_sbd.side_effect = exception.UnsupportedDriverExtension(
                                  extension='management', driver='test-driver')
        device = boot_devices.PXE
        ret = self.put_json('/nodes/%s/management/boot_device'
                            % self.node.uuid, {'boot_device': device},
                            expect_errors=True)
        self.assertEqual(400, ret.status_code)
        self.assertTrue(ret.json['error_message'])
        mock_sbd.assert_called_once_with(mock.ANY, self.node.uuid,
                                         device, persistent=False,
                                         topic='test-topic')

    @mock.patch.object(rpcapi.ConductorAPI, 'set_boot_device')
    def test_set_boot_device_persistent(self, mock_sbd):
        device = boot_devices.PXE
        ret = self.put_json('/nodes/%s/management/boot_device?persistent=True'
                            % self.node.uuid, {'boot_device': device})
        self.assertEqual(204, ret.status_code)
        self.assertEqual('', ret.body)
        mock_sbd.assert_called_once_with(mock.ANY, self.node.uuid,
                                         device, persistent=True,
                                         topic='test-topic')

    @mock.patch.object(rpcapi.ConductorAPI, 'set_boot_device')
    def test_set_boot_device_persistent_invalid_value(self, mock_sbd):
        device = boot_devices.PXE
        ret = self.put_json('/nodes/%s/management/boot_device?persistent=blah'
                            % self.node.uuid, {'boot_device': device},
                            expect_errors=True)
        self.assertEqual('application/json', ret.content_type)
        self.assertEqual(400, ret.status_code)
