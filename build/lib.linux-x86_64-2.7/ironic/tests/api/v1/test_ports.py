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
Tests for the API /ports/ methods.
"""

import datetime

import mock
from oslo.config import cfg
from oslo.utils import timeutils
from six.moves.urllib import parse as urlparse
from testtools.matchers import HasLength

from ironic.common import exception
from ironic.common import utils
from ironic.conductor import rpcapi
from ironic.tests.api import base
from ironic.tests.api import utils as apiutils
from ironic.tests.db import utils as dbutils
from ironic.tests.objects import utils as obj_utils


# NOTE(lucasagomes): When creating a port via API (POST)
#                    we have to use node_uuid
def post_get_test_port(**kw):
    port = apiutils.port_post_data(**kw)
    node = dbutils.get_test_node()
    del port['node_id']
    port['node_uuid'] = kw.get('node_uuid', node['uuid'])
    return port


class TestListPorts(base.FunctionalTest):

    def setUp(self):
        super(TestListPorts, self).setUp()
        self.node = obj_utils.create_test_node(self.context)

    def test_empty(self):
        data = self.get_json('/ports')
        self.assertEqual([], data['ports'])

    def test_one(self):
        port = obj_utils.create_test_port(self.context)
        data = self.get_json('/ports')
        self.assertEqual(port.uuid, data['ports'][0]["uuid"])
        self.assertNotIn('extra', data['ports'][0])
        self.assertNotIn('node_uuid', data['ports'][0])
        # never expose the node_id
        self.assertNotIn('node_id', data['ports'][0])

    def test_get_one(self):
        port = obj_utils.create_test_port(self.context)
        data = self.get_json('/ports/%s' % port.uuid)
        self.assertEqual(port.uuid, data['uuid'])
        self.assertIn('extra', data)
        self.assertIn('node_uuid', data)
        # never expose the node_id
        self.assertNotIn('node_id', data)

    def test_detail(self):
        port = obj_utils.create_test_port(self.context)
        data = self.get_json('/ports/detail')
        self.assertEqual(port.uuid, data['ports'][0]["uuid"])
        self.assertIn('extra', data['ports'][0])
        self.assertIn('node_uuid', data['ports'][0])
        # never expose the node_id
        self.assertNotIn('node_id', data['ports'][0])

    def test_detail_against_single(self):
        port = obj_utils.create_test_port(self.context)
        response = self.get_json('/ports/%s/detail' % port.uuid,
                                 expect_errors=True)
        self.assertEqual(404, response.status_int)

    def test_many(self):
        ports = []
        for id_ in range(5):
            port = obj_utils.create_test_port(self.context,
                                            id=id_,
                                            uuid=utils.generate_uuid(),
                                            address='52:54:00:cf:2d:3%s' % id_)
            ports.append(port.uuid)
        data = self.get_json('/ports')
        self.assertEqual(len(ports), len(data['ports']))

        uuids = [n['uuid'] for n in data['ports']]
        self.assertEqual(ports.sort(), uuids.sort())

    def test_links(self):
        uuid = utils.generate_uuid()
        obj_utils.create_test_port(self.context, id=1, uuid=uuid)
        data = self.get_json('/ports/%s' % uuid)
        self.assertIn('links', data.keys())
        self.assertEqual(2, len(data['links']))
        self.assertIn(uuid, data['links'][0]['href'])
        for l in data['links']:
            bookmark = l['rel'] == 'bookmark'
            self.assertTrue(self.validate_link(l['href'], bookmark=bookmark))

    def test_collection_links(self):
        ports = []
        for id_ in range(5):
            port = obj_utils.create_test_port(self.context,
                                            id=id_,
                                            uuid=utils.generate_uuid(),
                                            address='52:54:00:cf:2d:3%s' % id_)
            ports.append(port.uuid)
        data = self.get_json('/ports/?limit=3')
        self.assertEqual(3, len(data['ports']))

        next_marker = data['ports'][-1]['uuid']
        self.assertIn(next_marker, data['next'])

    def test_collection_links_default_limit(self):
        cfg.CONF.set_override('max_limit', 3, 'api')
        ports = []
        for id_ in range(5):
            port = obj_utils.create_test_port(self.context,
                                            id=id_,
                                            uuid=utils.generate_uuid(),
                                            address='52:54:00:cf:2d:3%s' % id_)
            ports.append(port.uuid)
        data = self.get_json('/ports')
        self.assertEqual(3, len(data['ports']))

        next_marker = data['ports'][-1]['uuid']
        self.assertIn(next_marker, data['next'])

    def test_port_by_address(self):
        address_template = "aa:bb:cc:dd:ee:f%d"
        for id_ in range(3):
            obj_utils.create_test_port(self.context,
                                       id=id_,
                                       uuid=utils.generate_uuid(),
                                       address=address_template % id_)

        target_address = address_template % 1
        data = self.get_json('/ports?address=%s' % target_address)
        self.assertThat(data['ports'], HasLength(1))
        self.assertEqual(target_address, data['ports'][0]['address'])

    def test_port_by_address_non_existent_address(self):
        # non-existent address
        data = self.get_json('/ports?address=%s' % 'aa:bb:cc:dd:ee:ff')
        self.assertThat(data['ports'], HasLength(0))

    def test_port_by_address_invalid_address_format(self):
        obj_utils.create_test_port(self.context)
        invalid_address = 'invalid-mac-format'
        response = self.get_json('/ports?address=%s' % invalid_address,
                                 expect_errors=True)
        self.assertEqual(400, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertIn(invalid_address, response.json['error_message'])


@mock.patch.object(rpcapi.ConductorAPI, 'update_port')
class TestPatch(base.FunctionalTest):

    def setUp(self):
        super(TestPatch, self).setUp()
        self.node = obj_utils.create_test_node(self.context)
        self.port = obj_utils.create_test_port(self.context)

        p = mock.patch.object(rpcapi.ConductorAPI, 'get_topic_for')
        self.mock_gtf = p.start()
        self.mock_gtf.return_value = 'test-topic'
        self.addCleanup(p.stop)

    def test_update_byid(self, mock_upd):
        extra = {'foo': 'bar'}
        mock_upd.return_value = self.port
        mock_upd.return_value.extra = extra
        response = self.patch_json('/ports/%s' % self.port.uuid,
                                   [{'path': '/extra/foo',
                                     'value': 'bar',
                                     'op': 'add'}])
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(200, response.status_code)
        self.assertEqual(extra, response.json['extra'])

        kargs = mock_upd.call_args[0][1]
        self.assertEqual(extra, kargs.extra)

    def test_update_byaddress_not_allowed(self, mock_upd):
        extra = {'foo': 'bar'}
        mock_upd.return_value = self.port
        mock_upd.return_value.extra = extra
        response = self.patch_json('/ports/%s' % self.port.address,
                                   [{'path': '/extra/foo',
                                     'value': 'bar',
                                     'op': 'add'}],
                                   expect_errors=True)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(400, response.status_int)
        self.assertIn(self.port.address, response.json['error_message'])
        self.assertFalse(mock_upd.called)

    def test_update_not_found(self, mock_upd):
        uuid = utils.generate_uuid()
        response = self.patch_json('/ports/%s' % uuid,
                                   [{'path': '/extra/foo',
                                     'value': 'bar',
                                     'op': 'add'}],
                                   expect_errors=True)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(404, response.status_int)
        self.assertTrue(response.json['error_message'])
        self.assertFalse(mock_upd.called)

    def test_replace_singular(self, mock_upd):
        address = 'aa:bb:cc:dd:ee:ff'
        mock_upd.return_value = self.port
        mock_upd.return_value.address = address
        response = self.patch_json('/ports/%s' % self.port.uuid,
                                   [{'path': '/address',
                                     'value': address,
                                     'op': 'replace'}])
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(200, response.status_code)
        self.assertEqual(address, response.json['address'])
        self.assertTrue(mock_upd.called)

        kargs = mock_upd.call_args[0][1]
        self.assertEqual(address, kargs.address)

    def test_replace_address_already_exist(self, mock_upd):
        address = 'aa:aa:aa:aa:aa:aa'
        mock_upd.side_effect = exception.MACAlreadyExists(mac=address)
        response = self.patch_json('/ports/%s' % self.port.uuid,
                                   [{'path': '/address',
                                     'value': address,
                                     'op': 'replace'}],
                                     expect_errors=True)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(409, response.status_code)
        self.assertTrue(response.json['error_message'])
        self.assertTrue(mock_upd.called)

        kargs = mock_upd.call_args[0][1]
        self.assertEqual(address, kargs.address)

    def test_replace_node_uuid(self, mock_upd):
        mock_upd.return_value = self.port
        response = self.patch_json('/ports/%s' % self.port.uuid,
                             [{'path': '/node_uuid',
                               'value': self.node.uuid,
                               'op': 'replace'}])
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(200, response.status_code)

    def test_add_node_uuid(self, mock_upd):
        mock_upd.return_value = self.port
        response = self.patch_json('/ports/%s' % self.port.uuid,
                             [{'path': '/node_uuid',
                               'value': self.node.uuid,
                               'op': 'add'}])
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(200, response.status_code)

    def test_add_node_id(self, mock_upd):
        response = self.patch_json('/ports/%s' % self.port.uuid,
                             [{'path': '/node_id',
                               'value': '1',
                               'op': 'add'}],
                               expect_errors=True)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(400, response.status_code)
        self.assertFalse(mock_upd.called)

    def test_replace_node_id(self, mock_upd):
        response = self.patch_json('/ports/%s' % self.port.uuid,
                             [{'path': '/node_id',
                               'value': '1',
                               'op': 'replace'}],
                               expect_errors=True)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(400, response.status_code)
        self.assertFalse(mock_upd.called)

    def test_remove_node_id(self, mock_upd):
        response = self.patch_json('/ports/%s' % self.port.uuid,
                             [{'path': '/node_id',
                               'op': 'remove'}],
                               expect_errors=True)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(400, response.status_code)
        self.assertFalse(mock_upd.called)

    def test_replace_non_existent_node_uuid(self, mock_upd):
        node_uuid = '12506333-a81c-4d59-9987-889ed5f8687b'
        response = self.patch_json('/ports/%s' % self.port.uuid,
                             [{'path': '/node_uuid',
                               'value': node_uuid,
                               'op': 'replace'}],
                             expect_errors=True)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(400, response.status_code)
        self.assertIn(node_uuid, response.json['error_message'])
        self.assertFalse(mock_upd.called)

    def test_replace_multi(self, mock_upd):
        extra = {"foo1": "bar1", "foo2": "bar2", "foo3": "bar3"}
        self.port.extra = extra
        self.port.save()

        # mutate extra so we replace all of them
        extra = dict((k, extra[k] + 'x') for k in extra.keys())

        patch = []
        for k in extra.keys():
            patch.append({'path': '/extra/%s' % k,
                          'value': extra[k],
                          'op': 'replace'})
        mock_upd.return_value = self.port
        mock_upd.return_value.extra = extra
        response = self.patch_json('/ports/%s' % self.port.uuid,
                                   patch)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(200, response.status_code)
        self.assertEqual(extra, response.json['extra'])
        kargs = mock_upd.call_args[0][1]
        self.assertEqual(extra, kargs.extra)

    def test_remove_multi(self, mock_upd):
        extra = {"foo1": "bar1", "foo2": "bar2", "foo3": "bar3"}
        self.port.extra = extra
        self.port.save()

        # Removing one item from the collection
        extra.pop('foo1')
        mock_upd.return_value = self.port
        mock_upd.return_value.extra = extra
        response = self.patch_json('/ports/%s' % self.port.uuid,
                                   [{'path': '/extra/foo1',
                                     'op': 'remove'}])
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(200, response.status_code)
        self.assertEqual(extra, response.json['extra'])
        kargs = mock_upd.call_args[0][1]
        self.assertEqual(extra, kargs.extra)

        # Removing the collection
        extra = {}
        mock_upd.return_value.extra = extra
        response = self.patch_json('/ports/%s' % self.port.uuid,
                                   [{'path': '/extra', 'op': 'remove'}])
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(200, response.status_code)
        self.assertEqual({}, response.json['extra'])
        kargs = mock_upd.call_args[0][1]
        self.assertEqual(extra, kargs.extra)

        # Assert nothing else was changed
        self.assertEqual(self.port.uuid, response.json['uuid'])
        self.assertEqual(self.port.address, response.json['address'])

    def test_remove_non_existent_property_fail(self, mock_upd):
        response = self.patch_json('/ports/%s' % self.port.uuid,
                                   [{'path': '/extra/non-existent',
                                     'op': 'remove'}],
                                   expect_errors=True)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(400, response.status_code)
        self.assertTrue(response.json['error_message'])
        self.assertFalse(mock_upd.called)

    def test_remove_mandatory_field(self, mock_upd):
        response = self.patch_json('/ports/%s' % self.port.uuid,
                                   [{'path': '/address',
                                     'op': 'remove'}],
                                   expect_errors=True)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(400, response.status_code)
        self.assertTrue(response.json['error_message'])
        self.assertFalse(mock_upd.called)

    def test_add_root(self, mock_upd):
        address = 'aa:bb:cc:dd:ee:ff'
        mock_upd.return_value = self.port
        mock_upd.return_value.address = address
        response = self.patch_json('/ports/%s' % self.port.uuid,
                                   [{'path': '/address',
                                     'value': address,
                                     'op': 'add'}])
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(200, response.status_code)
        self.assertEqual(address, response.json['address'])
        self.assertTrue(mock_upd.called)
        kargs = mock_upd.call_args[0][1]
        self.assertEqual(address, kargs.address)

    def test_add_root_non_existent(self, mock_upd):
        response = self.patch_json('/ports/%s' % self.port.uuid,
                                   [{'path': '/foo',
                                     'value': 'bar',
                                     'op': 'add'}],
                                   expect_errors=True)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(400, response.status_int)
        self.assertTrue(response.json['error_message'])
        self.assertFalse(mock_upd.called)

    def test_add_multi(self, mock_upd):
        extra = {"foo1": "bar1", "foo2": "bar2", "foo3": "bar3"}
        patch = []
        for k in extra.keys():
            patch.append({'path': '/extra/%s' % k,
                          'value': extra[k],
                          'op': 'add'})
        mock_upd.return_value = self.port
        mock_upd.return_value.extra = extra
        response = self.patch_json('/ports/%s' % self.port.uuid,
                                   patch)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(200, response.status_code)
        self.assertEqual(extra, response.json['extra'])
        kargs = mock_upd.call_args[0][1]
        self.assertEqual(extra, kargs.extra)

    def test_remove_uuid(self, mock_upd):
        response = self.patch_json('/ports/%s' % self.port.uuid,
                                   [{'path': '/uuid',
                                     'op': 'remove'}],
                                   expect_errors=True)
        self.assertEqual(400, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertTrue(response.json['error_message'])
        self.assertFalse(mock_upd.called)

    def test_update_address_invalid_format(self, mock_upd):
        response = self.patch_json('/ports/%s' % self.port.uuid,
                                   [{'path': '/address',
                                     'value': 'invalid-format',
                                     'op': 'replace'}],
                                   expect_errors=True)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(400, response.status_int)
        self.assertTrue(response.json['error_message'])
        self.assertFalse(mock_upd.called)

    def test_update_port_address_normalized(self, mock_upd):
        address = 'AA:BB:CC:DD:EE:FF'
        mock_upd.return_value = self.port
        mock_upd.return_value.address = address.lower()
        response = self.patch_json('/ports/%s' % self.port.uuid,
                                   [{'path': '/address',
                                     'value': address,
                                     'op': 'replace'}])
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(200, response.status_code)
        self.assertEqual(address.lower(), response.json['address'])
        kargs = mock_upd.call_args[0][1]
        self.assertEqual(address.lower(), kargs.address)


class TestPost(base.FunctionalTest):

    def setUp(self):
        super(TestPost, self).setUp()
        self.node = obj_utils.create_test_node(self.context)

    @mock.patch.object(timeutils, 'utcnow')
    def test_create_port(self, mock_utcnow):
        pdict = post_get_test_port()
        test_time = datetime.datetime(2000, 1, 1, 0, 0)
        mock_utcnow.return_value = test_time
        response = self.post_json('/ports', pdict)
        self.assertEqual(201, response.status_int)
        result = self.get_json('/ports/%s' % pdict['uuid'])
        self.assertEqual(pdict['uuid'], result['uuid'])
        self.assertFalse(result['updated_at'])
        return_created_at = timeutils.parse_isotime(
                            result['created_at']).replace(tzinfo=None)
        self.assertEqual(test_time, return_created_at)
        # Check location header
        self.assertIsNotNone(response.location)
        expected_location = '/v1/ports/%s' % pdict['uuid']
        self.assertEqual(urlparse.urlparse(response.location).path,
                         expected_location)

    def test_create_port_doesnt_contain_id(self):
        with mock.patch.object(self.dbapi, 'create_port',
                               wraps=self.dbapi.create_port) as cp_mock:
            pdict = post_get_test_port(extra={'foo': 123})
            self.post_json('/ports', pdict)
            result = self.get_json('/ports/%s' % pdict['uuid'])
            self.assertEqual(pdict['extra'], result['extra'])
            cp_mock.assert_called_once_with(mock.ANY)
            # Check that 'id' is not in first arg of positional args
            self.assertNotIn('id', cp_mock.call_args[0][0])

    def test_create_port_generate_uuid(self):
        pdict = post_get_test_port()
        del pdict['uuid']
        response = self.post_json('/ports', pdict)
        result = self.get_json('/ports/%s' % response.json['uuid'])
        self.assertEqual(pdict['address'], result['address'])
        self.assertTrue(utils.is_uuid_like(result['uuid']))

    def test_create_port_valid_extra(self):
        pdict = post_get_test_port(extra={'foo': 123})
        self.post_json('/ports', pdict)
        result = self.get_json('/ports/%s' % pdict['uuid'])
        self.assertEqual(pdict['extra'], result['extra'])

    def test_create_port_invalid_extra(self):
        pdict = post_get_test_port(extra={'foo': 0.123})
        response = self.post_json('/ports', pdict, expect_errors=True)
        self.assertEqual(400, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertTrue(response.json['error_message'])

    def test_create_port_no_mandatory_field_address(self):
        pdict = post_get_test_port()
        del pdict['address']
        response = self.post_json('/ports', pdict, expect_errors=True)
        self.assertEqual(400, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertTrue(response.json['error_message'])

    def test_create_port_no_mandatory_field_node_uuid(self):
        pdict = post_get_test_port()
        del pdict['node_uuid']
        response = self.post_json('/ports', pdict, expect_errors=True)
        self.assertEqual(400, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertTrue(response.json['error_message'])

    def test_create_port_invalid_addr_format(self):
        pdict = post_get_test_port(address='invalid-format')
        response = self.post_json('/ports', pdict, expect_errors=True)
        self.assertEqual(400, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertTrue(response.json['error_message'])

    def test_create_port_address_normalized(self):
        address = 'AA:BB:CC:DD:EE:FF'
        pdict = post_get_test_port(address=address)
        self.post_json('/ports', pdict)
        result = self.get_json('/ports/%s' % pdict['uuid'])
        self.assertEqual(address.lower(), result['address'])

    def test_create_port_with_hyphens_delimiter(self):
        pdict = post_get_test_port()
        colonsMAC = pdict['address']
        hyphensMAC = colonsMAC.replace(':', '-')
        pdict['address'] = hyphensMAC
        response = self.post_json('/ports', pdict, expect_errors=True)
        self.assertEqual(400, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertTrue(response.json['error_message'])

    def test_create_port_invalid_node_uuid_format(self):
        pdict = post_get_test_port(node_uuid='invalid-format')
        response = self.post_json('/ports', pdict, expect_errors=True)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(400, response.status_int)
        self.assertTrue(response.json['error_message'])

    def test_node_uuid_to_node_id_mapping(self):
        pdict = post_get_test_port(node_uuid=self.node['uuid'])
        self.post_json('/ports', pdict)
        # GET doesn't return the node_id it's an internal value
        port = self.dbapi.get_port_by_uuid(pdict['uuid'])
        self.assertEqual(self.node['id'], port.node_id)

    def test_create_port_node_uuid_not_found(self):
        pdict = post_get_test_port(
                              node_uuid='1a1a1a1a-2b2b-3c3c-4d4d-5e5e5e5e5e5e')
        response = self.post_json('/ports', pdict, expect_errors=True)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(400, response.status_int)
        self.assertTrue(response.json['error_message'])

    def test_create_port_address_already_exist(self):
        address = 'AA:AA:AA:11:22:33'
        pdict = post_get_test_port(address=address)
        self.post_json('/ports', pdict)
        pdict['uuid'] = utils.generate_uuid()
        response = self.post_json('/ports', pdict, expect_errors=True)
        self.assertEqual(409, response.status_int)
        self.assertEqual('application/json', response.content_type)
        error_msg = response.json['error_message']
        self.assertTrue(error_msg)
        self.assertIn(address, error_msg.upper())


class TestDelete(base.FunctionalTest):

    def setUp(self):
        super(TestDelete, self).setUp()
        self.node = obj_utils.create_test_node(self.context)
        self.port = obj_utils.create_test_port(self.context)

    def test_delete_port_byid(self):
        self.delete('/ports/%s' % self.port.uuid)
        response = self.get_json('/ports/%s' % self.port.uuid,
                                 expect_errors=True)
        self.assertEqual(404, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertIn(self.port.uuid, response.json['error_message'])

    def test_delete_port_byaddress(self):
        response = self.delete('/ports/%s' % self.port.address,
                               expect_errors=True)
        self.assertEqual(400, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertIn(self.port.address, response.json['error_message'])

    def test_delete_port_node_locked(self):
        self.node.reserve(self.context, 'fake', self.node.uuid)
        response = self.delete('/ports/%s' % self.port.uuid,
                               expect_errors=True)
        self.assertEqual(409, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertIn(self.node.uuid, response.json['error_message'])
