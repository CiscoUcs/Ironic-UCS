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
Tests for the API /chassis/ methods.
"""

import datetime

import mock
from oslo.config import cfg
from oslo.utils import timeutils
from six.moves.urllib import parse as urlparse

from ironic.common import utils
from ironic.tests.api import base
from ironic.tests.api import utils as apiutils
from ironic.tests.objects import utils as obj_utils


class TestListChassis(base.FunctionalTest):

    def test_empty(self):
        data = self.get_json('/chassis')
        self.assertEqual([], data['chassis'])

    def test_one(self):
        chassis = obj_utils.create_test_chassis(self.context)
        data = self.get_json('/chassis')
        self.assertEqual(chassis.uuid, data['chassis'][0]["uuid"])
        self.assertNotIn('extra', data['chassis'][0])
        self.assertNotIn('nodes', data['chassis'][0])

    def test_get_one(self):
        chassis = obj_utils.create_test_chassis(self.context)
        data = self.get_json('/chassis/%s' % chassis['uuid'])
        self.assertEqual(chassis.uuid, data['uuid'])
        self.assertIn('extra', data)
        self.assertIn('nodes', data)

    def test_detail(self):
        chassis = obj_utils.create_test_chassis(self.context)
        data = self.get_json('/chassis/detail')
        self.assertEqual(chassis.uuid, data['chassis'][0]["uuid"])
        self.assertIn('extra', data['chassis'][0])
        self.assertIn('nodes', data['chassis'][0])

    def test_detail_against_single(self):
        chassis = obj_utils.create_test_chassis(self.context)
        response = self.get_json('/chassis/%s/detail' % chassis['uuid'],
                                 expect_errors=True)
        self.assertEqual(404, response.status_int)

    def test_many(self):
        ch_list = []
        for id_ in range(5):
            chassis = obj_utils.create_test_chassis(self.context, id=id_,
                                                    uuid=utils.generate_uuid())
            ch_list.append(chassis.uuid)
        data = self.get_json('/chassis')
        self.assertEqual(len(ch_list), len(data['chassis']))
        uuids = [n['uuid'] for n in data['chassis']]
        self.assertEqual(ch_list.sort(), uuids.sort())

    def test_links(self):
        uuid = utils.generate_uuid()
        obj_utils.create_test_chassis(self.context, id=1, uuid=uuid)
        data = self.get_json('/chassis/%s' % uuid)
        self.assertIn('links', data.keys())
        self.assertEqual(2, len(data['links']))
        self.assertIn(uuid, data['links'][0]['href'])
        for l in data['links']:
            bookmark = l['rel'] == 'bookmark'
            self.assertTrue(self.validate_link(l['href'], bookmark=bookmark))

    def test_collection_links(self):
        for id in range(5):
            obj_utils.create_test_chassis(self.context, id=id,
                                          uuid=utils.generate_uuid())
        data = self.get_json('/chassis/?limit=3')
        self.assertEqual(3, len(data['chassis']))

        next_marker = data['chassis'][-1]['uuid']
        self.assertIn(next_marker, data['next'])

    def test_collection_links_default_limit(self):
        cfg.CONF.set_override('max_limit', 3, 'api')
        for id_ in range(5):
            obj_utils.create_test_chassis(self.context, id=id_,
                                          uuid=utils.generate_uuid())
        data = self.get_json('/chassis')
        self.assertEqual(3, len(data['chassis']))

        next_marker = data['chassis'][-1]['uuid']
        self.assertIn(next_marker, data['next'])

    def test_nodes_subresource_link(self):
        chassis = obj_utils.create_test_chassis(self.context)
        data = self.get_json('/chassis/%s' % chassis.uuid)
        self.assertIn('nodes', data.keys())

    def test_nodes_subresource(self):
        chassis = obj_utils.create_test_chassis(self.context)

        for id_ in range(2):
            obj_utils.create_test_node(self.context, id=id_,
                                       chassis_id=chassis.id,
                                       uuid=utils.generate_uuid())

        data = self.get_json('/chassis/%s/nodes' % chassis.uuid)
        self.assertEqual(2, len(data['nodes']))
        self.assertNotIn('next', data.keys())

        # Test collection pagination
        data = self.get_json('/chassis/%s/nodes?limit=1' % chassis.uuid)
        self.assertEqual(1, len(data['nodes']))
        self.assertIn('next', data.keys())

    def test_nodes_subresource_no_uuid(self):
        response = self.get_json('/chassis/nodes', expect_errors=True)
        self.assertEqual(400, response.status_int)

    def test_nodes_subresource_chassis_not_found(self):
        non_existent_uuid = 'eeeeeeee-cccc-aaaa-bbbb-cccccccccccc'
        response = self.get_json('/chassis/%s/nodes' % non_existent_uuid,
                                 expect_errors=True)
        self.assertEqual(404, response.status_int)


class TestPatch(base.FunctionalTest):

    def setUp(self):
        super(TestPatch, self).setUp()
        obj_utils.create_test_chassis(self.context)

    def test_update_not_found(self):
        uuid = utils.generate_uuid()
        response = self.patch_json('/chassis/%s' % uuid,
                                   [{'path': '/extra/a', 'value': 'b',
                                     'op': 'add'}],
                                   expect_errors=True)
        self.assertEqual(404, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertTrue(response.json['error_message'])

    @mock.patch.object(timeutils, 'utcnow')
    def test_replace_singular(self, mock_utcnow):
        chassis = obj_utils.get_test_chassis(self.context)
        description = 'chassis-new-description'
        test_time = datetime.datetime(2000, 1, 1, 0, 0)

        mock_utcnow.return_value = test_time
        response = self.patch_json('/chassis/%s' % chassis.uuid,
                                   [{'path': '/description',
                                     'value': description, 'op': 'replace'}])
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(200, response.status_code)
        result = self.get_json('/chassis/%s' % chassis.uuid)
        self.assertEqual(description, result['description'])
        return_updated_at = timeutils.parse_isotime(
                            result['updated_at']).replace(tzinfo=None)
        self.assertEqual(test_time, return_updated_at)

    def test_replace_multi(self):
        extra = {"foo1": "bar1", "foo2": "bar2", "foo3": "bar3"}
        chassis = obj_utils.create_test_chassis(self.context, extra=extra,
                                                uuid=utils.generate_uuid(),
                                                id=1)
        new_value = 'new value'
        response = self.patch_json('/chassis/%s' % chassis.uuid,
                                   [{'path': '/extra/foo2',
                                     'value': new_value, 'op': 'replace'}])
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(200, response.status_code)
        result = self.get_json('/chassis/%s' % chassis.uuid)

        extra["foo2"] = new_value
        self.assertEqual(extra, result['extra'])

    def test_remove_singular(self):
        chassis = obj_utils.create_test_chassis(self.context, extra={'a': 'b'},
                                                uuid=utils.generate_uuid(),
                                                id=1)
        response = self.patch_json('/chassis/%s' % chassis.uuid,
                                   [{'path': '/description', 'op': 'remove'}])
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(200, response.status_code)
        result = self.get_json('/chassis/%s' % chassis.uuid)
        self.assertIsNone(result['description'])

        # Assert nothing else was changed
        self.assertEqual(chassis.uuid, result['uuid'])
        self.assertEqual(chassis.extra, result['extra'])

    def test_remove_multi(self):
        extra = {"foo1": "bar1", "foo2": "bar2", "foo3": "bar3"}
        chassis = obj_utils.create_test_chassis(self.context, extra=extra,
                                                description="foobar",
                                                uuid=utils.generate_uuid(),
                                                id=1)

        # Removing one item from the collection
        response = self.patch_json('/chassis/%s' % chassis.uuid,
                                   [{'path': '/extra/foo2', 'op': 'remove'}])
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(200, response.status_code)
        result = self.get_json('/chassis/%s' % chassis.uuid)
        extra.pop("foo2")
        self.assertEqual(extra, result['extra'])

        # Removing the collection
        response = self.patch_json('/chassis/%s' % chassis.uuid,
                                   [{'path': '/extra', 'op': 'remove'}])
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(200, response.status_code)
        result = self.get_json('/chassis/%s' % chassis.uuid)
        self.assertEqual({}, result['extra'])

        # Assert nothing else was changed
        self.assertEqual(chassis.uuid, result['uuid'])
        self.assertEqual(chassis.description, result['description'])

    def test_remove_non_existent_property_fail(self):
        chassis = obj_utils.get_test_chassis(self.context)
        response = self.patch_json('/chassis/%s' % chassis.uuid,
                             [{'path': '/extra/non-existent', 'op': 'remove'}],
                             expect_errors=True)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(400, response.status_code)
        self.assertTrue(response.json['error_message'])

    def test_add_root(self):
        chassis = obj_utils.get_test_chassis(self.context)
        response = self.patch_json('/chassis/%s' % chassis.uuid,
                                   [{'path': '/description', 'value': 'test',
                                     'op': 'add'}])
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(200, response.status_int)

    def test_add_root_non_existent(self):
        chassis = obj_utils.get_test_chassis(self.context)
        response = self.patch_json('/chassis/%s' % chassis.uuid,
                                   [{'path': '/foo', 'value': 'bar',
                                     'op': 'add'}],
                                   expect_errors=True)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(400, response.status_int)
        self.assertTrue(response.json['error_message'])

    def test_add_multi(self):
        chassis = obj_utils.get_test_chassis(self.context)
        response = self.patch_json('/chassis/%s' % chassis.uuid,
                                   [{'path': '/extra/foo1', 'value': 'bar1',
                                     'op': 'add'},
                                    {'path': '/extra/foo2', 'value': 'bar2',
                                     'op': 'add'}])
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(200, response.status_code)
        result = self.get_json('/chassis/%s' % chassis.uuid)
        expected = {"foo1": "bar1", "foo2": "bar2"}
        self.assertEqual(expected, result['extra'])

    def test_patch_nodes_subresource(self):
        chassis = obj_utils.get_test_chassis(self.context)
        response = self.patch_json('/chassis/%s/nodes' % chassis.uuid,
                                   [{'path': '/extra/foo', 'value': 'bar',
                                     'op': 'add'}], expect_errors=True)
        self.assertEqual(403, response.status_int)

    def test_remove_uuid(self):
        chassis = obj_utils.get_test_chassis(self.context)
        response = self.patch_json('/chassis/%s' % chassis.uuid,
                                   [{'path': '/uuid', 'op': 'remove'}],
                                   expect_errors=True)
        self.assertEqual(400, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertTrue(response.json['error_message'])


class TestPost(base.FunctionalTest):

    @mock.patch.object(timeutils, 'utcnow')
    def test_create_chassis(self, mock_utcnow):
        cdict = apiutils.chassis_post_data()
        test_time = datetime.datetime(2000, 1, 1, 0, 0)
        mock_utcnow.return_value = test_time

        response = self.post_json('/chassis', cdict)
        self.assertEqual(201, response.status_int)
        result = self.get_json('/chassis/%s' % cdict['uuid'])
        self.assertEqual(cdict['uuid'], result['uuid'])
        self.assertFalse(result['updated_at'])
        return_created_at = timeutils.parse_isotime(
                            result['created_at']).replace(tzinfo=None)
        self.assertEqual(test_time, return_created_at)
        # Check location header
        self.assertIsNotNone(response.location)
        expected_location = '/v1/chassis/%s' % cdict['uuid']
        self.assertEqual(urlparse.urlparse(response.location).path,
                         expected_location)

    def test_create_chassis_doesnt_contain_id(self):
        with mock.patch.object(self.dbapi, 'create_chassis',
                               wraps=self.dbapi.create_chassis) as cc_mock:
            cdict = apiutils.chassis_post_data(extra={'foo': 123})
            self.post_json('/chassis', cdict)
            result = self.get_json('/chassis/%s' % cdict['uuid'])
            self.assertEqual(cdict['extra'], result['extra'])
            cc_mock.assert_called_once_with(mock.ANY)
            # Check that 'id' is not in first arg of positional args
            self.assertNotIn('id', cc_mock.call_args[0][0])

    def test_create_chassis_generate_uuid(self):
        cdict = apiutils.chassis_post_data()
        del cdict['uuid']
        self.post_json('/chassis', cdict)
        result = self.get_json('/chassis')
        self.assertEqual(cdict['description'],
                         result['chassis'][0]['description'])
        self.assertTrue(utils.is_uuid_like(result['chassis'][0]['uuid']))

    def test_post_nodes_subresource(self):
        chassis = obj_utils.create_test_chassis(self.context)
        ndict = apiutils.node_post_data(chassis_id=None)
        ndict['chassis_uuid'] = chassis.uuid
        response = self.post_json('/chassis/nodes', ndict,
                                   expect_errors=True)
        self.assertEqual(403, response.status_int)

    def test_create_chassis_valid_extra(self):
        cdict = apiutils.chassis_post_data(extra={'foo': 123})
        self.post_json('/chassis', cdict)
        result = self.get_json('/chassis/%s' % cdict['uuid'])
        self.assertEqual(cdict['extra'], result['extra'])

    def test_create_chassis_invalid_extra(self):
        cdict = apiutils.chassis_post_data(extra={'foo': 0.123})
        response = self.post_json('/chassis', cdict, expect_errors=True)
        self.assertEqual(400, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertTrue(response.json['error_message'])

    def test_create_chassis_unicode_description(self):
        descr = u'\u0430\u043c\u043e'
        cdict = apiutils.chassis_post_data(description=descr)
        self.post_json('/chassis', cdict)
        result = self.get_json('/chassis/%s' % cdict['uuid'])
        self.assertEqual(descr, result['description'])


class TestDelete(base.FunctionalTest):

    def test_delete_chassis(self):
        chassis = obj_utils.create_test_chassis(self.context)
        self.delete('/chassis/%s' % chassis.uuid)
        response = self.get_json('/chassis/%s' % chassis.uuid,
                                 expect_errors=True)
        self.assertEqual(404, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertTrue(response.json['error_message'])

    def test_delete_chassis_with_node(self):
        chassis = obj_utils.create_test_chassis(self.context)
        obj_utils.create_test_node(self.context, chassis_id=chassis.id)
        response = self.delete('/chassis/%s' % chassis.uuid,
                               expect_errors=True)
        self.assertEqual(400, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertTrue(response.json['error_message'])
        self.assertIn(chassis.uuid, response.json['error_message'])

    def test_delete_chassis_not_found(self):
        uuid = utils.generate_uuid()
        response = self.delete('/chassis/%s' % uuid, expect_errors=True)
        self.assertEqual(404, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertTrue(response.json['error_message'])

    def test_delete_nodes_subresource(self):
        chassis = obj_utils.create_test_chassis(self.context)
        response = self.delete('/chassis/%s/nodes' % chassis.uuid,
                               expect_errors=True)
        self.assertEqual(403, response.status_int)
