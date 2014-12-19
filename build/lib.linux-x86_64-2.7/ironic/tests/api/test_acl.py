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
Tests for ACL. Checks whether certain kinds of requests
are blocked or allowed to be processed.
"""

import mock

# NOTE(deva): import auth_token so we can override a config option
from keystonemiddleware import auth_token  # noqa

from oslo.config import cfg

from ironic.db import api as db_api
from ironic.tests.api import base
from ironic.tests.api import utils
from ironic.tests.db import utils as db_utils


class TestACL(base.FunctionalTest):

    def setUp(self):
        super(TestACL, self).setUp()

        self.environ = {'fake.cache': utils.FakeMemcache()}
        self.fake_db_node = db_utils.get_test_node(chassis_id=None)
        self.dbapi = db_api.get_instance()
        self.node_path = '/nodes/%s' % self.fake_db_node['uuid']

    def get_json(self, path, expect_errors=False, headers=None, q=[], **param):
        return super(TestACL, self).get_json(path,
                                                expect_errors=expect_errors,
                                                headers=headers,
                                                q=q,
                                                extra_environ=self.environ,
                                                **param)

    def _make_app(self):
        cfg.CONF.set_override('cache', 'fake.cache',
                              group='keystone_authtoken')
        return super(TestACL, self)._make_app(enable_acl=True)

    def test_non_authenticated(self):
        response = self.get_json(self.node_path, expect_errors=True)
        self.assertEqual(401, response.status_int)

    def test_authenticated(self):
        with mock.patch.object(self.dbapi, 'get_node_by_uuid',
                               autospec=True) as mock_get_node:
            mock_get_node.return_value = self.fake_db_node

            response = self.get_json(self.node_path,
                                 headers={'X-Auth-Token': utils.ADMIN_TOKEN})

            self.assertEqual(self.fake_db_node['uuid'], response['uuid'])
            mock_get_node.assert_called_once_with(self.fake_db_node['uuid'])

    def test_non_admin(self):
        response = self.get_json(self.node_path,
                                 headers={'X-Auth-Token': utils.MEMBER_TOKEN},
                                 expect_errors=True)

        self.assertEqual(403, response.status_int)

    def test_non_admin_with_admin_header(self):
        response = self.get_json(self.node_path,
                                 headers={'X-Auth-Token': utils.MEMBER_TOKEN,
                                          'X-Roles': 'admin'},
                                 expect_errors=True)

        self.assertEqual(403, response.status_int)

    def test_public_api(self):
        # expect_errors should be set to True: If expect_errors is set to False
        # the response gets converted to JSON and we cannot read the response
        # code so easy.
        for route in ('/', '/v1'):
            response = self.get_json(route,
                                     path_prefix='', expect_errors=True)
            self.assertEqual(200, response.status_int)

    def test_public_api_with_path_extensions(self):
        for route in ('/v1/', '/v1.json', '/v1.xml'):
            response = self.get_json(route,
                                     path_prefix='', expect_errors=True)
            self.assertEqual(200, response.status_int)
