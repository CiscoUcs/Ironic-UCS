# coding=utf-8

# Copyright 2014 International Business Machines Corporation
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

"""Test class for console_utils driver module."""

import mock
import os
import random
import string
import subprocess
import tempfile

from oslo.config import cfg

from ironic.common import exception
from ironic.common import utils
from ironic.drivers.modules import console_utils
from ironic.drivers.modules import ipmitool as ipmi
from ironic.openstack.common import processutils
from ironic.tests.db import base as db_base
from ironic.tests.db import utils as db_utils
from ironic.tests.objects import utils as obj_utils


CONF = cfg.CONF

INFO_DICT = db_utils.get_test_ipmi_info()


class ConsoleUtilsTestCase(db_base.DbTestCase):

    def setUp(self):
        super(ConsoleUtilsTestCase, self).setUp()
        self.node = obj_utils.get_test_node(
                self.context,
                driver='fake_ipmitool',
                driver_info=INFO_DICT)
        self.info = ipmi._parse_driver_info(self.node)

    def test__get_console_pid_dir(self):
        pid_dir = '/tmp/pid_dir'
        self.config(terminal_pid_dir=pid_dir, group='console')
        dir = console_utils._get_console_pid_dir()
        self.assertEqual(pid_dir, dir)

    def test__get_console_pid_dir_tempdir(self):
        tempdir = tempfile.gettempdir()
        dir = console_utils._get_console_pid_dir()
        self.assertEqual(tempdir, dir)

    @mock.patch.object(os, 'makedirs', autospec=True)
    @mock.patch.object(os.path, 'exists', autospec=True)
    def test__ensure_console_pid_dir_exists(self, mock_path_exists,
                                            mock_makedirs):
        mock_path_exists.return_value = True
        mock_makedirs.side_effect = OSError
        pid_dir = console_utils._get_console_pid_dir()

        console_utils._ensure_console_pid_dir_exists()

        mock_path_exists.assert_called_once_with(pid_dir)
        self.assertFalse(mock_makedirs.called)

    @mock.patch.object(os, 'makedirs', autospec=True)
    @mock.patch.object(os.path, 'exists', autospec=True)
    def test__ensure_console_pid_dir_exists_fail(self, mock_path_exists,
                                                 mock_makedirs):
        mock_path_exists.return_value = False
        mock_makedirs.side_effect = OSError
        pid_dir = console_utils._get_console_pid_dir()

        self.assertRaises(exception.ConsoleError,
                          console_utils._ensure_console_pid_dir_exists)

        mock_path_exists.assert_called_once_with(pid_dir)
        mock_makedirs.assert_called_once_with(pid_dir)

    @mock.patch.object(console_utils, '_get_console_pid_dir', autospec=True)
    def test__get_console_pid_file(self, mock_dir):
        mock_dir.return_value = tempfile.gettempdir()
        expected_path = '%(tempdir)s/%(uuid)s.pid' % {
                            'tempdir': mock_dir.return_value,
                            'uuid': self.info.get('uuid')}
        path = console_utils._get_console_pid_file(self.info['uuid'])
        self.assertEqual(expected_path, path)
        mock_dir.assert_called_once_with()

    @mock.patch.object(console_utils, '_get_console_pid_file', autospec=True)
    def test__get_console_pid(self, mock_exec):
        tmp_file_handle = tempfile.NamedTemporaryFile()
        tmp_file = tmp_file_handle.name
        self.addCleanup(utils.unlink_without_raise, tmp_file)
        with open(tmp_file, "w") as f:
            f.write("12345\n")

        mock_exec.return_value = tmp_file

        pid = console_utils._get_console_pid(self.info['uuid'])

        mock_exec.assert_called_once_with(self.info['uuid'])
        self.assertEqual(pid, 12345)

    @mock.patch.object(console_utils, '_get_console_pid_file', autospec=True)
    def test__get_console_pid_not_a_num(self, mock_exec):
        tmp_file_handle = tempfile.NamedTemporaryFile()
        tmp_file = tmp_file_handle.name
        self.addCleanup(utils.unlink_without_raise, tmp_file)
        with open(tmp_file, "w") as f:
            f.write("Hello World\n")

        mock_exec.return_value = tmp_file

        self.assertRaises(exception.NoConsolePid,
                          console_utils._get_console_pid,
                          self.info['uuid'])
        mock_exec.assert_called_once_with(self.info['uuid'])

    def test__get_console_pid_file_not_found(self):
        self.assertRaises(exception.NoConsolePid,
                          console_utils._get_console_pid,
                          self.info['uuid'])

    @mock.patch.object(utils, 'unlink_without_raise', autospec=True)
    @mock.patch.object(utils, 'execute', autospec=True)
    @mock.patch.object(console_utils, '_get_console_pid', autospec=True)
    def test__stop_console(self, mock_pid, mock_execute, mock_unlink):
        pid_file = console_utils._get_console_pid_file(self.info['uuid'])
        mock_pid.return_value = '12345'

        console_utils._stop_console(self.info['uuid'])

        mock_pid.assert_called_once_with(self.info['uuid'])
        mock_execute.assert_called_once_with('kill', mock_pid.return_value,
                                             check_exit_code=[0, 99])
        mock_unlink.assert_called_once_with(pid_file)

    @mock.patch.object(utils, 'unlink_without_raise', autospec=True)
    @mock.patch.object(utils, 'execute', autospec=True)
    @mock.patch.object(console_utils, '_get_console_pid', autospec=True)
    def test__stop_console_nopid(self, mock_pid, mock_execute, mock_unlink):
        pid_file = console_utils._get_console_pid_file(self.info['uuid'])
        mock_pid.side_effect = exception.NoConsolePid(pid_path="/tmp/blah")

        self.assertRaises(exception.NoConsolePid,
                          console_utils._stop_console,
                          self.info['uuid'])

        mock_pid.assert_called_once_with(self.info['uuid'])
        self.assertFalse(mock_execute.called)
        mock_unlink.assert_called_once_with(pid_file)

    @mock.patch.object(utils, 'unlink_without_raise', autospec=True)
    @mock.patch.object(utils, 'execute', autospec=True)
    @mock.patch.object(console_utils, '_get_console_pid', autospec=True)
    def test__stop_console_nokill(self, mock_pid, mock_execute, mock_unlink):
        pid_file = console_utils._get_console_pid_file(self.info['uuid'])
        mock_pid.return_value = '12345'
        mock_execute.side_effect = processutils.ProcessExecutionError()

        self.assertRaises(processutils.ProcessExecutionError,
                          console_utils._stop_console,
                          self.info['uuid'])

        mock_pid.assert_called_once_with(self.info['uuid'])
        mock_execute.assert_called_once_with('kill', mock_pid.return_value,
                                             check_exit_code=[0, 99])
        mock_unlink.assert_called_once_with(pid_file)

    def test_get_shellinabox_console_url(self):
        generated_url = console_utils.get_shellinabox_console_url(
                self.info['port'])
        console_host = CONF.my_ip
        if utils.is_valid_ipv6(console_host):
            console_host = '[%s]' % console_host
        http_url = "http://%s:%s" % (console_host, self.info['port'])
        self.assertEqual(generated_url, http_url)

    def test_make_persistent_password_file(self):
        filepath = '%(tempdir)s/%(node_uuid)s' % {
                'tempdir': tempfile.gettempdir(),
                'node_uuid': self.info['uuid']}
        password = ''.join([random.choice(string.ascii_letters)
                            for n in xrange(16)])
        console_utils.make_persistent_password_file(filepath, password)
        # make sure file exists
        self.assertTrue(os.path.exists(filepath))
        # make sure the content is correct
        with open(filepath) as file:
            content = file.read()
        self.assertEqual(password, content)
        # delete the file
        os.unlink(filepath)

    @mock.patch.object(os, 'chmod', autospec=True)
    def test_make_persistent_password_file_fail(self, mock_chmod):
        mock_chmod.side_effect = IOError()
        filepath = '%(tempdir)s/%(node_uuid)s' % {
                'tempdir': tempfile.gettempdir(),
                'node_uuid': self.info['uuid']}
        self.assertRaises(exception.PasswordFileFailedToCreate,
                          console_utils.make_persistent_password_file,
                          filepath,
                          'password')

    @mock.patch.object(subprocess, 'Popen', autospec=True)
    @mock.patch.object(console_utils, '_ensure_console_pid_dir_exists',
                       autospec=True)
    @mock.patch.object(console_utils, '_stop_console', autospec=True)
    def test_start_shellinabox_console(self, mock_stop, mock_dir_exists,
                                       mock_popen):
        mock_popen.return_value.poll.return_value = 0

        # touch the pid file
        pid_file = console_utils._get_console_pid_file(self.info['uuid'])
        open(pid_file, 'a').close()
        self.assertTrue(os.path.exists(pid_file))

        console_utils.start_shellinabox_console(self.info['uuid'],
                                                 self.info['port'],
                                                 'ls&')

        mock_stop.assert_called_once_with(self.info['uuid'])
        mock_dir_exists.assert_called_once_with()
        mock_popen.assert_called_once_with(mock.ANY,
                                           stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE)
        mock_popen.return_value.poll.assert_called_once_with()

    @mock.patch.object(subprocess, 'Popen', autospec=True)
    @mock.patch.object(console_utils, '_ensure_console_pid_dir_exists',
                       autospec=True)
    @mock.patch.object(console_utils, '_stop_console', autospec=True)
    def test_start_shellinabox_console_nopid(self, mock_stop, mock_dir_exists,
                                             mock_popen):
        # no existing PID file before starting
        mock_stop.side_effect = exception.NoConsolePid('/tmp/blah')
        mock_popen.return_value.poll.return_value = 0

        # touch the pid file
        pid_file = console_utils._get_console_pid_file(self.info['uuid'])
        open(pid_file, 'a').close()
        self.assertTrue(os.path.exists(pid_file))

        console_utils.start_shellinabox_console(self.info['uuid'],
                                                 self.info['port'],
                                                 'ls&')

        mock_stop.assert_called_once_with(self.info['uuid'])
        mock_dir_exists.assert_called_once_with()
        mock_popen.assert_called_once_with(mock.ANY,
                                           stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE)
        mock_popen.return_value.poll.assert_called_once_with()

    @mock.patch.object(subprocess, 'Popen', autospec=True)
    @mock.patch.object(console_utils, '_ensure_console_pid_dir_exists',
                       autospec=True)
    @mock.patch.object(console_utils, '_stop_console', autospec=True)
    def test_start_shellinabox_console_fail(self, mock_stop, mock_dir_exists,
                                            mock_popen):
        mock_popen.return_value.poll.return_value = 1
        mock_popen.return_value.communicate.return_value = ('output', 'error')

        self.assertRaises(exception.ConsoleSubprocessFailed,
                          console_utils.start_shellinabox_console,
                          self.info['uuid'],
                          self.info['port'],
                          'ls&')

        mock_stop.assert_called_once_with(self.info['uuid'])
        mock_dir_exists.assert_called_once_with()
        mock_popen.assert_called_once_with(mock.ANY,
                                           stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE)
        mock_popen.return_value.poll.assert_called_once_with()

    @mock.patch.object(subprocess, 'Popen', autospec=True)
    @mock.patch.object(console_utils, '_ensure_console_pid_dir_exists',
                       autospec=True)
    @mock.patch.object(console_utils, '_stop_console', autospec=True)
    def test_start_shellinabox_console_fail_nopiddir(self, mock_stop,
                                                     mock_dir_exists,
                                                     mock_popen):
        mock_dir_exists.side_effect = exception.ConsoleError(message='fail')
        mock_popen.return_value.poll.return_value = 0

        self.assertRaises(exception.ConsoleError,
                          console_utils.start_shellinabox_console,
                          self.info['uuid'],
                          self.info['port'],
                          'ls&')

        mock_stop.assert_called_once_with(self.info['uuid'])
        mock_dir_exists.assert_called_once_with()
        self.assertFalse(mock_popen.called)

    @mock.patch.object(console_utils, '_stop_console', autospec=True)
    def test_stop_shellinabox_console(self, mock_stop):

        console_utils.stop_shellinabox_console(self.info['uuid'])

        mock_stop.assert_called_once_with(self.info['uuid'])

    @mock.patch.object(console_utils, '_stop_console', autospec=True)
    def test_stop_shellinabox_console_fail_nopid(self, mock_stop):
        mock_stop.side_effect = exception.NoConsolePid('/tmp/blah')

        console_utils.stop_shellinabox_console(self.info['uuid'])

        mock_stop.assert_called_once_with(self.info['uuid'])

    @mock.patch.object(console_utils, '_stop_console', autospec=True)
    def test_stop_shellinabox_console_fail_nokill(self, mock_stop):
        mock_stop.side_effect = processutils.ProcessExecutionError()

        self.assertRaises(exception.ConsoleError,
                          console_utils.stop_shellinabox_console,
                          self.info['uuid'])

        mock_stop.assert_called_once_with(self.info['uuid'])
