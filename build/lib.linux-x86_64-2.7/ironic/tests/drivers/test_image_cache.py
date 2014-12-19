# -*- encoding: utf-8 -*-
#
# Copyright 2014 Red Hat, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""Tests for ImageCache class and helper functions."""

import mock
import os
import tempfile
import time

from ironic.common import exception
from ironic.common import image_service
from ironic.common import images
from ironic.common import utils
from ironic.drivers.modules import image_cache
from ironic.tests import base


def touch(filename):
    open(filename, 'w').close()


@mock.patch.object(image_cache, '_fetch_to_raw')
class TestImageCacheFetch(base.TestCase):

    def setUp(self):
        super(TestImageCacheFetch, self).setUp()
        self.master_dir = tempfile.mkdtemp()
        self.cache = image_cache.ImageCache(self.master_dir, None, None)
        self.dest_dir = tempfile.mkdtemp()
        self.dest_path = os.path.join(self.dest_dir, 'dest')
        self.uuid = 'uuid'
        self.master_path = os.path.join(self.master_dir, self.uuid)

    @mock.patch.object(image_cache.ImageCache, 'clean_up')
    @mock.patch.object(image_cache.ImageCache, '_download_image')
    def test_fetch_image_no_master_dir(self, mock_download, mock_clean_up,
                                       mock_fetch_to_raw):
        self.cache.master_dir = None
        self.cache.fetch_image('uuid', self.dest_path)
        self.assertFalse(mock_download.called)
        mock_fetch_to_raw.assert_called_once_with(
            None, 'uuid', self.dest_path, None)
        self.assertFalse(mock_clean_up.called)

    @mock.patch.object(image_cache.ImageCache, 'clean_up')
    @mock.patch.object(image_cache.ImageCache, '_download_image')
    def test_fetch_image_dest_exists(self, mock_download, mock_clean_up,
                                     mock_fetch_to_raw):
        touch(self.dest_path)
        self.cache.fetch_image(self.uuid, self.dest_path)
        self.assertFalse(mock_download.called)
        self.assertFalse(mock_fetch_to_raw.called)
        self.assertFalse(mock_clean_up.called)

    @mock.patch.object(image_cache.ImageCache, 'clean_up')
    @mock.patch.object(image_cache.ImageCache, '_download_image')
    def test_fetch_image_master_exists(self, mock_download, mock_clean_up,
                                       mock_fetch_to_raw):
        touch(self.master_path)
        self.cache.fetch_image(self.uuid, self.dest_path)
        self.assertFalse(mock_download.called)
        self.assertFalse(mock_fetch_to_raw.called)
        self.assertTrue(os.path.isfile(self.dest_path))
        self.assertEqual(os.stat(self.dest_path).st_ino,
                         os.stat(self.master_path).st_ino)
        self.assertFalse(mock_clean_up.called)

    @mock.patch.object(image_cache.ImageCache, 'clean_up')
    @mock.patch.object(image_cache.ImageCache, '_download_image')
    def test_fetch_image(self, mock_download, mock_clean_up,
                         mock_fetch_to_raw):
        self.cache.fetch_image(self.uuid, self.dest_path)
        self.assertFalse(mock_fetch_to_raw.called)
        mock_download.assert_called_once_with(
            self.uuid, self.master_path, self.dest_path, ctx=None)
        self.assertTrue(mock_clean_up.called)

    def test__download_image(self, mock_fetch_to_raw):
        def _fake_fetch_to_raw(ctx, uuid, tmp_path, *args):
            self.assertEqual(self.uuid, uuid)
            self.assertNotEqual(self.dest_path, tmp_path)
            self.assertNotEqual(os.path.dirname(tmp_path), self.master_dir)
            with open(tmp_path, 'w') as fp:
                fp.write("TEST")

        mock_fetch_to_raw.side_effect = _fake_fetch_to_raw
        self.cache._download_image(self.uuid, self.master_path, self.dest_path)
        self.assertTrue(os.path.isfile(self.dest_path))
        self.assertTrue(os.path.isfile(self.master_path))
        self.assertEqual(os.stat(self.dest_path).st_ino,
                         os.stat(self.master_path).st_ino)
        with open(self.dest_path) as fp:
            self.assertEqual("TEST", fp.read())


class TestImageCacheCleanUp(base.TestCase):

    def setUp(self):
        super(TestImageCacheCleanUp, self).setUp()
        self.master_dir = tempfile.mkdtemp()
        self.cache = image_cache.ImageCache(self.master_dir,
                                            cache_size=10,
                                            cache_ttl=600)

    @mock.patch.object(image_cache.ImageCache, '_clean_up_ensure_cache_size')
    def test_clean_up_old_deleted(self, mock_clean_size):
        mock_clean_size.return_value = None
        files = [os.path.join(self.master_dir, str(i))
                 for i in range(2)]
        for filename in files:
            touch(filename)
        # NOTE(dtantsur): Can't alter ctime, have to set mtime to the future
        new_current_time = time.time() + 900
        os.utime(files[0], (new_current_time - 100, new_current_time - 100))
        with mock.patch.object(time, 'time', lambda: new_current_time):
            self.cache.clean_up()

        mock_clean_size.assert_called_once_with(mock.ANY, None)
        survived = mock_clean_size.call_args[0][0]
        self.assertEqual(1, len(survived))
        self.assertEqual(files[0], survived[0][0])
        # NOTE(dtantsur): do not compare milliseconds
        self.assertEqual(int(new_current_time - 100), int(survived[0][1]))
        self.assertEqual(int(new_current_time - 100),
                         int(survived[0][2].st_mtime))

    @mock.patch.object(image_cache.ImageCache, '_clean_up_ensure_cache_size')
    def test_clean_up_old_with_amount(self, mock_clean_size):
        files = [os.path.join(self.master_dir, str(i))
                 for i in range(2)]
        for filename in files:
            open(filename, 'wb').write('X')
        new_current_time = time.time() + 900
        with mock.patch.object(time, 'time', lambda: new_current_time):
            self.cache.clean_up(amount=1)

        self.assertFalse(mock_clean_size.called)
        # Exactly one file is expected to be deleted
        self.assertTrue(any(os.path.exists(f) for f in files))
        self.assertFalse(all(os.path.exists(f) for f in files))

    @mock.patch.object(image_cache.ImageCache, '_clean_up_ensure_cache_size')
    def test_clean_up_files_with_links_untouched(self, mock_clean_size):
        mock_clean_size.return_value = None
        files = [os.path.join(self.master_dir, str(i))
                 for i in range(2)]
        for filename in files:
            touch(filename)
            os.link(filename, filename + 'copy')

        new_current_time = time.time() + 900
        with mock.patch.object(time, 'time', lambda: new_current_time):
            self.cache.clean_up()

        for filename in files:
            self.assertTrue(os.path.exists(filename))
        mock_clean_size.assert_called_once_with([], None)

    @mock.patch.object(image_cache.ImageCache, '_clean_up_too_old')
    def test_clean_up_ensure_cache_size(self, mock_clean_ttl):
        mock_clean_ttl.side_effect = lambda *xx: xx
        # NOTE(dtantsur): Cache size in test is 10 bytes, we create 6 files
        # with 3 bytes each and expect 3 to be deleted
        files = [os.path.join(self.master_dir, str(i))
                 for i in range(6)]
        for filename in files:
            with open(filename, 'w') as fp:
                fp.write('123')
        # NOTE(dtantsur): Make 3 files 'newer' to check that
        # old ones are deleted first
        new_current_time = time.time() + 100
        for filename in files[:3]:
            os.utime(filename, (new_current_time, new_current_time))

        with mock.patch.object(time, 'time', lambda: new_current_time):
            self.cache.clean_up()

        for filename in files[:3]:
            self.assertTrue(os.path.exists(filename))
        for filename in files[3:]:
            self.assertFalse(os.path.exists(filename))

        mock_clean_ttl.assert_called_once_with(mock.ANY, None)

    @mock.patch.object(image_cache.ImageCache, '_clean_up_too_old')
    def test_clean_up_ensure_cache_size_with_amount(self, mock_clean_ttl):
        mock_clean_ttl.side_effect = lambda *xx: xx
        # NOTE(dtantsur): Cache size in test is 10 bytes, we create 6 files
        # with 3 bytes each and set amount to be 15, 5 files are to be deleted
        files = [os.path.join(self.master_dir, str(i))
                 for i in range(6)]
        for filename in files:
            with open(filename, 'w') as fp:
                fp.write('123')
        # NOTE(dtantsur): Make 1 file 'newer' to check that
        # old ones are deleted first
        new_current_time = time.time() + 100
        os.utime(files[0], (new_current_time, new_current_time))

        with mock.patch.object(time, 'time', lambda: new_current_time):
            self.cache.clean_up(amount=15)

        self.assertTrue(os.path.exists(files[0]))
        for filename in files[5:]:
            self.assertFalse(os.path.exists(filename))

        mock_clean_ttl.assert_called_once_with(mock.ANY, 15)

    @mock.patch.object(image_cache.LOG, 'info')
    @mock.patch.object(image_cache.ImageCache, '_clean_up_too_old')
    def test_clean_up_cache_still_large(self, mock_clean_ttl, mock_log):
        mock_clean_ttl.side_effect = lambda *xx: xx
        # NOTE(dtantsur): Cache size in test is 10 bytes, we create 2 files
        # than cannot be deleted and expected this to be logged
        files = [os.path.join(self.master_dir, str(i))
                 for i in range(2)]
        for filename in files:
            with open(filename, 'w') as fp:
                fp.write('123')
            os.link(filename, filename + 'copy')

        self.cache.clean_up()

        for filename in files:
            self.assertTrue(os.path.exists(filename))
        self.assertTrue(mock_log.called)
        mock_clean_ttl.assert_called_once_with(mock.ANY, None)

    @mock.patch.object(utils, 'rmtree_without_raise')
    @mock.patch.object(image_cache, '_fetch_to_raw')
    def test_temp_images_not_cleaned(self, mock_fetch_to_raw, mock_rmtree):
        def _fake_fetch_to_raw(ctx, uuid, tmp_path, *args):
            with open(tmp_path, 'w') as fp:
                fp.write("TEST" * 10)

            # assume cleanup from another thread at this moment
            self.cache.clean_up()
            self.assertTrue(os.path.exists(tmp_path))

        mock_fetch_to_raw.side_effect = _fake_fetch_to_raw
        master_path = os.path.join(self.master_dir, 'uuid')
        dest_path = os.path.join(tempfile.mkdtemp(), 'dest')
        self.cache._download_image('uuid', master_path, dest_path)
        self.assertTrue(mock_rmtree.called)

    @mock.patch.object(utils, 'rmtree_without_raise')
    @mock.patch.object(image_cache, '_fetch_to_raw')
    def test_temp_dir_exception(self, mock_fetch_to_raw, mock_rmtree):
        mock_fetch_to_raw.side_effect = exception.IronicException
        self.assertRaises(exception.IronicException,
                          self.cache._download_image,
                          'uuid', 'fake', 'fake')
        self.assertTrue(mock_rmtree.called)

    @mock.patch.object(image_cache.LOG, 'warn')
    @mock.patch.object(image_cache.ImageCache, '_clean_up_too_old')
    @mock.patch.object(image_cache.ImageCache, '_clean_up_ensure_cache_size')
    def test_clean_up_amount_not_satisfied(self, mock_clean_size,
                                           mock_clean_ttl, mock_log):
        mock_clean_ttl.side_effect = lambda *xx: xx
        mock_clean_size.side_effect = lambda listing, amount: amount
        self.cache.clean_up(amount=15)
        self.assertTrue(mock_log.called)

    def test_cleanup_ordering(self):

        class ParentCache(image_cache.ImageCache):
            def __init__(self):
                super(ParentCache, self).__init__('a', 1, 1, None)

        @image_cache.cleanup(priority=10000)
        class Cache1(ParentCache):
            pass

        @image_cache.cleanup(priority=20000)
        class Cache2(ParentCache):
            pass

        @image_cache.cleanup(priority=10000)
        class Cache3(ParentCache):
            pass

        self.assertEqual(image_cache._cache_cleanup_list[0][1], Cache2)

        # The order of caches with same prioirty is not deterministic.
        item_possibilities = [Cache1, Cache3]
        second_item_actual = image_cache._cache_cleanup_list[1][1]
        self.assertIn(second_item_actual, item_possibilities)
        item_possibilities.remove(second_item_actual)
        third_item_actual = image_cache._cache_cleanup_list[2][1]
        self.assertEqual(item_possibilities[0], third_item_actual)


@mock.patch.object(image_cache, '_cache_cleanup_list')
@mock.patch.object(os, 'statvfs')
@mock.patch.object(image_service, 'Service')
class CleanupImageCacheTestCase(base.TestCase):

    def setUp(self):
        super(CleanupImageCacheTestCase, self).setUp()
        self.mock_first_cache = mock.MagicMock()
        self.mock_second_cache = mock.MagicMock()
        self.cache_cleanup_list = [(50, self.mock_first_cache),
                                   (20, self.mock_second_cache)]
        self.mock_first_cache.return_value.master_dir = 'first_cache_dir'
        self.mock_second_cache.return_value.master_dir = 'second_cache_dir'

    def test_no_clean_up(self, mock_image_service, mock_statvfs,
                         cache_cleanup_list_mock):
        # Enough space found - no clean up
        mock_show = mock_image_service.return_value.show
        mock_show.return_value = dict(size=42)
        mock_statvfs.return_value = mock.Mock(f_frsize=1, f_bavail=1024)

        cache_cleanup_list_mock.__iter__.return_value = self.cache_cleanup_list

        image_cache.clean_up_caches(None, 'master_dir', [('uuid', 'path')])

        mock_show.assert_called_once_with('uuid')
        mock_statvfs.assert_called_once_with('master_dir')
        self.assertFalse(self.mock_first_cache.return_value.clean_up.called)
        self.assertFalse(self.mock_second_cache.return_value.clean_up.called)

        mock_statvfs.assert_called_once_with('master_dir')

    @mock.patch.object(os, 'stat')
    def test_one_clean_up(self, mock_stat, mock_image_service, mock_statvfs,
                          cache_cleanup_list_mock):
        # Not enough space, first cache clean up is enough
        mock_stat.return_value.st_dev = 1
        mock_show = mock_image_service.return_value.show
        mock_show.return_value = dict(size=42)
        mock_statvfs.side_effect = [
            mock.Mock(f_frsize=1, f_bavail=1),
            mock.Mock(f_frsize=1, f_bavail=1024)
        ]
        cache_cleanup_list_mock.__iter__.return_value = self.cache_cleanup_list
        image_cache.clean_up_caches(None, 'master_dir', [('uuid', 'path')])

        mock_show.assert_called_once_with('uuid')
        mock_statvfs.assert_called_with('master_dir')
        self.assertEqual(2, mock_statvfs.call_count)
        self.mock_first_cache.return_value.clean_up.assert_called_once_with(
            amount=(42 - 1))
        self.assertFalse(self.mock_second_cache.return_value.clean_up.called)

        # Since we are using generator expression in clean_up_caches, stat on
        # second cache wouldn't be called if we got enough free space on
        # cleaning up the first cache.
        mock_stat_calls_expected = [mock.call('master_dir'),
                                    mock.call('first_cache_dir')]
        mock_statvfs_calls_expected = [mock.call('master_dir'),
                                       mock.call('master_dir')]
        self.assertEqual(mock_stat_calls_expected, mock_stat.mock_calls)
        self.assertEqual(mock_statvfs_calls_expected, mock_statvfs.mock_calls)

    @mock.patch.object(os, 'stat')
    def test_clean_up_another_fs(self, mock_stat, mock_image_service,
                                 mock_statvfs, cache_cleanup_list_mock):
        # Not enough space, need to cleanup second cache
        mock_stat.side_effect = [mock.Mock(st_dev=1),
                                 mock.Mock(st_dev=2),
                                 mock.Mock(st_dev=1)]
        mock_show = mock_image_service.return_value.show
        mock_show.return_value = dict(size=42)
        mock_statvfs.side_effect = [
            mock.Mock(f_frsize=1, f_bavail=1),
            mock.Mock(f_frsize=1, f_bavail=1024)
        ]

        cache_cleanup_list_mock.__iter__.return_value = self.cache_cleanup_list
        image_cache.clean_up_caches(None, 'master_dir', [('uuid', 'path')])

        mock_show.assert_called_once_with('uuid')
        mock_statvfs.assert_called_with('master_dir')
        self.assertEqual(2, mock_statvfs.call_count)
        self.mock_second_cache.return_value.clean_up.assert_called_once_with(
            amount=(42 - 1))
        self.assertFalse(self.mock_first_cache.return_value.clean_up.called)

        # Since first cache exists on a different partition, it wouldn't be
        # considered for cleanup.
        mock_stat_calls_expected = [mock.call('master_dir'),
                                    mock.call('first_cache_dir'),
                                    mock.call('second_cache_dir')]
        mock_statvfs_calls_expected = [mock.call('master_dir'),
                                       mock.call('master_dir')]
        self.assertEqual(mock_stat_calls_expected, mock_stat.mock_calls)
        self.assertEqual(mock_statvfs_calls_expected, mock_statvfs.mock_calls)

    @mock.patch.object(os, 'stat')
    def test_both_clean_up(self, mock_stat, mock_image_service, mock_statvfs,
                           cache_cleanup_list_mock):
        # Not enough space, clean up of both caches required
        mock_stat.return_value.st_dev = 1
        mock_show = mock_image_service.return_value.show
        mock_show.return_value = dict(size=42)
        mock_statvfs.side_effect = [
            mock.Mock(f_frsize=1, f_bavail=1),
            mock.Mock(f_frsize=1, f_bavail=2),
            mock.Mock(f_frsize=1, f_bavail=1024)
        ]

        cache_cleanup_list_mock.__iter__.return_value = self.cache_cleanup_list
        image_cache.clean_up_caches(None, 'master_dir', [('uuid', 'path')])

        mock_show.assert_called_once_with('uuid')
        mock_statvfs.assert_called_with('master_dir')
        self.assertEqual(3, mock_statvfs.call_count)
        self.mock_first_cache.return_value.clean_up.assert_called_once_with(
            amount=(42 - 1))
        self.mock_second_cache.return_value.clean_up.assert_called_once_with(
            amount=(42 - 2))

        mock_stat_calls_expected = [mock.call('master_dir'),
                                    mock.call('first_cache_dir'),
                                    mock.call('second_cache_dir')]
        mock_statvfs_calls_expected = [mock.call('master_dir'),
                                       mock.call('master_dir'),
                                       mock.call('master_dir')]
        self.assertEqual(mock_stat_calls_expected, mock_stat.mock_calls)
        self.assertEqual(mock_statvfs_calls_expected, mock_statvfs.mock_calls)

    @mock.patch.object(os, 'stat')
    def test_clean_up_fail(self, mock_stat, mock_image_service, mock_statvfs,
                           cache_cleanup_list_mock):
        # Not enough space even after cleaning both caches - failure
        mock_stat.return_value.st_dev = 1
        mock_show = mock_image_service.return_value.show
        mock_show.return_value = dict(size=42)
        mock_statvfs.return_value = mock.Mock(f_frsize=1, f_bavail=1)

        cache_cleanup_list_mock.__iter__.return_value = self.cache_cleanup_list
        self.assertRaises(exception.InsufficientDiskSpace,
                          image_cache.clean_up_caches,
                          None, 'master_dir', [('uuid', 'path')])

        mock_show.assert_called_once_with('uuid')
        mock_statvfs.assert_called_with('master_dir')
        self.assertEqual(3, mock_statvfs.call_count)
        self.mock_first_cache.return_value.clean_up.assert_called_once_with(
            amount=(42 - 1))
        self.mock_second_cache.return_value.clean_up.assert_called_once_with(
            amount=(42 - 1))

        mock_stat_calls_expected = [mock.call('master_dir'),
                                    mock.call('first_cache_dir'),
                                    mock.call('second_cache_dir')]
        mock_statvfs_calls_expected = [mock.call('master_dir'),
                                       mock.call('master_dir'),
                                       mock.call('master_dir')]
        self.assertEqual(mock_stat_calls_expected, mock_stat.mock_calls)
        self.assertEqual(mock_statvfs_calls_expected, mock_statvfs.mock_calls)


class TestFetchCleanup(base.TestCase):

    def setUp(self):
        super(TestFetchCleanup, self).setUp()

    @mock.patch.object(images, 'converted_size')
    @mock.patch.object(images, 'fetch')
    @mock.patch.object(images, 'image_to_raw')
    @mock.patch.object(image_cache, '_clean_up_caches')
    def test__fetch_to_raw(self, mock_clean, mock_raw, mock_fetch, mock_size):
        mock_size.return_value = 100
        image_cache._fetch_to_raw('fake', 'fake-uuid', '/foo/bar')
        mock_fetch.assert_called_once_with('fake', 'fake-uuid',
                                           '/foo/bar.part', None)
        mock_clean.assert_called_once_with('/foo', 100)
        mock_raw.assert_called_once_with('fake-uuid', '/foo/bar',
                                         '/foo/bar.part')
