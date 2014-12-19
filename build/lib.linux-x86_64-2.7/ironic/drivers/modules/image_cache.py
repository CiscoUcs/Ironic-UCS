# -*- encoding: utf-8 -*-
#
# Copyright 2013 Hewlett-Packard Development Company, L.P.
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
"""
Utility for caching master images.
"""

import os
import tempfile
import time

from oslo.config import cfg

from ironic.common import exception
from ironic.common.glance_service import service_utils
from ironic.common.i18n import _LI
from ironic.common.i18n import _LW
from ironic.common import images
from ironic.common import utils
from ironic.openstack.common import fileutils
from ironic.openstack.common import lockutils
from ironic.openstack.common import log as logging


LOG = logging.getLogger(__name__)

img_cache_opts = [
    cfg.BoolOpt('parallel_image_downloads',
                default=False,
                help='Run image downloads and raw format conversions in '
                     'parallel.'),
]

CONF = cfg.CONF
CONF.register_opts(img_cache_opts)

# This would contain a sorted list of instances of ImageCache to be
# considered for cleanup. This list will be kept sorted in non-increasing
# order of priority.
_cache_cleanup_list = []


class ImageCache(object):
    """Class handling access to cache for master images."""

    def __init__(self, master_dir, cache_size, cache_ttl,
                 image_service=None):
        """Constructor.

        :param master_dir: cache directory to work on
        :param cache_size: desired maximum cache size in bytes
        :param cache_ttl: cache entity TTL in seconds
        :param image_service: Glance image service to use, None for default
        """
        self.master_dir = master_dir
        self._cache_size = cache_size
        self._cache_ttl = cache_ttl
        self._image_service = image_service
        if master_dir is not None:
            fileutils.ensure_tree(master_dir)

    def fetch_image(self, uuid, dest_path, ctx=None):
        """Fetch image with given uuid to the destination path.

        Does nothing if destination path exists.
        Only creates a link if master image for this UUID is already in cache.
        Otherwise downloads an image and also stores it in cache.

        :param uuid: image UUID or href to fetch
        :param dest_path: destination file path
        :param ctx: context
        """
        img_download_lock_name = 'download-image'
        if self.master_dir is None:
            #NOTE(ghe): We don't share images between instances/hosts
            if not CONF.parallel_image_downloads:
                with lockutils.lock(img_download_lock_name, 'ironic-'):
                    _fetch_to_raw(ctx, uuid, dest_path, self._image_service)
            else:
                _fetch_to_raw(ctx, uuid, dest_path, self._image_service)
            return

        #TODO(ghe): have hard links and counts the same behaviour in all fs

        master_file_name = service_utils.parse_image_ref(uuid)[0]
        master_path = os.path.join(self.master_dir, master_file_name)

        if CONF.parallel_image_downloads:
            img_download_lock_name = 'download-image:%s' % master_file_name

        # TODO(dtantsur): lock expiration time
        with lockutils.lock(img_download_lock_name, 'ironic-'):
            if os.path.exists(dest_path):
                LOG.debug("Destination %(dest)s already exists for "
                            "image %(uuid)s" %
                          {'uuid': uuid,
                           'dest': dest_path})
                return

            try:
                # NOTE(dtantsur): ensure we're not in the middle of clean up
                with lockutils.lock('master_image', 'ironic-'):
                    os.link(master_path, dest_path)
            except OSError:
                LOG.info(_LI("Master cache miss for image %(uuid)s, "
                             "starting download"),
                         {'uuid': uuid})
            else:
                LOG.debug("Master cache hit for image %(uuid)s",
                          {'uuid': uuid})
                return

            self._download_image(uuid, master_path, dest_path, ctx=ctx)

        # NOTE(dtantsur): we increased cache size - time to clean up
        self.clean_up()

    def _download_image(self, uuid, master_path, dest_path, ctx=None):
        """Download image from Glance and store at a given path.
        This method should be called with uuid-specific lock taken.

        :param uuid: image UUID or href to fetch
        :param master_path: destination master path
        :param dest_path: destination file path
        :param ctx: context
        """
        #TODO(ghe): timeout and retry for downloads
        #TODO(ghe): logging when image cannot be created
        tmp_dir = tempfile.mkdtemp(dir=self.master_dir)
        tmp_path = os.path.join(tmp_dir, uuid)
        try:
            _fetch_to_raw(ctx, uuid, tmp_path, self._image_service)
            # NOTE(dtantsur): no need for global lock here - master_path
            # will have link count >1 at any moment, so won't be cleaned up
            os.link(tmp_path, master_path)
            os.link(master_path, dest_path)
        finally:
            utils.rmtree_without_raise(tmp_dir)

    @lockutils.synchronized('master_image', 'ironic-')
    def clean_up(self, amount=None):
        """Clean up directory with images, keeping cache of the latest images.

        Files with link count >1 are never deleted.
        Protected by global lock, so that no one messes with master images
        after we get listing and before we actually delete files.

        :param amount: if present, amount of space to reclaim in bytes,
                       cleaning will stop, if this goal was reached,
                       even if it is possible to clean up more files
        """
        if self.master_dir is None:
            return

        LOG.debug("Starting clean up for master image cache %(dir)s" %
                  {'dir': self.master_dir})

        amount_copy = amount
        listing = _find_candidates_for_deletion(self.master_dir)
        survived, amount = self._clean_up_too_old(listing, amount)
        if amount is not None and amount <= 0:
            return
        amount = self._clean_up_ensure_cache_size(survived, amount)
        if amount is not None and amount > 0:
            LOG.warn(_LW("Cache clean up was unable to reclaim %(required)d "
                       "MiB of disk space, still %(left)d MiB required"),
                     {'required': amount_copy / 1024 / 1024,
                      'left': amount / 1024 / 1024})

    def _clean_up_too_old(self, listing, amount):
        """Clean up stage 1: drop images that are older than TTL.

        This method removes files all files older than TTL seconds
        unless 'amount' is non-None. If 'amount' is non-None,
        it starts removing files older than TTL seconds,
        oldest first, until the required 'amount' of space is reclaimed.

        :param listing: list of tuples (file name, last used time)
        :param amount: if not None, amount of space to reclaim in bytes,
                       cleaning will stop, if this goal was reached,
                       even if it is possible to clean up more files
        :returns: tuple (list of files left after clean up,
                         amount still to reclaim)
        """
        threshold = time.time() - self._cache_ttl
        survived = []
        for file_name, last_used, stat in listing:
            if last_used < threshold:
                try:
                    os.unlink(file_name)
                except EnvironmentError as exc:
                    LOG.warn(_LW("Unable to delete file %(name)s from "
                                 "master image cache: %(exc)s"),
                             {'name': file_name, 'exc': exc})
                else:
                    if amount is not None:
                        amount -= stat.st_size
                        if amount <= 0:
                            amount = 0
                            break
            else:
                survived.append((file_name, last_used, stat))
        return survived, amount

    def _clean_up_ensure_cache_size(self, listing, amount):
        """Clean up stage 2: try to ensure cache size < threshold.
        Try to delete the oldest files until conditions is satisfied
        or no more files are eligable for delition.

        :param listing: list of tuples (file name, last used time)
        :param amount: amount of space to reclaim, if possible.
                       if amount is not None, it has higher priority than
                       cache size in settings
        :returns: amount of space still required after clean up
        """
        # NOTE(dtantsur): Sort listing to delete the oldest files first
        listing = sorted(listing,
                         key=lambda entry: entry[1],
                         reverse=True)
        total_listing = (os.path.join(self.master_dir, f)
                         for f in os.listdir(self.master_dir))
        total_size = sum(os.path.getsize(f)
                         for f in total_listing)
        while listing and (total_size > self._cache_size or
               (amount is not None and amount > 0)):
            file_name, last_used, stat = listing.pop()
            try:
                os.unlink(file_name)
            except EnvironmentError as exc:
                LOG.warn(_LW("Unable to delete file %(name)s from "
                             "master image cache: %(exc)s"),
                         {'name': file_name, 'exc': exc})
            else:
                total_size -= stat.st_size
                if amount is not None:
                    amount -= stat.st_size

        if total_size > self._cache_size:
            LOG.info(_LI("After cleaning up cache dir %(dir)s "
                         "cache size %(actual)d is still larger than "
                         "threshold %(expected)d"),
                     {'dir': self.master_dir, 'actual': total_size,
                      'expected': self._cache_size})
        return max(amount, 0)


def _find_candidates_for_deletion(master_dir):
    """Find files eligible for deletion i.e. with link count ==1.

    :param master_dir: directory to operate on
    :returns: iterator yielding tuples (file name, last used time, stat)
    """
    for filename in os.listdir(master_dir):
        filename = os.path.join(master_dir, filename)
        stat = os.stat(filename)
        if not os.path.isfile(filename) or stat.st_nlink > 1:
            continue
        # NOTE(dtantsur): Detect most recently accessed files,
        # seeing atime can be disabled by the mount option
        # Also include ctime as it changes when image is linked to
        last_used_time = max(stat.st_mtime, stat.st_atime, stat.st_ctime)
        yield filename, last_used_time, stat


def _free_disk_space_for(path):
    """Get free disk space on a drive where path is located."""
    stat = os.statvfs(path)
    return stat.f_frsize * stat.f_bavail


def _fetch_to_raw(context, image_href, path, image_service=None):
    """Fetch image and convert to raw format if needed."""
    path_tmp = "%s.part" % path
    images.fetch(context, image_href, path_tmp, image_service)
    required_space = images.converted_size(path_tmp)
    directory = os.path.dirname(path_tmp)
    _clean_up_caches(directory, required_space)
    images.image_to_raw(image_href, path, path_tmp)


def _clean_up_caches(directory, amount):
    """Explicitly cleanup caches based on their priority (if required).

    :param directory: the directory (of the cache) to be freed up.
    :param amount: amount of space to reclaim.
    :raises: InsufficientDiskSpace exception, if we cannot free up enough space
    after trying all the caches.
    """
    free = _free_disk_space_for(directory)

    if amount < free:
        return

    # NOTE(dtantsur): filter caches, whose directory is on the same device
    st_dev = os.stat(directory).st_dev

    caches_to_clean = [x[1]() for x in _cache_cleanup_list]
    caches = (c for c in caches_to_clean
              if os.stat(c.master_dir).st_dev == st_dev)
    for cache_to_clean in caches:
        cache_to_clean.clean_up(amount=(amount - free))
        free = _free_disk_space_for(directory)
        if amount < free:
            break
    else:
        raise exception.InsufficientDiskSpace(path=directory,
                                              required=amount / 1024 / 1024,
                                              actual=free / 1024 / 1024,
                                              )


def clean_up_caches(ctx, directory, images_info):
    """Explicitly cleanup caches based on their priority (if required).

    This cleans up the caches to free up the amount of space required for the
    images in images_info. The caches are cleaned up one after the other in
    the order of their priority.  If we still cannot free up enough space
    after trying all the caches, this method throws exception.

    :param ctx: context
    :param directory: the directory (of the cache) to be freed up.
    :param images_info: a list of tuples of the form (image_uuid,path)
        for which space is to be created in cache.
    :raises: InsufficientDiskSpace exception, if we cannot free up enough space
    after trying all the caches.
    """
    total_size = sum(images.download_size(ctx, uuid)
            for (uuid, path) in images_info)
    _clean_up_caches(directory, total_size)


def cleanup(priority):
    """Decorator method for adding cleanup priority to a class."""
    def _add_property_to_class_func(cls):
        _cache_cleanup_list.append((priority, cls))
        _cache_cleanup_list.sort(reverse=True)
        return cls

    return _add_property_to_class_func
