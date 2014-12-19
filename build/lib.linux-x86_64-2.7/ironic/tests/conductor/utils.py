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

"""Test utils for Ironic Managers."""

from ironic.common import driver_factory
import pkg_resources
from stevedore import dispatch


def mock_the_extension_manager(driver="fake", namespace="ironic.drivers"):
    """Get a fake stevedore NameDispatchExtensionManager instance.

    :param namespace: A string representing the namespace over which to
                      search for entrypoints.
    :returns mock_ext_mgr: A DriverFactory instance that has been faked.
    :returns mock_ext: A real plugin loaded by mock_ext_mgr in the specified
                       namespace.

    """
    entry_point = None
    for ep in list(pkg_resources.iter_entry_points(namespace)):
        s = "%s" % ep
        if driver == s[:s.index(' =')]:
            entry_point = ep
            break

    # NOTE(lucasagomes): Initialize the _extension_manager before
    #                    instantiaing a DriverFactory class to avoid
    #                    a real NameDispatchExtensionManager to be created
    #                    with the real namespace.
    driver_factory.DriverFactory._extension_manager = \
            dispatch.NameDispatchExtensionManager('ironic.no-such-namespace',
                                                  lambda x: True)
    mock_ext_mgr = driver_factory.DriverFactory()
    mock_ext = mock_ext_mgr._extension_manager._load_one_plugin(
                                              entry_point, True, [], {}, False)
    mock_ext_mgr._extension_manager.extensions = [mock_ext]
    mock_ext_mgr._extension_manager.by_name = dict((e.name, e)
                                                   for e in [mock_ext])

    return (mock_ext_mgr, mock_ext)
