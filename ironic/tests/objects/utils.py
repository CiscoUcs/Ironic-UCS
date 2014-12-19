# Copyright 2014 Rackspace Hosting
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
"""Ironic object test utilities."""

from ironic import objects
from ironic.tests.db import utils as db_utils


def get_test_node(ctxt, **kw):
    """Return a Node object with appropriate attributes.

    NOTE: The object leaves the attributes marked as changed, such
    that a create() could be used to commit it to the DB.
    """
    db_node = db_utils.get_test_node(**kw)
    node = objects.Node(ctxt)
    for key in db_node:
        setattr(node, key, db_node[key])
    return node


def create_test_node(ctxt, **kw):
    """Create a node in the DB and return a Node object with appropriate
    attributes.
    """
    node = get_test_node(ctxt, **kw)
    node.create()
    return node


def get_test_port(ctxt, **kw):
    """Return a Port object with appropriate attributes.

    NOTE: The object leaves the attributes marked as changed, such
    that a create() could be used to commit it to the DB.
    """
    db_port = db_utils.get_test_port(**kw)
    port = objects.Port(ctxt)
    for key in db_port:
        setattr(port, key, db_port[key])
    return port


def create_test_port(ctxt, **kw):
    """Create a port in the DB and return a Port object with appropriate
    attributes.
    """
    port = get_test_port(ctxt, **kw)
    port.create()
    return port


def get_test_chassis(ctxt, **kw):
    """Return a Chassis object with appropriate attributes.

    NOTE: The object leaves the attributes marked as changed, such
    that a create() could be used to commit it to the DB.
    """
    db_chassis = db_utils.get_test_chassis(**kw)
    chassis = objects.Chassis(ctxt)
    for key in db_chassis:
        setattr(chassis, key, db_chassis[key])
    return chassis


def create_test_chassis(ctxt, **kw):
    """Create a chassis in the DB and return a Chassis object with appropriate
    attributes.
    """
    chassis = get_test_chassis(ctxt, **kw)
    chassis.create()
    return chassis
