# -*- encoding: utf-8 -*-
#
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

"""The Ironic Service API."""

import logging
import sys

from oslo.config import cfg
from six.moves import socketserver
from wsgiref import simple_server

from ironic.api import app
from ironic.common.i18n import _LI
from ironic.common import service as ironic_service
from ironic.openstack.common import log

CONF = cfg.CONF


class ThreadedSimpleServer(socketserver.ThreadingMixIn,
                           simple_server.WSGIServer):
    """A Mixin class to make the API service greenthread-able."""
    pass


def main():
    # Pase config file and command line options, then start logging
    ironic_service.prepare_service(sys.argv)

    # Build and start the WSGI app
    host = CONF.api.host_ip
    port = CONF.api.port
    wsgi = simple_server.make_server(
            host, port,
            app.VersionSelectorApplication(),
            server_class=ThreadedSimpleServer)

    LOG = log.getLogger(__name__)
    LOG.info(_LI("Serving on http://%(host)s:%(port)s"),
             {'host': host, 'port': port})
    LOG.info(_LI("Configuration:"))
    CONF.log_opt_values(LOG, logging.INFO)

    try:
        wsgi.serve_forever()
    except KeyboardInterrupt:
        pass
