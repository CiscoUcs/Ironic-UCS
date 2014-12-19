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
Wrapper for pywsman.Client
"""

from xml.etree import ElementTree

from oslo.utils import importutils

from ironic.common import exception

pywsman = importutils.try_import('pywsman')

_SOAP_ENVELOPE_URI = 'http://www.w3.org/2003/05/soap-envelope'

# Filter Dialects, see (Section 2.3.1):
# http://en.community.dell.com/techcenter/extras/m/white_papers/20439105.aspx
_FILTER_DIALECT_MAP = {'cql': 'http://schemas.dmtf.org/wbem/cql/1/dsp0202.pdf',
                       'wql': 'http://schemas.microsoft.com/wbem/wsman/1/WQL'}


class Client(object):

    def __init__(self, drac_host, drac_port, drac_path, drac_protocol,
                 drac_username, drac_password):
        pywsman_client = pywsman.Client(drac_host, drac_port, drac_path,
                                        drac_protocol, drac_username,
                                        drac_password)
        # TODO(ifarkas): Add support for CACerts
        pywsman.wsman_transport_set_verify_peer(pywsman_client, False)

        self.client = pywsman_client

    def wsman_enumerate(self, resource_uri, options, filter_query=None,
                        filter_dialect='cql'):
        """Enumerates a remote WS-Man class.

        :param resource_uri: URI of the resource.
        :param options: client options.
        :param filter_query: the query string.
        :param filter_dialect: the filter dialect. Valid options are:
                               'cql' and 'wql'. Defaults to 'cql'.
        :raises: DracClientError on an error from pywsman library.
        :raises: DracInvalidFilterDialect if an invalid filter dialect
                 was specified.
        :returns: an ElementTree object of the response received.
        """
        filter_ = None
        if filter_query is not None:
            try:
                filter_dialect = _FILTER_DIALECT_MAP[filter_dialect]
            except KeyError:
                valid_opts = ', '.join(_FILTER_DIALECT_MAP)
                raise exception.DracInvalidFilterDialect(
                    invalid_filter=filter_dialect, supported=valid_opts)

            filter_ = pywsman.Filter()
            filter_.simple(filter_dialect, filter_query)

        options.set_flags(pywsman.FLAG_ENUMERATION_OPTIMIZATION)
        options.set_max_elements(100)

        doc = self.client.enumerate(options, filter_, resource_uri)
        root = self._get_root(doc)

        final_xml = root
        find_query = './/{%s}Body' % _SOAP_ENVELOPE_URI
        insertion_point = final_xml.find(find_query)
        while doc.context() is not None:
            doc = self.client.pull(options, None, resource_uri,
                                   str(doc.context()))
            root = self._get_root(doc)
            for result in root.findall(find_query):
                for child in list(result):
                    insertion_point.append(child)

        return final_xml

    def wsman_invoke(self, resource_uri, options, method):
        """Invokes a remote WS-Man method.

        :param resource_uri: URI of the resource.
        :param options: client options.
        :param method: name of the method to invoke.
        :raises: DracClientError on an error from pywsman library.
        :returns: an ElementTree object of the response received.
        """
        doc = self.client.invoke(options, resource_uri, method)
        return self._get_root(doc)

    def _get_root(self, doc):
        if doc is None or doc.root() is None:
            raise exception.DracClientError(
                    last_error=self.client.last_error(),
                    fault_string=self.client.fault_string(),
                    response_code=self.client.response_code())
        root = doc.root()
        return ElementTree.fromstring(root.string())
