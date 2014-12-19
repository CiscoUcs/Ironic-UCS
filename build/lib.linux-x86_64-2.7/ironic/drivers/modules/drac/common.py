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
Common functionalities shared between different DRAC modules.
"""

from oslo.utils import importutils

from ironic.common import exception
from ironic.common.i18n import _
from ironic.drivers.modules.drac import client as drac_client

pywsman = importutils.try_import('pywsman')

REQUIRED_PROPERTIES = {
    'drac_host': _('IP address or hostname of the DRAC card. Required.'),
    'drac_username': _('username used for authentication. Required.'),
    'drac_password': _('password used for authentication. Required.')
}
OPTIONAL_PROPERTIES = {
    'drac_port': _('port used for WS-Man endpoint; default is 443. Optional.'),
    'drac_path': _('path used for WS-Man endpoint; default is "/wsman". '
                   'Optional.'),
    'drac_protocol': _('protocol used for WS-Man endpoint; one of http, https;'
                       ' default is "https". Optional.'),
}
COMMON_PROPERTIES = REQUIRED_PROPERTIES.copy()
COMMON_PROPERTIES.update(OPTIONAL_PROPERTIES)

# ReturnValue constants
RET_SUCCESS = '0'
RET_ERROR = '2'
RET_CREATED = '4096'


def parse_driver_info(node):
    """Parses the driver_info of the node, reads default values
    and returns a dict containing the combination of both.

    :param node: an ironic node object.
    :returns: a dict containing information from driver_info
              and default values.
    :raises: InvalidParameterValue if some mandatory information
             is missing on the node or on invalid inputs.
    """
    driver_info = node.driver_info
    parsed_driver_info = {}

    error_msgs = []
    for param in REQUIRED_PROPERTIES:
        try:
            parsed_driver_info[param] = str(driver_info[param])
        except KeyError:
            error_msgs.append(_("'%s' not supplied to DracDriver.") % param)
        except UnicodeEncodeError:
            error_msgs.append(_("'%s' contains non-ASCII symbol.") % param)

    parsed_driver_info['drac_port'] = driver_info.get('drac_port', 443)

    try:
        parsed_driver_info['drac_path'] = str(driver_info.get('drac_path',
                                                              '/wsman'))
    except UnicodeEncodeError:
        error_msgs.append(_("'drac_path' contains non-ASCII symbol."))

    try:
        parsed_driver_info['drac_protocol'] = str(
            driver_info.get('drac_protocol', 'https'))
    except UnicodeEncodeError:
        error_msgs.append(_("'drac_protocol' contains non-ASCII symbol."))

    try:
        parsed_driver_info['drac_port'] = int(parsed_driver_info['drac_port'])
    except ValueError:
        error_msgs.append(_("'drac_port' is not an integer value."))

    if error_msgs:
        msg = (_('The following errors were encountered while parsing '
                 'driver_info:\n%s') % '\n'.join(error_msgs))
        raise exception.InvalidParameterValue(msg)

    return parsed_driver_info


def get_wsman_client(node):
    """Given an ironic node object, this method gives back a
    Client object which is a wrapper for pywsman.Client.

    :param node: an ironic node object.
    :returns: a Client object.
    :raises: InvalidParameterValue if some mandatory information
             is missing on the node or on invalid inputs.
    """
    driver_info = parse_driver_info(node)
    client = drac_client.Client(**driver_info)
    return client


def find_xml(doc, item, namespace, find_all=False):
    """Find the first or all elements in a ElementTree object.

    :param doc: the element tree object.
    :param item: the element name.
    :param namespace: the namespace of the element.
    :param find_all: Boolean value, if True find all elements, if False
                     find only the first one. Defaults to False.
    :returns: if find_all is False the element object will be returned
              if found, None if not found. If find_all is True a list of
              element objects will be returned or an empty list if no
              elements were found.

    """
    query = ('.//{%(namespace)s}%(item)s' % {'namespace': namespace,
                                             'item': item})
    if find_all:
        return doc.findall(query)
    return doc.find(query)
