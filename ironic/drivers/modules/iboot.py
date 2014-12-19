# -*- coding: utf-8 -*-
#
# Copyright 2014 Red Hat, Inc.
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

"""
Ironic iBoot PDU power manager.
"""

from oslo.utils import importutils

from ironic.common import exception
from ironic.common.i18n import _
from ironic.common.i18n import _LW
from ironic.common import states
from ironic.conductor import task_manager
from ironic.drivers import base
from ironic.openstack.common import log as logging

iboot = importutils.try_import('iboot')


LOG = logging.getLogger(__name__)

REQUIRED_PROPERTIES = {
    'iboot_address': _("IP address of the node. Required."),
    'iboot_username': _("username. Required."),
    'iboot_password': _("password. Required."),
}
OPTIONAL_PROPERTIES = {
    'iboot_relay_id': _("iBoot PDU relay id; default is 1. Optional."),
    'iboot_port': _("iBoot PDU port; default is 9100. Optional."),
}
COMMON_PROPERTIES = REQUIRED_PROPERTIES.copy()
COMMON_PROPERTIES.update(OPTIONAL_PROPERTIES)


def _parse_driver_info(node):
    info = node.driver_info or {}
    missing_info = [key for key in REQUIRED_PROPERTIES if not info.get(key)]
    if missing_info:
        raise exception.MissingParameterValue(_(
              "The following iBoot credentials were not supplied to iBoot PDU "
              "driver: %s.") % missing_info)

    address = info.get('iboot_address', None)
    username = info.get('iboot_username', None)
    password = info.get('iboot_password', None)

    relay_id = info.get('iboot_relay_id', 1)
    try:
        relay_id = int(relay_id)
    except ValueError:
        raise exception.InvalidParameterValue(_(
              "iBoot PDU relay id must be an integer."))

    port = info.get('iboot_port', 9100)
    try:
        port = int(port)
    except ValueError:
        raise exception.InvalidParameterValue(_(
              "iBoot PDU port must be an integer."))

    return {
            'address': address,
            'username': username,
            'password': password,
            'port': port,
            'relay_id': relay_id,
            'uuid': node.uuid,
           }


def _get_connection(driver_info):
    # NOTE: python-iboot wants username and password as strings (not unicode)
    return iboot.iBootInterface(driver_info['address'],
                                str(driver_info['username']),
                                str(driver_info['password']),
                                port=driver_info['port'],
                                num_relays=driver_info['relay_id'])


def _switch(driver_info, enabled):
    conn = _get_connection(driver_info)
    relay_id = driver_info['relay_id']
    return conn.switch(relay_id, enabled)


def _power_status(driver_info):
    conn = _get_connection(driver_info)
    relay_id = driver_info['relay_id']
    try:
        response = conn.get_relays()
        status = response[relay_id - 1]
    except TypeError:
        msg = (_("Cannot get power status for node '%(node)s'. iBoot "
                 "get_relays() returned '%(resp)s'.")
                 % {'node': driver_info['uuid'], 'resp': response})
        LOG.error(msg)
        raise exception.IBootOperationError(message=msg)
    except IndexError:
        LOG.warning(_LW("Cannot get power status for node '%(node)s' at relay "
                        "'%(relay)s'. iBoot get_relays() returned "
                        "'%(resp)s'."),
                        {'node': driver_info['uuid'], 'relay': relay_id,
                         'resp': response})
        return states.ERROR

    if status:
        return states.POWER_ON
    else:
        return states.POWER_OFF


class IBootPower(base.PowerInterface):
    """iBoot PDU Power Driver for Ironic

    This PowerManager class provides a mechanism for controlling power state
    via an iBoot capable device.

    Requires installation of python-iboot:

        https://github.com/darkip/python-iboot

    """

    def get_properties(self):
        return COMMON_PROPERTIES

    def validate(self, task):
        """Validate driver_info for iboot driver.

        :param task: a TaskManager instance containing the node to act on.
        :raises: InvalidParameterValue if iboot parameters are invalid.
        :raises: MissingParameterValue if required iboot parameters are
            missing.

        """
        _parse_driver_info(task.node)

    def get_power_state(self, task):
        """Get the current power state of the task's node.

        :param task: a TaskManager instance containing the node to act on.
        :returns: one of ironic.common.states POWER_OFF, POWER_ON or ERROR.
        :raises: IBootOperationError on an error from iBoot.
        :raises: InvalidParameterValue if iboot parameters are invalid.
        :raises: MissingParameterValue if required iboot parameters are
            missing.

        """
        driver_info = _parse_driver_info(task.node)
        return _power_status(driver_info)

    @task_manager.require_exclusive_lock
    def set_power_state(self, task, pstate):
        """Turn the power on or off.

        :param task: a TaskManager instance containing the node to act on.
        :param pstate: The desired power state, one of ironic.common.states
            POWER_ON, POWER_OFF.
        :raises: IBootOperationError on an error from iBoot.
        :raises: InvalidParameterValue if iboot parameters are invalid or if
            an invalid power state was specified.
        :raises: MissingParameterValue if required iboot parameters are
            missing.
        :raises: PowerStateFailure if the power couldn't be set to pstate.

        """
        driver_info = _parse_driver_info(task.node)
        if pstate == states.POWER_ON:
            _switch(driver_info, True)
        elif pstate == states.POWER_OFF:
            _switch(driver_info, False)
        else:
            raise exception.InvalidParameterValue(_(
                  "set_power_state called with invalid "
                  "power state %s.") % pstate)

        state = _power_status(driver_info)
        if state != pstate:
            raise exception.PowerStateFailure(pstate=pstate)

    @task_manager.require_exclusive_lock
    def reboot(self, task):
        """Cycles the power to the task's node.

        :param task: a TaskManager instance containing the node to act on.
        :raises: IBootOperationError on an error from iBoot.
        :raises: InvalidParameterValue if iboot parameters are invalid.
        :raises: MissingParameterValue if required iboot parameters are
            missing.
        :raises: PowerStateFailure if the final state of the node is not
            POWER_ON.

        """
        driver_info = _parse_driver_info(task.node)
        _switch(driver_info, False)
        _switch(driver_info, True)

        state = _power_status(driver_info)
        if state != states.POWER_ON:
            raise exception.PowerStateFailure(pstate=states.POWER_ON)
