#    Copyright 2014, Cisco Systems.

#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at

#        http://www.apache.org/licenses/LICENSE-2.0

#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.

"""
Ironic Cisco UCSM interfaces.

Provides basic power control of servers managed by Cisco UCSM using PyUcs Sdk.

Provides vendor passthru methods for Cisco UCSM specific functionality.
"""

from oslo.config import cfg

from ironic.common import exception
from ironic.common import states
from ironic.conductor import task_manager
from ironic.drivers import base
from ironic.openstack.common import importutils
from ironic.openstack.common import log as logging
from ironic.openstack.common import loopingcall
from ironic.db import api as db_api

ucssdk = importutils.try_import('UcsSdk')
if ucssdk:
    from UcsSdk import *


opts = [
    cfg.IntOpt('max_retry',
               default=10,
               help='No of retries'),
    cfg.IntOpt('action_timeout',
               default=5,
               help='Seconds to wait for power action to be completed'),
    cfg.IntOpt('dump_xml',
               default=True,
               help='Dump xml query response and responses')
]

# _LE = i18n._LE

CONF = cfg.CONF
opt_group = cfg.OptGroup(name='cisco',
                         title='Options for the cisco power driver')
CONF.register_group(opt_group)
CONF.register_opts(opts, opt_group)

LOG = logging.getLogger(__name__)

VENDOR_PASSTHRU_METHODS = [
    'launch_kvm', 'get_location',
    'get_inventory', 'get_faults', 
    'get_temperature_stats',
    'get_power_stats', 'get_firmware_version'
    ]

REQUIRED_PROPERTIES = {'ucsm_address': _("IP or hostname of the UCS Manager. Required."),
                       'ucsm_username': _("UCSM admin username. Required."),
                       'ucsm_password': _("UCSM login password. Required."),
                       'ucsm_service_profile': _("UCSM service-profile name. Required.")}

COMMON_PROPERTIES = REQUIRED_PROPERTIES

DRIVER_VENDOR_PASSTHRU_METHODS = ['enroll_nodes']

def get_processor_units(handle, compute_unit):
    """Gets the processor inventory of the passed computenode

    :param handle: Active UCS Manager handle
    :param compute_node: Compute node MO object
    :returns: Compute node adaptor inventory
    :raises: UcsException if driver failes to get inventory.
    """

    in_filter = FilterFilter()
    wcard_filter = WcardFilter()
    wcard_filter.Class = "processorUnit"
    wcard_filter.Property = "dn"
    wcard_filter.Value = "%s/" % compute_unit.Dn
    in_filter.AddChild(wcard_filter)
    p_units = {}

    try:
        processor_units = handle.ConfigResolveClass(
                              ProcessorUnit.ClassId(), 
                              in_filter, 
                              inHierarchical=YesOrNo.FALSE, 
                              #dumpXml=CONF.cisco.dump_xml
                              dumpXml=YesOrNo.TRUE
                              )

        if processor_units.errorCode == 0:
            for p_unit in processor_units.OutConfigs.GetChild():
                unit = {}
                unit['arch'] = p_unit.getattr(ProcessorUnit.ARCH)
                unit['cores'] = p_unit.getattr(ProcessorUnit.CORES)
                unit['coresEnabled'] = p_unit.getattr(
                                           ProcessorUnit.CORES_ENABLED)
                unit['model'] = p_unit.getattr(ProcessorUnit.MODEL)
                unit['socketDesignation'] = p_unit.getattr(
                                            ProcessorUnit.SOCKET_DESIGNATION)
                unit['speed'] = p_unit.getattr(ProcessorUnit.SPEED)
                unit['stepping'] = p_unit.getattr(ProcessorUnit.STEPPING)
                unit['threads'] = p_unit.getattr(ProcessorUnit.THREADS)
                unit['vendor'] = p_unit.getattr(ProcessorUnit.VENDOR)
                p_units['AdaptorUnit-%s' % (p_unit.getattr(ProcessorUnit.ID))] = unit
            pass
        pass
    except Exception as ex:
        raise exception.IronicException("Cisco Driver: %s" % ex)
    return p_units
pass

def get_memory_inventory(handle, compute_blade):
    """Gets the memory inventory of the passed computenode

    :param handle: Active UCS Manager handle
    :param compute_node: Compute node MO object
    :returns: Compute node adaptor inventory
    :raises: UcsException if driver failes to get inventory.
    """
    in_filter = FilterFilter()
    wcard_filter = WcardFilter()
    wcard_filter.Class = "memoryArray"
    wcard_filter.Property = "dn"
    wcard_filter.Value = "%s/" % compute_blade.Dn
    in_filter.AddChild(wcard_filter)
    mem_arrays = {}

    try: 
        m_arrays = handle.ConfigResolveClass(
                            MemoryArray.ClassId(),
                            in_filter,
                            inHierarchical=YesOrNo.FALSE,
                            #dumpXml=CONF.cisco.dump_xml
                            dumpXml=YesOrNo.TRUE
                            )

        if (m_arrays.errorCode == 0):
            for array in m_arrays.OutConfigs.GetChild():
                unit = {}
                unit['cpuId'] = array.getattr(MemoryArray.CPU_ID)
                unit['currCapacity'] = array.getattr(MemoryArray.CURR_CAPACITY)
                unit['maxCapacity'] = array.getattr(MemoryArray.MAX_CAPACITY)
                unit['populated'] = array.getattr(MemoryArray.POPULATED)
                mem_arrays['MemoryArray-%s' % (array.getattr(MemoryArray.ID))] = unit
            pass
    except UcsException as ex:
        raise exception.IronicException("Cisco Driver: %s" % ex)
    return mem_arrays
pass

def get_storage_inventory(handle, compute_blade):
    """Gets the storage inventory of the passed computenode

    :param handle: Active UCS Manager handle
    :param compute_node: Compute node MO object
    :returns: Compute node adaptor inventory
    :raises: UcsException if driver failes to get inventory.
    """

    in_filter = FilterFilter()
    wcard_filter = WcardFilter()
    wcard_filter.Class = "storageLocalDisk"
    wcard_filter.Property = "dn"
    wcard_filter.Value = "%s/" % compute_blade.Dn
    in_filter.AddChild(wcard_filter)

    disks = {}
    try:
        local_disks = handle.ConfigResolveClass(
                                  StorageLocalDisk.ClassId(), 
                                  in_filter, 
                                  inHierarchical=YesOrNo.FALSE, 
                                  dumpXml=YesOrNo.TRUE)
                                  #dumpXml=CONF.cisco.dump_xml)
        if (local_disks.errorCode == 0):
            for l_disk in local_disks.OutConfigs.GetChild():
                disk = {}
                disk['blockSize'] = l_disk.getattr(StorageLocalDisk.BLOCK_SIZE)
                disk['connectionProtocol'] = l_disk.getattr(StorageLocalDisk.CONNECTION_PROTOCOL)
                disk['model'] = l_disk.getattr(StorageLocalDisk.MODEL)
                disk['numberOfBlocks'] = l_disk.getattr(StorageLocalDisk.NUMBER_OF_BLOCKS)
                disk['presence'] = l_disk.getattr(StorageLocalDisk.PRESENCE)
                disk['serial'] = l_disk.getattr(StorageLocalDisk.SERIAL)
                disk['size'] = l_disk.getattr(StorageLocalDisk.SIZE)
                disk['vendor'] = l_disk.getattr(StorageLocalDisk.VENDOR)
                disks['StorageLocalDisk-%s' % (l_disk.getattr(StorageLocalDisk.ID))] = disk
            pass
        pass
    except UcsException as ex:
        raise exception.IronicException("Cisco Driver: (%s)" %ex)
    return disks
pass


def get_adaptor_inventory(handle, compute_node):
    """Gets the adaptor inventory of the passed computenode

    :param handle: Active UCS Manager handle
    :param compute_node: Compute node MO object 
    :returns: Compute node adaptor inventory
    :raises: UcsException if driver failes to get inventory.
    """
    in_filter = FilterFilter()
    wcard_filter = WcardFilter()
    wcard_filter.Class = "adaptorUnit"
    wcard_filter.Property = "dn"
    wcard_filter.Value = "%s/" % compute_node.Dn
    in_filter.AddChild(wcard_filter)

    units = {}
    try:
        adaptor_units = handle.ConfigResolveClass(
                            AdaptorUnit.ClassId(),
                            in_filter,
                            inHierarchical=YesOrNo.FALSE,
                            dumpXml=YesOrNo.TRUE
                            #dumpXml=CONF.cisco.dump_xml
                            )
        if (adaptor_units.errorCode == 0):
            for a_unit in adaptor_units.OutConfigs.GetChild():
                unit = {}
                unit['baseMac'] = a_unit.getattr(AdaptorUnit.BASE_MAC)
                unit['model'] = a_unit.getattr(AdaptorUnit.MODEL)
                unit['partNumber'] = a_unit.getattr(AdaptorUnit.PART_NUMBER)
                unit['serial'] = a_unit.getattr(AdaptorUnit.SERIAL)
                unit['vendor'] = a_unit.getattr(AdaptorUnit.VENDOR)
                units['AdaptorUnit-%s' % (a_unit.getattr(AdaptorUnit.ID))] = unit
            pass
        pass
    except UcsException as ex:
        raise exception.IronicException("Cisco Driver: (%s)" %ex)
    
    return units
pass


class CiscoIronicDriverHelper(object):
    """ Cisco UCS Ironic driver helper."""

    def __init__(self, hostname=None, username=None, password=None):
        """ Initialize with UCS Manager details.

        :param hostname: UCS Manager hostname or ipaddress
        :param username: Username to login to UCS Manager.
        :param password: Login user password.
        """

        self.hostname = hostname
        self.username = username
        self.password = password
        self.service_profile = None
        self.handles = {}

    def _parse_driver_info(self, task):
        """Parses and creates Cisco driver info
    
        :param node: An Ironic node object.
        :returns: Cisco driver info.
        :raises: InvalidParameterValue if any required parameters are missing.
        """

        info = task.node.driver_info or {}
        self.hostname = info.get('hostname')
        self.username = info.get('username')
        self.password = info.get('password')
        self.service_profile = info.get('service_profile')
        self.uuid = task.node.uuid

        if not self.hostname:
            raise exception.InvalidParameterValue(_(
                "Cisco driver requires hostname be set"))

        if not self.username or not self.password:
            raise exception.InvalidParameterValue(_(
                "Cisco driver requires both username and password be set"))

        if not self.service_profile:
            raise exception.InvalidParameterValue(_(
                "Cisco driver requires service_profile be set"))

    def connect_ucsm(self, task):
        """Creates the UcsHandle

            :param task: Ironic task,
                   which contain: 'hostname', 'username', 'password' parameters
            :returns: UcsHandle with active session
            :raises: IronicException in case of failure.
        """
  
        self._parse_driver_info(task)

        ucs_handle = UcsHandle()
        try:
            ucs_login = ucs_handle.Login(
                            self.hostname, 
                            self.username, 
                            self.password 
                            )
            self.handles[self.hostname] = ucs_handle
        except UcsException as e:
            # Raise an Ironic exception. Include the description 
            # of original exception.
            LOG.error("Cisco client exception %(msg)s" % (e.message))
            raise exception.TemporaryFailure("Cisco client exception %(msg)s" 
                      % (e.message))

        return self.handles[self.hostname]

    def logout(self):
        """Logouts the current active session. """
        self.handles[self.hostname].Logout()

    def get_managed_object(self, managed_object, in_filter):
        """ Get the specified MO from UCS Manager.

        :param managed_object: MO classid 
               in_filter: input filter value
        :returns: Managed Object 
        :raises: UcsException in case of failure.
        """
    
        handle = self.handles[self.hostname]

        try: 
            managed_object = handle.GetManagedObject(
                                 None,  
                                 managed_object, 
                                 inFilter = in_filter,
                                 inHierarchincal = in_hierarchical)
            if not managed_object:
                LOG("No Managed Objects found")
        except UcsException as e:
            raise exception.IronicException("Cisco client exception %(msg)" %
                      (e.message))

         
    def get_lsboot_def(self, ucs_handle, compute):
	""" Get the boot definition.
        :param ucs_handle: Active UCS handle.
        :returns: lsbootDef Managed Object
        :raises: UcsException in case of failure
        """

        in_filter = FilterFilter()
        wcard_filter = WcardFilter()
        wcard_filter.Class = "lsbootDef"
        wcard_filter.Property = "dn" 
        wcard_filter.Value = "%s/"%compute.Dn
        in_filter.AddChild(wcard_filter)
        try: 
            lsboot_def = ucs_handle.ConfigResolveClass(
                             LsbootDef.ClassId(), 
                             in_filter, 
                             inHierarchical=YesOrNo.FALSE, 
                             #dumpXml = CONF.cisco.dump_xml
                             dumpXml = YesOrNo.TRUE
                             )
            return lsboot_def
        except UcsException as ex:
            raise exception.IronicException("Cisco driver: %s" % ex)
    pass

    def get_server_local_storage(self, compute):
        """ Get the lsbootLan of specific compute node
        :param compute_blade: compute blade managed object
        :returns: total local storage associated with this server
        :raises: UcsException in case of failure
        """
        LOG.error("In get_server_local_storage")
        in_filter = FilterFilter()
        wcard_filter = WcardFilter()
        wcard_filter.Class = "storageLocalDisk"
        wcard_filter.Property = "dn"
        wcard_filter.Value = "%s/"%compute.getattr(ComputeBlade.DN)
        in_filter.AddChild(wcard_filter)
        handle = self.handles[self.hostname]
        local_gb = 0
        try:
            disks = handle.ConfigResolveClass(
                        StorageLocalDisk.ClassId(),
                        in_filter,
                        inHierarchical=YesOrNo.FALSE,
                        #dumpXml = CONF.cisco.dump_xml
                        dumpXml = YesOrNo.TRUE
                        )
            if disks.errorCode == 0:
                for local_disk in disks.OutConfigs.GetChild():
                    if local_disk.getattr(StorageLocalDisk.SIZE) != StorageLocalDisk.CONST_BLOCK_SIZE_UNKNOWN:
                        local_gb += int(local_disk.getattr(StorageLocalDisk.SIZE))
                    LOG.error('Disk:%s size:%s' % (local_disk.getattr(StorageLocalDisk.DN), local_disk.getattr(StorageLocalDisk.SIZE)))
                
        except UcsException as ex:
            raise exception.IronicException("Cisco driver: %s" % ex)
        if local_gb != 0:
            local_gb /= 1024 
        LOG.error('Total disk: %d' % local_gb)
        return local_gb

    def get_lsboot_lan(self, lsboot_def):
        """ Get the lsbootLan of specific compute node
        :param lsboot_def: lsboot_def MO
        :returns: lsbootDef Managed Object
        :raises: UcsException in case of failure
        """

        in_filter = FilterFilter()
        wcard_filter = WcardFilter()
        wcard_filter.Class = "lsbootLan"
        wcard_filter.Property = "dn"
        wcard_filter.Value = "%s/"%lsboot_def.getattr(LsbootDef.DN)
        in_filter.AddChild(wcard_filter)
        handle = self.handles[self.hostname]
        try:
            lsboot_lan  = handle.ConfigResolveClass(
                              LsbootLan.ClassId(), 
                              in_filter, 
                              inHierarchical=YesOrNo.TRUE, 
                              #dumpXml = CONF.cisco.dump_xml
                              dumpXml = YesOrNo.TRUE
                              )
            if (lsboot_lan.errorCode == 0):
                return lsboot_lan.OutConfigs.GetChild()
            else:
                LOG.debug('Failed to get lsbootLan')
        except UcsException as ex:
            raise exception.IronicExceptoin("Cisco driver: %s" % ex)
    pass

    #
    def get_vnic_ether(self, vnic_name, ls_server):
        """ Get the boot definition.
        :param vnic_name: vNIC name of service-profile
        :param ls_server: service-profile MO
        :returns: vNIC Managed Object
        :raises: UcsException in case of failure
        """

        in_filter = FilterFilter()

        and_filter0 = AndFilter()

        wcard_filter = WcardFilter()
        wcard_filter.Class = VnicEther.ClassId()
        wcard_filter.Property = "dn"
        wcard_filter.Value = "%s/"%ls_server.Dn
        and_filter0.AddChild(wcard_filter)

        eq_filter = EqFilter()
        eq_filter.Class = VnicEther.ClassId()
        eq_filter.Property = "name"
        eq_filter.Value = vnic_name
        and_filter0.AddChild(eq_filter)

        in_filter.AddChild(and_filter0)
        handle = self.handles[self.hostname]
        try:
            vnic_ether = handle.ConfigResolveClass(
                             VnicEther.ClassId(), 
                             in_filter, 
                             inHierarchical=YesOrNo.TRUE, 
                             dumpXml = YesOrNo.TRUE
                             #dumpXml = CONF.cisco.dump_xml
                             )

            if (vnic_ether.errorCode == 0):
                return vnic_ether.OutConfigs.GetChild()
        except UcsException:
            raise exception.IronicExceptoin("Cisco driver: %s" % ex)
    pass

    def update_ironic_db(self, mac, ls_server, compute_blade):
        """ Enroll nodes into Ironic DB
        :param mac: MAC address of the node being enrolled
        :param ls_server: service-profile MO
        """

        LOG.debug("Adding new node")
        # Check if any port is already registered in Ironic.
        dbapi = db_api.get_instance()
        for address in mac:
            try:
                port = dbapi.get_port_by_address(address.lower())
                LOG.debug("Address already in use.")
                LOG.debug('Port is already in use, skip adding nodes.')
                return
            except exception.PortNotFound as ex:
                LOG.debug("Port was not found")
            LOG.debug("Adding Port:"+ address.lower())
        pass

        if len(mac) == 1 and mac[0] == 'derived':
            return

        rn_array = [
            ls_server.getattr(LsServer.DN),
            ManagedObject(NamingId.LS_POWER).MakeRn()
            ]

        power_state = None
        try:
            ls_power = self.handles[self.hostname].GetManagedObject(
                           None, LsPower.ClassId(),
                           {LsPower.DN: UcsUtils.MakeDn(rn_array)},
                           inHierarchical=YesOrNo.FALSE,
                           #dumpXml=CONF.cisco.dump_xml
                           dumpXml=YesOrNo.TRUE
                           )
            if not ls_power:
                power_state = states.ERROR
                raise exception.IronicException("Failed to get power MO, configure valid service-profile.")
            else:
                LOG.error("PowerState:%s" % (ls_power[0].getattr(LsPower.STATE)))
                if ls_power[0].getattr(LsPower.STATE) == None:
                    power_state = states.ERROR
                if ls_power[0].getattr(LsPower.STATE) == LsPower.CONST_STATE_DOWN:
                    power_state = states.POWER_OFF
                elif ls_power[0].getattr(LsPower.STATE) == LsPower.CONST_STATE_UP:
                    power_state = states.POWER_ON
        except UcsException as ex:
            LOG.error(_("Cisco client exception: %(msg)s for node %(uuid)s"),
                      {'msg': ex, 'uuid': task.node.uuid})
            raise exception.IronicException("Cisco client exception: %s" % ex)

        # Create new ironic node 
        node = {'driver': 'pxe_cisco',
                'driver_info': {'service_profile': ls_server.getattr(LsServer.DN),
                                'hostname': self.hostname,
                                'username': self.username,
                                'password': self.password},
                'power_state': power_state,
                'properties': {'memory_mb': compute_blade.getattr(ComputeBlade.TOTAL_MEMORY),
                               'cpus': compute_blade.getattr(ComputeBlade.NUM_OF_CPUS),
                               'cpu_arch': 'x86_64',
                               'local_gb': self.get_server_local_storage(compute_blade)}
               }
        db_node = dbapi.create_node(node).as_dict()
        
        LOG.debug("Node Instance uuid:%s, db_power_state:%s power_state:%s" %(db_node['uuid'], db_node['power_state'], power_state))

        # Create ports 
        for address in mac:
            port = {
                'address': address.lower(),
                'node_id': db_node['id']
                }
            LOG.debug("enrolling port: %s" % address.lower())
            db_port = dbapi.create_port(port).as_dict()
            LOG.debug("after create_port")
        pass
       
        LOG.debug('Enrolled node')
        LOG.debug('2Enrolled node')

    def get_node_info(self, lsboot_def, ls_server, compute_blade):
        """ Enroll nodes into Ironic DB
        :param lsboot_def: boot definition MO of service-profile
        :param ls_server: service-profile MO
        :returns None: 
        :raises : IronicException in case of failure
        """

        try:
            # lsbootDef contains only one LsbootLan Mo
            boot_lan = self.get_lsboot_lan(lsboot_def)
            mac = []
            for lsboot_lan in boot_lan:
                if ((lsboot_lan != 0)
                    and (isinstance(lsboot_lan, ManagedObject) == True)
                    and (lsboot_lan.classId == "LsbootLan")):

                    for image_path in lsboot_lan.GetChild():
                        if ((image_path != 0)):
                            vnic_ether = self.get_vnic_ether(
                                             image_path.getattr("VnicName"),
                                             ls_server
                                             )
                            if (vnic_ether != 0):
                                LOG.debug("MAC" + vnic_ether[0].getattr(VnicEther.ADDR))
                                mac.insert(
                                    int(vnic_ether[0].getattr(VnicEther.OPER_ORDER))-1,
                                    vnic_ether[0].getattr(VnicEther.ADDR)
                                    )

            if len(mac) > 0:
                LOG.debug('node has ' + str(len(mac)) + 'nics' + ' '.join(mac))
                self.update_ironic_db(mac, ls_server, compute_blade)
            pass
        except UcsException as ex:
            raise UcsException("Cisco driver: %s" % ex)
    pass

    def enroll_nodes(self):
        """ Enroll nodes to ironic DB """

        handle = self.handles[self.hostname]
        try:
            ls_servers = handle.GetManagedObject(
                             None,
                             LsServer.ClassId(),
                             None,
                             #dumpXml = CONF.cisco.dump_xml
                             dumpXml = YesOrNo.TRUE
                             )
            for ls_server in ls_servers:
                LOG.debug('Adding/Updating server - ' + 
                    ls_server.getattr(LsServer.DN))
                LOG.debug('In addUcsServer')
                if 'blade' in ls_server.getattr(LsServer.PN_DN):
                    in_filter = FilterFilter()
                    eq_filter = EqFilter()
                    eq_filter.Class = "computeBlade"
                    eq_filter.Property = "assignedToDn"
                    eq_filter.Value = ls_server.getattr(LsServer.DN)
                    in_filter.AddChild(eq_filter)
                    compute_blades = handle.ConfigResolveClass(
                                         ComputeBlade.ClassId(), 
                                         in_filter, 
                                         inHierarchical=YesOrNo.FALSE, 
                                         dumpXml = YesOrNo.TRUE
                                         #dumpXml = CONF.cisco.dump_xml
                                         )
                    if (compute_blades.errorCode == 0):
                        # for each computeBladeMo, get the lsbootDef Info.
                        for blade in compute_blades.OutConfigs.GetChild():
                            lsboot_def = self.get_lsboot_def(handle, blade)
                            for boot_def in lsboot_def.OutConfigs.GetChild():
                                # only one LsbootDef will be present, 
                                # break once got that info.
                                self.get_node_info(boot_def, ls_server, blade)
                            pass
                        pass
                    pass
                elif 'rack' in ls_server.getattr(LsServer.PN_DN):
                    in_filter = FilterFilter()
                    eq_filter = EqFilter()
                    eq_filter.Class = "computeRackUnit"
                    eq_filter.Property = "assignedToDn"
                    eq_filter.Value = ls_server.getattr(LsServer.DN)
                    in_filter.AddChild(eq_filter)
                    compute_rus = handle.ConfigResolveClass(
                                         ComputeRackUnit.ClassId(), 
                                         in_filter, 
                                         inHierarchical=YesOrNo.FALSE, 
                                         dumpXml = YesOrNo.TRUE
                                         )
                    if (compute_rus.errorCode == 0):
                        # for each computeRackUnitMo, get the lsbootDef Info.
                        for rack_unit in compute_rus.OutConfigs.GetChild():
                            lsboot_def = self.get_lsboot_def(handle, rack_unit)
                            for boot_def in lsboot_def.OutConfigs.GetChild():
                                # only one LsbootDef will be present, 
                                # break once got that info.
                                self.get_node_info(boot_def, ls_server, rack_unit)
                            pass
                        pass
                    pass
                pass
            pass
        except UcsException as ex:
            raise exception.IronicException("Cisco driver: %s" % ex)
    pass
    
    def _get_power_state(self, task):
        """Get current power state of this node

        :param node: Ironic node one of :class:`ironic.db.models.Node`
        :raises: InvalidParameterValue if required Ucs parameters are
            missing.
        :raises: ServiceUnavailable on an error from Ucs.
        :returns: Power state of the given node
        """
        handle = self.handles[self.hostname]
        rn_array = [
            self.service_profile,
            ManagedObject(NamingId.LS_POWER).MakeRn()
            ]
        power_status = states.ERROR
        # LOG.error(_("Cisco driver: dump_xml:%(dump_xml)s"), {'dump_xml':CONF.cisco.dump_xml})
        try:
            ls_power = handle.GetManagedObject(
                           None, LsPower.ClassId(), 
                           {LsPower.DN: UcsUtils.MakeDn(rn_array)},
                           inHierarchical=YesOrNo.FALSE,
                           dumpXml=YesOrNo.TRUE
                           #dumpXml=CONF.cisco.dump_xml
                           )
            if not ls_power:
                power_status = states.ERROR
                raise exception.IronicException("Failed to get power MO, configure valid service-profile.") 
            else:
                if ls_power[0].getattr(LsPower.STATE) == None:
                    power_status = states.ERROR
                if ls_power[0].getattr(LsPower.STATE) == LsPower.CONST_STATE_DOWN:
                    power_status = states.POWER_OFF
                elif ls_power[0].getattr(LsPower.STATE) == LsPower.CONST_STATE_UP:
                    power_status = states.POWER_ON

            return power_status
        except UcsException as ex:
            LOG.error(_("Cisco client exception: %(msg)s for node %(uuid)s"),
                      {'msg': ex, 'uuid': task.node.uuid})
            raise exception.IronicException("Cisco client exception: %s" % ex)

    def _set_power_state(self, task, desired_state):
        """Set power state of this node

        :param node: Ironic node one of :class:`ironic.db.models.Node`
        :raises: InvalidParameterValue if required seamicro parameters are
            missing.
        :raises: ServiceUnavailable on an error from UcsHandle Client.
        :returns: Power state of the given node
        """

        handle = self.handles[self.hostname]
        rn_array = [
            self.service_profile, 
            ManagedObject(NamingId.LS_POWER).MakeRn()
            ]
        power_status = states.ERROR
        try:
            ls_power = handle.GetManagedObject(
                           None, 
                           LsPower.ClassId(), 
                           {LsPower.DN: UcsUtils.MakeDn(rn_array)},
                           inHierarchical=YesOrNo.FALSE,
                           dumpXml=YesOrNo.TRUE
                           #dumpXml=CONF.cisco.dump_xml
                           )
            if not ls_power:
                power_status = states.ERROR
                raise exception.IronicException("Failed to get power MO, configure valid service-profile.")
            else:
                ls_power_set = handle.SetManagedObject(
                                   ls_power, 
                                   LsPower.ClassId(),
                                   {LsPower.STATE: desired_state},
                                   dumpXml=YesOrNo.TRUE
                                   #dumpXml=CONF.cisco.dump_xml
                                   )
                if ls_power_set:
                    # There will be one one instance of LsPower
                    for power in ls_power_set:
                        power_status = power.getattr(LsPower.STATE)
                    pass
                pass
            pass

            return power_status
        except Exception,ex:
            LOG.error(_("Cisco client exception: %(msg)s for node %(uuid)s"),
                      {'msg': ex, 'uuid': task.node.uuid})
            self.logout()
            raise exception.IronicException("%s" % ex)

    def set_power_status(self, task, desired_state):
        """Set power state of this node

        :param node: Ironic node one of :class:`ironic.db.models.Node`
        :raises: InvalidParameterValue if required seamicro parameters are
            missing.
        :raises: ServiceUnavailable on an error from UcsHandle Client.
        :returns: Power state of the given node
        """
        try:
            power_status = self._get_power_state(task)
            if power_status is not desired_state:
                #pdesired_state = states.ERROR
                if desired_state == states.POWER_OFF:
                    pdesired_state = LsPower.CONST_STATE_DOWN
                elif desired_state == states.POWER_ON:
                    pdesired_state = LsPower.CONST_STATE_UP
                elif desired_state == states.REBOOT:
                    pdesired_state = LsPower.CONST_STATE_HARD_RESET_IMMEDIATE
                pass
                power_status = self._set_power_state(task, pdesired_state)
            pass
            updated_status = states.ERROR
            if power_status == LsPower.CONST_STATE_UP:
                updated_status = states.POWER_ON
            elif power_status == LsPower.CONST_STATE_DOWN:
                updated_status = states.POWER_OFF
            pass
            return updated_status

        except exception.IronicException,ex:
            LOG.error(_("Cisco client exception %(msg)s for node %(uuid)s"),
                      {'msg': ex, 'uuid': task.node.uuid})
            self.logout()
            raise exception.IronicException("%s" % ex)

    def _reboot(self, task, timeout=None):
        """Reboot this node
        :param node: Ironic node one of :class:`ironic.db.models.Node`
        :param timeout: Time in seconds to wait till reboot is compelete
        :raises: InvalidParameterValue if required seamicro parameters are
            missing.
        :returns: Power state of the given node
        """
        if timeout is None:
            timeout = CONF.cisco.action_timeout
        state = [None]
        retries = 0

        def _wait_for_reboot(state, retries):
            """Called at an interval until the node is rebooted successfully."""
            state[0] = self._get_power_state(task)
            if state[0] == states.POWER_ON:
                LOG.error("In _reboot %d %s" % (retries, state[0]))
                raise loopingcall.LoopingCallDone()

            if retries > CONF.cisco.max_retry:
                state[0] = states.ERROR
                LOG.error("In _reboot %d %s" % (retries, state[0]))
                raise loopingcall.LoopingCallDone()

            retries += 1
            #state = self._set_power_state(task, LsPower.CONST_STATE_UP)
        pass

        timer = loopingcall.FixedIntervalLoopingCall(_wait_for_reboot,
                                                     state, retries)
        p_state = self._get_power_state(task)
        LOG.error("p_state:%s" %(p_state))
        if p_state == states.POWER_OFF:
            self._set_power_state(task, LsPower.CONST_STATE_UP)
        else:
            self._set_power_state(task, LsPower.CONST_STATE_HARD_RESET_IMMEDIATE)
        timer.start(interval=timeout).wait()
        LOG.error("state: %s" % state[0])
        return state[0]


    def get_faults(self, task):

        handle = self.connect_ucsm(task)
        params = {'server' : self.service_profile, 'faults' : {}}

        # Need to get the server dn first.
        ls_server  = handle.GetManagedObject(
                         None, 
                         LsServer.ClassId(),
                         {LsServer.DN: self.service_profile},
                         #dumpXml=CONF.cisco.dump_xml
                         dumpXml=YesOrNo.TRUE
                         )
        # There will be only one service-profile matches the given DN.
        if ls_server and len(ls_server) == 1:
            # create wcard filter.
            in_filter = FilterFilter()
            wcard_filter = WcardFilter()
            wcard_filter.Class = FaultInst.ClassId()
            wcard_filter.Property = "dn"
            wcard_filter.Value = ls_server[0].getattr(LsServer.PN_DN)
            in_filter.AddChild(wcard_filter)

            fault_insts = handle.ConfigResolveClass(
                          FaultInst.ClassId(),
                          in_filter,
                          dumpXml=YesOrNo.TRUE
                          #dumpXml=CONF.cisco.dump_xml
                          )
            if fault_insts:
                for fault_inst in fault_insts.OutConfigs.GetChild():
                    fault_details = {
                        FaultInst.CHANGE_SET: fault_inst.getattr(FaultInst.CHANGE_SET),
                        FaultInst.DESCR : fault_inst.getattr(FaultInst.DESCR),
                        FaultInst.LAST_TRANSITION: fault_inst.getattr(FaultInst.LAST_TRANSITION),
                        FaultInst.RN: fault_inst.getattr(FaultInst.RN),
                        FaultInst.TYPE: fault_inst.getattr(FaultInst.TYPE),
                        FaultInst.SEVERITY: fault_inst.getattr(FaultInst.SEVERITY),
                        FaultInst.TAGS: fault_inst.getattr(FaultInst.TAGS),
                        FaultInst.CAUSE: fault_inst.getattr(FaultInst.CAUSE),
                        FaultInst.STATUS: fault_inst.getattr(FaultInst.STATUS),
                        FaultInst.CREATED: fault_inst.getattr(FaultInst.CREATED),
                        FaultInst.ACK: fault_inst.getattr(FaultInst.ACK),
                        FaultInst.RULE: fault_inst.getattr(FaultInst.RULE),
                        FaultInst.ORIG_SEVERITY: fault_inst.getattr(FaultInst.ORIG_SEVERITY),
                        FaultInst.PREV_SEVERITY: fault_inst.getattr(FaultInst.PREV_SEVERITY),
                        FaultInst.CODE: fault_inst.getattr(FaultInst.CODE),
                        FaultInst.HIGHEST_SEVERITY: fault_inst.getattr(FaultInst.HIGHEST_SEVERITY),
                        FaultInst.ID: fault_inst.getattr(FaultInst.ID),
                        FaultInst.OCCUR: fault_inst.getattr(FaultInst.OCCUR)
                        }
                    params['faults'][fault_inst.getattr(FaultInst.DN)]  = fault_details
                pass
            pass
        pass

        return params
    def get_temperature_stats(self, task):

        LOG.debug("In get_temperature_stats")
        handle = self.connect_ucsm(task)
        params = {'server': self.service_profile}

        ls_server  = handle.GetManagedObject(
                         None, 
                         LsServer.ClassId(),
                         {LsServer.DN: self.service_profile},
                         inHierarchical=YesOrNo.FALSE,
                         dumpXml=YesOrNo.TRUE
                         #dumpXml=CONF.cisco.dump_xml
                         )
        # There will be only one service-profile matches the given DN.
        if ls_server and len(ls_server) == 1:
            if 'blade' in ls_server[0].getattr(LsServer.PN_DN):
                #make ComputeMbTempStats Mo dn.
                mb_temp_stats = handle.GetManagedObject(
                                None,
                                ComputeMbTempStats.ClassId(),
                                {ComputeMbTempStats.DN: ls_server[0].getattr(LsServer.PN_DN) + '/board/temp-stats'}, 
                                inHierarchical=YesOrNo.FALSE,
                                dumpXml=YesOrNo.TRUE
                                #dumpXml=CONF.cisco.dump_xml
                                )
                if mb_temp_stats and len(mb_temp_stats) == 1 :
                    temp_stats = {
                             ComputeMbTempStats.DN: mb_temp_stats[0].getattr(ComputeMbTempStats.DN),
                             ComputeMbTempStats.FM_TEMP_SEN_IO: mb_temp_stats[0].getattr(ComputeMbTempStats.FM_TEMP_SEN_IO),
                             ComputeMbTempStats.FM_TEMP_SEN_IO_AVG: mb_temp_stats[0].getattr(ComputeMbTempStats.FM_TEMP_SEN_IO_AVG),
                             ComputeMbTempStats.FM_TEMP_SEN_IO_MAX: mb_temp_stats[0].getattr(ComputeMbTempStats.FM_TEMP_SEN_IO_MAX),
                             ComputeMbTempStats.FM_TEMP_SEN_IO_MIN: mb_temp_stats[0].getattr(ComputeMbTempStats.FM_TEMP_SEN_IO_MIN),
                             ComputeMbTempStats.FM_TEMP_SEN_REAR: mb_temp_stats[0].getattr(ComputeMbTempStats.FM_TEMP_SEN_REAR),
                             ComputeMbTempStats.FM_TEMP_SEN_REAR_AVG: mb_temp_stats[0].getattr(ComputeMbTempStats.FM_TEMP_SEN_REAR_AVG),
                             ComputeMbTempStats.FM_TEMP_SEN_REAR_L: mb_temp_stats[0].getattr(ComputeMbTempStats.FM_TEMP_SEN_REAR_L),
                             ComputeMbTempStats.FM_TEMP_SEN_REAR_LAVG: mb_temp_stats[0].getattr(ComputeMbTempStats.FM_TEMP_SEN_REAR_LAVG),
                             ComputeMbTempStats.FM_TEMP_SEN_REAR_LMAX: mb_temp_stats[0].getattr(ComputeMbTempStats.FM_TEMP_SEN_REAR_LMAX),
                             ComputeMbTempStats.FM_TEMP_SEN_REAR_LMIN: mb_temp_stats[0].getattr(ComputeMbTempStats.FM_TEMP_SEN_REAR_LMIN),
                             ComputeMbTempStats.FM_TEMP_SEN_REAR_MAX: mb_temp_stats[0].getattr(ComputeMbTempStats.FM_TEMP_SEN_REAR_MAX),
                             ComputeMbTempStats.FM_TEMP_SEN_REAR_MIN: mb_temp_stats[0].getattr(ComputeMbTempStats.FM_TEMP_SEN_REAR_MIN),
                             ComputeMbTempStats.FM_TEMP_SEN_REAR_R: mb_temp_stats[0].getattr(ComputeMbTempStats.FM_TEMP_SEN_REAR_R),
                             ComputeMbTempStats.FM_TEMP_SEN_REAR_RAVG: mb_temp_stats[0].getattr(ComputeMbTempStats.FM_TEMP_SEN_REAR_RAVG),
                             ComputeMbTempStats.FM_TEMP_SEN_REAR_RMAX: mb_temp_stats[0].getattr(ComputeMbTempStats.FM_TEMP_SEN_REAR_RMAX),
                             ComputeMbTempStats.FM_TEMP_SEN_REAR_RMIN: mb_temp_stats[0].getattr(ComputeMbTempStats.FM_TEMP_SEN_REAR_RMIN),
                             ComputeMbTempStats.SUSPECT: mb_temp_stats[0].getattr(ComputeMbTempStats.SUSPECT),
                             ComputeMbTempStats.THRESHOLDED: mb_temp_stats[0].getattr(ComputeMbTempStats.THRESHOLDED),
                             ComputeMbTempStats.TIME_COLLECTED: mb_temp_stats[0].getattr(ComputeMbTempStats.TIME_COLLECTED)
                             }
                    params['temp_stats'] = temp_stats
            elif 'rack' in ls_server[0].getattr(LsServer.PN_DN):
                mb_temp_stats = handle.GetManagedObject(
                                    None,
                                    ComputeRackUnitMbTempStats.ClassId(),
                                    {ComputeRackUnitMbTempStats.DN: ls_server[0].getattr(LsServer.PN_DN) + '/board/temp-stats'}, 
                                    inHierarchical=YesOrNo.FALSE,
                                    dumpXml=YesOrNo.TRUE
                                    )
                if mb_temp_stats and len(mb_temp_stats) == 1 :
                    temp_stats = {
                             ComputeRackUnitMbTempStats.DN: mb_temp_stats[0].getattr(ComputeRackUnitMbTempStats.DN),
                             ComputeRackUnitMbTempStats.AMBIENT_TEMP: mb_temp_stats[0].getattr(ComputeRackUnitMbTempStats.AMBIENT_TEMP),
                             ComputeRackUnitMbTempStats.AMBIENT_TEMP_AVG: mb_temp_stats[0].getattr(ComputeRackUnitMbTempStats.AMBIENT_TEMP_AVG),
                             ComputeRackUnitMbTempStats.AMBIENT_TEMP_MAX: mb_temp_stats[0].getattr(ComputeRackUnitMbTempStats.AMBIENT_TEMP_MAX),
                             ComputeRackUnitMbTempStats.AMBIENT_TEMP_MIN: mb_temp_stats[0].getattr(ComputeRackUnitMbTempStats.AMBIENT_TEMP_MIN),
                             ComputeRackUnitMbTempStats.FRONT_TEMP: mb_temp_stats[0].getattr(ComputeRackUnitMbTempStats.FRONT_TEMP),
                             ComputeRackUnitMbTempStats.FRONT_TEMP_AVG: mb_temp_stats[0].getattr(ComputeRackUnitMbTempStats.FRONT_TEMP_AVG),
                             ComputeRackUnitMbTempStats.FRONT_TEMP_MAX: mb_temp_stats[0].getattr(ComputeRackUnitMbTempStats.FRONT_TEMP_MAX),
                             ComputeRackUnitMbTempStats.FRONT_TEMP_MIN: mb_temp_stats[0].getattr(ComputeRackUnitMbTempStats.FRONT_TEMP_MIN),
                             ComputeRackUnitMbTempStats.INTERVALS: mb_temp_stats[0].getattr(ComputeRackUnitMbTempStats.INTERVALS),
                             ComputeRackUnitMbTempStats.IOH1_TEMP: mb_temp_stats[0].getattr(ComputeRackUnitMbTempStats.IOH1_TEMP),
                             ComputeRackUnitMbTempStats.IOH1_TEMP_AVG: mb_temp_stats[0].getattr(ComputeRackUnitMbTempStats.IOH1_TEMP_AVG),
                             ComputeRackUnitMbTempStats.IOH1_TEMP_MAX: mb_temp_stats[0].getattr(ComputeRackUnitMbTempStats.IOH1_TEMP_MAX),
                             ComputeRackUnitMbTempStats.IOH1_TEMP_MIN: mb_temp_stats[0].getattr(ComputeRackUnitMbTempStats.IOH1_TEMP_MIN),
                             ComputeRackUnitMbTempStats.IOH2_TEMP: mb_temp_stats[0].getattr(ComputeRackUnitMbTempStats.IOH2_TEMP),
                             ComputeRackUnitMbTempStats.IOH2_TEMP_AVG: mb_temp_stats[0].getattr(ComputeRackUnitMbTempStats.IOH2_TEMP_AVG),
                             ComputeRackUnitMbTempStats.IOH2_TEMP_MAX: mb_temp_stats[0].getattr(ComputeRackUnitMbTempStats.IOH2_TEMP_MAX),
                             ComputeRackUnitMbTempStats.IOH2_TEMP_MIN: mb_temp_stats[0].getattr(ComputeRackUnitMbTempStats.IOH2_TEMP_MIN),
                             ComputeRackUnitMbTempStats.REAR_TEMP: mb_temp_stats[0].getattr(ComputeRackUnitMbTempStats.REAR_TEMP),
                             ComputeRackUnitMbTempStats.REAR_TEMP_AVG: mb_temp_stats[0].getattr(ComputeRackUnitMbTempStats.REAR_TEMP_AVG),
                             ComputeRackUnitMbTempStats.REAR_TEMP_MAX: mb_temp_stats[0].getattr(ComputeRackUnitMbTempStats.REAR_TEMP_MAX),
                             ComputeRackUnitMbTempStats.REAR_TEMP_MIN: mb_temp_stats[0].getattr(ComputeRackUnitMbTempStats.REAR_TEMP_MIN),
                             ComputeRackUnitMbTempStats.SUSPECT: mb_temp_stats[0].getattr(ComputeRackUnitMbTempStats.SUSPECT),
                             ComputeRackUnitMbTempStats.THRESHOLDED: mb_temp_stats[0].getattr(ComputeRackUnitMbTempStats.THRESHOLDED),
                             ComputeRackUnitMbTempStats.TIME_COLLECTED: mb_temp_stats[0].getattr(ComputeRackUnitMbTempStats.TIME_COLLECTED)
                             }
                    params['temperature_stats'] = temp_stats
            pass 
        return params

    def get_power_stats(self, task):

        LOG.debug("In _get_power_stats")
        handle = self.connect_ucsm(task)
        params = {'server': self.service_profile}

        ls_server  = handle.GetManagedObject(
                         None,
                         LsServer.ClassId(),
                         {LsServer.DN: self.service_profile},
                         dumpXml=YesOrNo.TRUE
                         #dumpXml=CONF.cisco.dump_xml
                         )
        # There will be only one service-profile matches the given DN.
        if ls_server and len(ls_server) == 1:
            #make ComputeMbTempStats Mo dn.
            mb_power_stats = handle.GetManagedObject(
                                 None,
                                 ComputeMbPowerStats.ClassId(),
                                 {ComputeMbPowerStats.DN: ls_server[0].getattr(LsServer.PN_DN) + '/board/power-stats'}, 
                                 dumpXml=YesOrNo.TRUE
                                 #dumpXml=CONF.cisco.dump_xml
                                 )
            if mb_power_stats and len(mb_power_stats) == 1 :
                power_stats = {
                               str(ComputeMbPowerStats.DN): mb_power_stats[0].getattr(ComputeMbPowerStats.DN),
                               str(ComputeMbPowerStats.CONSUMED_POWER): mb_power_stats[0].getattr(ComputeMbPowerStats.CONSUMED_POWER),
                               str(ComputeMbPowerStats.CONSUMED_POWER_AVG): mb_power_stats[0].getattr(ComputeMbPowerStats.CONSUMED_POWER_AVG),
                               str(ComputeMbPowerStats.CONSUMED_POWER_MAX): mb_power_stats[0].getattr(ComputeMbPowerStats.CONSUMED_POWER_MAX),
                               str(ComputeMbPowerStats.CONSUMED_POWER_MIN): mb_power_stats[0].getattr(ComputeMbPowerStats.CONSUMED_POWER_MIN),
                               str(ComputeMbPowerStats.INPUT_CURRENT): mb_power_stats[0].getattr(ComputeMbPowerStats.INPUT_CURRENT),
                               str(ComputeMbPowerStats.INPUT_CURRENT_AVG): mb_power_stats[0].getattr(ComputeMbPowerStats.INPUT_CURRENT_AVG),
                               str(ComputeMbPowerStats.INPUT_CURRENT_MAX): mb_power_stats[0].getattr(ComputeMbPowerStats.INPUT_CURRENT_MAX),
                               str(ComputeMbPowerStats.INPUT_CURRENT_MIN): mb_power_stats[0].getattr(ComputeMbPowerStats.INPUT_CURRENT_MIN),
                               str(ComputeMbPowerStats.INPUT_VOLTAGE): mb_power_stats[0].getattr(ComputeMbPowerStats.INPUT_VOLTAGE),
                               str(ComputeMbPowerStats.INPUT_VOLTAGE_AVG): mb_power_stats[0].getattr(ComputeMbPowerStats.INPUT_VOLTAGE_AVG),
                               str(ComputeMbPowerStats.INPUT_VOLTAGE_MAX): mb_power_stats[0].getattr(ComputeMbPowerStats.INPUT_VOLTAGE_MAX),
                               str(ComputeMbPowerStats.INPUT_VOLTAGE_MIN): mb_power_stats[0].getattr(ComputeMbPowerStats.INPUT_VOLTAGE_MIN),
                               str(ComputeMbPowerStats.SUSPECT): mb_power_stats[0].getattr(ComputeMbPowerStats.SUSPECT),
                               str(ComputeMbPowerStats.THRESHOLDED): mb_power_stats[0].getattr(ComputeMbPowerStats.THRESHOLDED),
                               str(ComputeMbPowerStats.TIME_COLLECTED): mb_power_stats[0].getattr(ComputeMbPowerStats.TIME_COLLECTED),
                               }
                return power_stats
        return None
    def get_location(self, task):
        """Retrieve the server id."""
        
        handle = self.connect_ucsm(task)
        params = {'server' : self.service_profile, 'Location' : {}}
        # Need to get the server dn first.
        ls_server  = handle.GetManagedObject(
                         None, 
                         LsServer.ClassId(),
                         {LsServer.DN: self.service_profile},
                         dumpXml=YesOrNo.TRUE
                         #dumpXml=CONF.cisco.dump_xml
                         )
        # There will be only one service-profile matches the given DN.
        if ls_server and len(ls_server) == 1:
            location = {
                'Ucs' : self.hostname, 
                'server-id' : ls_server[0].getattr(LsServer.PN_DN)
                }
            params['Location'] =  location
        pass
        return params

    def get_firmware_version(self, task):
        LOG.error("In get_firmware_version")	
        handle = self.connect_ucsm(task)
        ls_server = handle.GetManagedObject(
                        None, None, 
                        {LsServer.DN:self.service_profile}
                        )

        params = {"server": ""}

        if ls_server:
            for server in ls_server:
                #get firmware status
                rn_array = [
                    server.getattr(LsServer.PN_DN), 
                    ManagedObject(FirmwareStatus.ClassId()).MakeRn()
                    ]
                firmware_version = handle.GetManagedObject(
                                       None,
                                       FirmwareStatus.ClassId(),
                                       {FirmwareStatus.DN:UcsUtils.MakeDn(rn_array)}
                                       )
                if firmware_version:
                    for version in firmware_version:
                       params = { 
                           FirmwareStatus.DN: version.getattr(FirmwareStatus.DN),
                           FirmwareStatus.OPER_STATE: version.getattr(FirmwareStatus.OPER_STATE),
                           FirmwareStatus.PACKAGE_VERSION: version.getattr(FirmwareStatus.PACKAGE_VERSION)
                           }
                       LOG.debug(_("UCS server firmware version: %s") % params)

        return params


    def get_inventory(self, task):
        """

        """

        handle = self.connect_ucsm(task)
        ls_server = handle.GetManagedObject(
                        None, None, 
                        {LsServer.DN:self.service_profile},
                         dumpXml=YesOrNo.TRUE
                        )

        params = {"server": ""}

        if ls_server:
            for server in ls_server:
                if 'blade' in server.getattr(LsServer.PN_DN):
                    mo_id = ComputeBlade.ClassId()
                else:
                    mo_id = ComputeRackUnit.ClassId()
               
                compute_unit = handle.GetManagedObject(
                                       None,
                                       mo_id,
                                       {ComputeBlade.DN:server.getattr(LsServer.PN_DN)},
                                       dumpXml=YesOrNo.TRUE
                                       )
                if compute_unit:
                    if mo_id is ComputeBlade.ClassId():
                        for unit in compute_unit:
                            params = { 
                                ComputeBlade.DN: unit.getattr(ComputeBlade.DN),
                                ComputeBlade.CHASSIS_ID: unit.getattr(ComputeBlade.CHASSIS_ID),
                                ComputeBlade.AVAILABLE_MEMORY: unit.getattr(ComputeBlade.AVAILABLE_MEMORY),
                                ComputeBlade.NUM_OF_ADAPTORS: unit.getattr(ComputeBlade.NUM_OF_ADAPTORS),
                                ComputeBlade.NUM_OF_CORES: unit.getattr(ComputeBlade.NUM_OF_CORES),
                                ComputeBlade.NUM_OF_CORES_ENABLED: unit.getattr(ComputeBlade.NUM_OF_CORES_ENABLED),
                                ComputeBlade.NUM_OF_CPUS: unit.getattr(ComputeBlade.NUM_OF_CPUS),
                                ComputeBlade.NUM_OF_ETH_HOST_IFS: unit.getattr(ComputeBlade.NUM_OF_ETH_HOST_IFS),
                                ComputeBlade.NUM_OF_FC_HOST_IFS: unit.getattr(ComputeBlade.NUM_OF_FC_HOST_IFS),
                                ComputeBlade.NUM_OF_THREADS: unit.getattr(ComputeBlade.NUM_OF_THREADS),
                                'ProcessorUnits': get_processor_units(handle, unit),
                                'MemoryArrays': get_memory_inventory(handle, unit),
                                'StorageUnits': get_storage_inventory(handle, unit),
                                'AdaptorUnits': get_adaptor_inventory(handle, unit)
                                }
                    elif mo_id is ComputeRackUnit.ClassId():
                        for unit in compute_unit:
                            params = { 
                                ComputeRackUnit.DN: unit.getattr(ComputeRackUnit.DN),
                                ComputeRackUnit.AVAILABLE_MEMORY: unit.getattr(ComputeRackUnit.AVAILABLE_MEMORY),
                                ComputeRackUnit.NUM_OF_ADAPTORS: unit.getattr(ComputeRackUnit.NUM_OF_ADAPTORS),
                                ComputeRackUnit.NUM_OF_CORES: unit.getattr(ComputeRackUnit.NUM_OF_CORES),
                                ComputeRackUnit.NUM_OF_CORES_ENABLED: unit.getattr(ComputeRackUnit.NUM_OF_CORES_ENABLED),
                                ComputeRackUnit.NUM_OF_CPUS: unit.getattr(ComputeRackUnit.NUM_OF_CPUS),
                                ComputeRackUnit.NUM_OF_ETH_HOST_IFS: unit.getattr(ComputeRackUnit.NUM_OF_ETH_HOST_IFS),
                                ComputeRackUnit.NUM_OF_FC_HOST_IFS: unit.getattr(ComputeRackUnit.NUM_OF_FC_HOST_IFS),
                                ComputeRackUnit.NUM_OF_THREADS: unit.getattr(ComputeRackUnit.NUM_OF_THREADS),
                                'ProcessorUnits': get_processor_units(handle, unit),
                                'MemoryArrays': get_memory_inventory(handle, unit),
                                'StorageUnits': get_storage_inventory(handle, unit),
                                'AdaptorUnits': get_adaptor_inventory(handle, unit)
                                }
                        pass
                    pass
        return params

class Power(base.PowerInterface):
    """Cisco Power Interface.

    This PowerInterface class provides a mechanism for controlling the power
    state of servers managed by Cisco UCSM.
    """

    def get_properties(self):
        return COMMON_PROPERTIES

    def validate(self, task):
        """Check that node 'driver_info' is valid.

        Check that node 'driver_info' contains the required fields.

        :param node: Single node object.
        :raises: InvalidParameterValue if required seamicro parameters are
            missing.
        """
        ucs_helper = CiscoIronicDriverHelper()
        ucs_helper._parse_driver_info(task)
        del ucs_helper

    def get_power_state(self, task):
        """Get the current power state.

        Poll the host for the current power state of the node.

        :param task: A instance of `ironic.manager.task_manager.TaskManager`.
        :param node: A single node.
        :raises: InvalidParameterValue if required seamicro parameters are
            missing.
        :raises: ServiceUnavailable on an error from SeaMicro Client.
        :returns: power state. One of :class:`ironic.common.states`.
        """
        ucs_helper = CiscoIronicDriverHelper()
        ucs_helper.connect_ucsm(task)
        power_state = ucs_helper._get_power_state(task)
        ucs_helper.logout()
        del ucs_helper
        return power_state

    @task_manager.require_exclusive_lock
    def set_power_state(self, task, pstate):
        """Turn the power on or off.

        Set the power state of a node.

        :param task: A instance of `ironic.manager.task_manager.TaskManager`.
        :param node: A single node.
        :param pstate: Either POWER_ON or POWER_OFF from :class:
            `ironic.common.states`.
        :raises: InvalidParameterValue if an invalid power state was specified.
        :raises: PowerStateFailure if the desired power state couldn't be set.
        """

        if pstate in [ states.POWER_ON, states.POWER_OFF ]:
            ucs_helper = CiscoIronicDriverHelper()
            ucs_helper.connect_ucsm(task)
            state = ucs_helper.set_power_status(task, pstate)
            ucs_helper.logout()
        else:
            raise exception.InvalidParameterValue(_(
                "set_power_state called with invalid power state."))

        if state != pstate:
            raise exception.PowerStateFailure(pstate=pstate)

    @task_manager.require_exclusive_lock
    def reboot(self, task):
        """Cycles the power to a node.

        :param task: a TaskManager instance.
        :param node: An Ironic node object.
        :raises: InvalidParameterValue if required seamicro parameters are
            missing.
        :raises: PowerStateFailure if the final state of the node is not
            POWER_ON.
        """
        ucs_helper = CiscoIronicDriverHelper()
        ucs_helper.connect_ucsm(task)
        state = ucs_helper._reboot(task)
        LOG.error("in reboot : %s" % state)
        ucs_helper.logout()

        if state != states.POWER_ON:
            raise exception.PowerStateFailure(pstate=states.POWER_ON)


class VendorPassthru(base.VendorInterface):
    """Cisco vendor-specific methods."""

    def get_properties(self):
        return COMMON_PROPERTIES

    def validate(self, task, **kwargs):
        method = kwargs['method']
        if method in VENDOR_PASSTHRU_METHODS:
            return True
        else:
            raise exception.InvalidParameterValue(_(
                "Unsupported method (%s) passed to Cisco driver.")
                % method)

    def vendor_passthru(self, task, **kwargs):
        """Dispatch vendor specific method calls."""
        method = kwargs['method']
        if method in VENDOR_PASSTHRU_METHODS:
            return getattr(self, "_" + method)(task, **kwargs)

    def driver_vendor_passthru(self, context, method, **kwargs):
        """ pxe_ucsm driver level vedor_passthru. """

        if method in DRIVER_VENDOR_PASSTHRU_METHODS:
            return getattr(self, "_" + method)(context, **kwargs)

    def _get_location(self, task, **kwargs):
        """Retrieve the server id."""
        ucs_helper = CiscoIronicDriverHelper()
        location = None
        try:
            ucs_helper.connect_ucsm(task)
            location = ucs_helper.get_location(task)
        except Exception as ex:
            LOG.error("Cisco driver: failed to get node location")
            raise exception.IronicException("Failed to get ManagedObject (%s) " %(ex))
        finally:
            ucs_helper.logout()
            del ucs_helper
        LOG.error(location)
        return location

    def _get_inventory(self, task, **kwargs):
        """Sets a untagged vlan id for NIC 0 of node."""
        ucs_helper = CiscoIronicDriverHelper()
        inventory = None
        
        try:
            inventory = ucs_helper.get_inventory(task)
        except Exception as ex:
            raise exception.IronicException("Cisco driver:"
                "Failed to get node inventory (%s), msg (%s)"
                %(task.node.uuid, ex))
        finally:
            ucs_helper.logout()
            del ucs_helper
        LOG.error(inventory)
        return inventory
                 
    def _get_faults(self, task, **kwargs):
        """Sets a untagged vlan id for NIC 0 of node.

        @kwargs vlan_id: id of untagged vlan for NIC 0 of node
        """
        ucs_helper = CiscoIronicDriverHelper()
        faults = {}
        try:
            faults = ucs_helper.get_faults(task)
        except Exception as ex:
            LOG.error("Cisco driver: Failed to get temperature stats for node"
                "(%s)" %(task.node.uuid))
            raise exception.IronicException("Cisco driver:"
                "failed to get temperature stats for node (%s), msg:(%s)"
                %(task.node.uuid, ex))
        finally:
            ucs_helper.logout()
            del ucs_helper
        LOG.error(faults)
        return faults 

    def _get_temperature_stats(self, task, **kwargs):
        """Sets a untagged vlan id for NIC 0 of node.

        @kwargs vlan_id: id of untagged vlan for NIC 0 of node
        """
        ucs_helper = CiscoIronicDriverHelper()
        temperature_stats = {}
        try:
            temperature_stats = ucs_helper.get_temperature_stats(task)
        except Exception as ex:
            LOG.error("Cisco driver: Failed to get temperature stats for node"
                "(%s)" %(task.node.uuid))
            raise exception.IronicException("Cisco driver:"
                "failed to get temperature stats for node (%s), msg:(%s)"
                %(task.node.uuid, ex))
        finally:
            ucs_helper.logout()
            del ucs_helper
        pass
        LOG.error(temperature_stats)
        return temperature_stats

    def _get_power_stats(self, task, **kwargs):
        """Sets a untagged vlan id for NIC 0 of node.
        """
        ucs_helper = CiscoIronicDriverHelper()
        power_stats = {}
        try:
            power_stats = ucs_helper.get_power_stats(task)
        except Exception as ex:
            LOG.error("Cisco driver: Failed to get power stats for node"
                "(%s)" %(task.node.uuid))
            raise exception.IronicException("Cisco driver:"
                "failed to get power stats for node (%s), msg:(%s)"
                %(task.node.uuid, ex))
        finally:
            ucs_helper.logout()
            del ucs_helper
        pass 
        LOG.error(power_stats)
        return power_stats

    def _get_firmware_version(self, task, **kwargs):
        """ This method gets the firmware version information"""
        ucs_helper = CiscoIronicDriverHelper()
        firmware_version = None
        try:
            firmware_version = ucs_helper.get_firmware_version(task)
        except Exception as ex:
            LOG.error("Cisco driver: Failed to get firmware version for node"
                "(%s)" %(task.node.uuid))
            raise exception.IronicException("Cisco driver:"
                "failed to get firmware version for node (%s)"
                %(task.node.uuid))
        finally:
            ucs_helper.logout()
            del ucs_helper
        pass
        LOG.error(firmware_version)
        return firmware_version

    def _enroll_nodes(self, context, **kwargs):
        """ This method enrolls the nodes into ironic DB. """
        LOG.debug(_("UCS driver vendor_passthru enroll nodes"))
        ucs_node = { 
            'hostname': kwargs.get('hostname'),
            'username': kwargs.get('username'),
            'password': kwargs.get('password'),
            'qualifier': kwargs.get('qualifier')
            }

        if not ucs_node['hostname']:
            raise exception.InvalidParameterValue(_(
                "Cisco driver_vendor_passthru enroll_nodes requires "
                "hostname be set"))

        if not ucs_node['username'] or not ucs_node['password']:
            raise exception.InvalidParameterValue(_(
                "Cisco driver requires both username and password be set"))

        ucs_helper = CiscoIronicDriverHelper(
                         ucs_node['hostname'],
                         ucs_node['username'],
                         ucs_node['password']
                         )

        handle = UcsHandle()
        try:
            ret_val = handle.Login(ucs_node['hostname'], ucs_node['username'], ucs_node['password'])
            if ret_val is True :
                ucs_helper.handles[ucs_node['hostname']] = handle
                ucs_helper.enroll_nodes()
                LOG.error("ucs_helper.handles + %s" % ucs_helper.handles)
            else:
                LOG.error("Authentication failed")    
        except exception.IronicException,ex:
            raise exception.IronicException("Cisco client: Failed to get Ucs Handle")
        finally:
            ucs_helper.logout()
            del ucs_helper
    pass
