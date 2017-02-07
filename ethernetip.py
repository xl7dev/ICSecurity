"""
Copyright (C) 2014  Sebastian Block
    
This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License.
                
This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.
 
You should have received a copy of the GNU General Public License along
with this program; if not, write to the Free Software Foundation, Inc.,
51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
"""

import random
import select
import socket
import struct
import threading
import time

from .dpkt import dpkt

ENIP_TCP_PORT   = 44818
ENIP_UDP_PORT   = 2222

#/* Common Services */
CI_SRV_GET_ALL         = 0x01
CI_SRV_SET_ATTR_ALL    = 0x02
CI_SRV_GET_ATTR_LIST   = 0x03
CI_SRV_SET_ATTR_LIST   = 0x04
CI_SRV_RESET           = 0x05
CI_SRV_START           = 0x06
CI_SRV_STOP            = 0x07
CI_SRV_CREATE          = 0x08
CI_SRV_DELETE          = 0x09
CI_SRV_MULTIPLE_SRV    = 0x0A
CI_SRV_APPLY_ATTR      = 0x0D
CI_SRV_GET_ATTR_SINGLE = 0x0E
CI_SRV_SET_ATTR_SINGLE = 0x10
CI_SRV_FIND_NEXT_OBJ   = 0x11
CI_SRV_RESTORE         = 0x15
CI_SRV_SAVE            = 0x16
CI_SRV_NOP             = 0x17
CI_SRV_GET_MEMBER      = 0x18
CI_SRV_SET_MEMBER      = 0x19
CI_SRV_INSERT_MEMBER   = 0x1A
CI_SRV_REMOVE_MEMBER   = 0x1B
CI_SRV_GROUP_SYNC      = 0x1C
CI_SRV_FORWARD_CLOSE   = 0x4E
CI_SRV_UNCONN_SEND     = 0x52
CI_SRV_FORWARD_OPEN    = 0x54

#/* List of Objects */
CIP_OBJ_IDENTITY       = 0x01
CIP_OBJ_MESSAGE_ROUTER = 0x02
CIP_OBJ_ASSEMBLY       = 0x04
CIP_OBJ_CONNECTION     = 0x05
CIP_OBJ_CONNMANAGER    = 0x06
CIP_OBJ_DLR            = 0x47
CIP_OBJ_QOS            = 0x48
CIP_OBJ_BASE_SWITCH    = 0x51
CIP_OBJ_SNMP           = 0x52
CIP_OBJ_POWER_MANAGEM  = 0x53
CIP_OBJ_RSTP_BRIDGE    = 0x54
CIP_OBJ_RSTP_PORT      = 0x55
CIP_OBJ_PRP            = 0x56
CIP_OBJ_PRP_NODE_TABLE = 0x57
CIP_OBJ_CONN_CONF      = 0xF3
CIP_OBJ_PORT           = 0xF4
CIP_OBJ_TCPIP          = 0xF5
CIP_OBJ_ETHERNET_LINK  = 0xF6

#/* The following are CIP (Ethernet/IP) Generic error codes */
CIP_ROUTER_ERROR_SUCCESS                   = 0x00  # We done good...
CIP_ROUTER_ERROR_FAILURE                   = 0x01  # Connection failure
CIP_ROUTER_ERROR_NO_RESOURCE               = 0x02  # Resource(s) unavailable
CIP_ROUTER_ERROR_INVALID_PARAMETER_VALUE   = 0x03  # Obj specific data bad
CIP_ROUTER_ERROR_INVALID_SEG_TYPE          = 0x04  # Invalid segment type in path
CIP_ROUTER_ERROR_INVALID_DESTINATION       = 0x05  # Invalid segment value in path
CIP_ROUTER_ERROR_PARTIAL_DATA              = 0x06  # Not all expected data sent
CIP_ROUTER_ERROR_CONN_LOST                 = 0x07  # Messaging connection lost
CIP_ROUTER_ERROR_BAD_SERVICE               = 0x08  # Unimplemented service code
CIP_ROUTER_ERROR_BAD_ATTR_DATA             = 0x09  # Bad attribute data value
CIP_ROUTER_ERROR_ATTR_LIST_ERROR           = 0x0A  # Get/set attr list failed
CIP_ROUTER_ERROR_ALREADY_IN_REQUESTED_MODE = 0x0B  # Obj already in requested mode
CIP_ROUTER_ERROR_OBJECT_STATE_CONFLICT     = 0x0C  # Obj not in proper mode
CIP_ROUTER_ERROR_OBJ_ALREADY_EXISTS        = 0x0D  # Object already created
CIP_ROUTER_ERROR_ATTR_NOT_SETTABLE         = 0x0E  # Set of get only attr tried
CIP_ROUTER_ERROR_PERMISSION_DENIED         = 0x0F  # Insufficient access permission
CIP_ROUTER_ERROR_DEV_IN_WRONG_STATE        = 0x10  # Device not in proper mode
CIP_ROUTER_ERROR_REPLY_DATA_TOO_LARGE      = 0x11  # Response packet too large
CIP_ROUTER_ERROR_FRAGMENT_PRIMITIVE        = 0x12  # Primitive value will fragment
CIP_ROUTER_ERROR_NOT_ENOUGH_DATA           = 0x13  # Goldilocks complaint #1
CIP_ROUTER_ERROR_ATTR_NOT_SUPPORTED        = 0x14  # Attribute is undefined
CIP_ROUTER_ERROR_TOO_MUCH_DATA             = 0x15  # Goldilocks complaint #2
CIP_ROUTER_ERROR_OBJ_DOES_NOT_EXIST        = 0x16  # Non-existant object specified
CIP_ROUTER_ERROR_NO_FRAGMENTATION          = 0x17  # Fragmentation not active
CIP_ROUTER_ERROR_DATA_NOT_SAVED            = 0x18  # Attr data not previously saved
CIP_ROUTER_ERROR_DATA_WRITE_FAILURE        = 0x19  # Attr data not saved this time
CIP_ROUTER_ERROR_REQUEST_TOO_LARGE         = 0x1A  # Routing failure on request
CIP_ROUTER_ERROR_RESPONSE_TOO_LARGE        = 0x1B  # Routing failure on response
CIP_ROUTER_ERROR_MISSING_LIST_DATA         = 0x1C  # Attr data not found in list
CIP_ROUTER_ERROR_INVALID_LIST_STATUS       = 0x1D  # Returned list of attr w/status
CIP_ROUTER_ERROR_SERVICE_ERROR             = 0x1E  # Embedded service failed
CIP_ROUTER_ERROR_VENDOR_SPECIFIC           = 0x1F  # Vendor specific error
CIP_ROUTER_ERROR_INVALID_PARAMETER         = 0x20  # Invalid parameter
CIP_ROUTER_ERROR_WRITE_ONCE_FAILURE        = 0x21  # Write once previously done
CIP_ROUTER_ERROR_INVALID_REPLY             = 0x22  # Invalid reply received
CIP_ROUTER_ERROR_BAD_KEY_IN_PATH           = 0x25  # Electronic key in path failed
CIP_ROUTER_ERROR_BAD_PATH_SIZE             = 0x26  # Invalid path size
CIP_ROUTER_ERROR_UNEXPECTED_ATTR           = 0x27  # Cannot set attr at this time
CIP_ROUTER_ERROR_INVALID_MEMBER            = 0x28  # Member ID in list nonexistant
CIP_ROUTER_ERROR_MEMBER_NOT_SETTABLE       = 0x29  # Cannot set value of member
CIP_ROUTER_ERROR_UNKNOWN_MODBUS_ERROR      = 0x2B  # Unhandled Modbus Error
CIP_ROUTER_ERROR_STILL_PROCESSING          = 0xFF  # Special marker to indicate we haven't finished processing the request yet

# Extended status in Forward open response
CIP_FWD_OPEN_EXTENDED_STATUS_INVALID_CONFIGURATION_SIZE = 0x126

class EncapsulationPacket(dpkt.Packet):
    # commands
    ENCAP_CMD_NOP                       = 0x0000
    ENCAP_CMD_LISTSERVICES              = 0x0004
    ENCAP_CMD_LISTIDENTITY              = 0x0063
    ENCAP_CMD_LISTINTERFACES            = 0x0064
    ENCAP_CMD_REGISTERSESSION           = 0x0065
    ENCAP_CMD_UNREGISTERSESSION         = 0x0066
    ENCAP_CMD_SENDRRDATA                = 0x006F
    ENCAP_CMD_SENDUNITDATA              = 0x0070
    ENCAP_CMD_INDICATESTATUS            = 0x0072
    ENCAP_CMD_CANCEL                    = 0x0073
    # status
    ENCAP_STATUS_SUCCESS                = 0x0000
    ENCAP_STATUS_INVALID_CMD            = 0x0001
    ENCAP_STATUS_OUT_OF_MEMORY          = 0x0002
    ENCAP_STATUS_INCORRECT_DATA         = 0x0003
    ENCAP_STATUS_INVALID_LENGTH         = 0x0065
    ENCAP_STATUS_UNSUPPORTED_VERSION    = 0x0069

    __byte_order__ = '<'
    __hdr__ = (('command', 'H', 0), 
               ('length',  'H', 0),
               ('session', 'I', 0),
               ('status',  'I', 0),
               ('sender_context', '8s', bytes([0,0,0,0,0,0,0,0])),
               ('options', 'I', 0))

class CommandSpecificData(dpkt.Packet):
    # type ID
    TYPE_ID_NULL                        = 0x0000
    TYPE_ID_LIST_IDENT_RESPONSE         = 0x000C
    TYPE_ID_CONNECTION_BASED            = 0x00A1
    TYPE_ID_CONNECTED_TRANSPORT_PACKET  = 0x00B1
    TYPE_ID_UNCONNECTED_MESSAGE         = 0x00B2
    TYPE_ID_LISTSERVICES_RESPONSE       = 0x0100
    TYPE_ID_SOCKADDR_INFO_ORIG_TARGET   = 0x8000
    TYPE_ID_SOCKADDR_INFO_TARGET_ORIG   = 0x8001
    TYPE_ID_SEQUENCED_ADDRESS           = 0x8002
    
    __byte_order__ = '<'
    __hdr__ = (('item_count', 'H', 0),
               ('type_id', 'H', 0),
               ('length', 'H', 0))

class UnconnectedDataItem(dpkt.Packet):

    UNCONN_DATA_ITEM_SERVICE_REQUEST  = 0x00
    UNCONN_DATA_ITEM_SERVICE_RESPONSE = 0x80

    __byte_order__ = '<'
    __hdr__ = (('type_id', 'H', 0),
               ('length', 'H', 0),
               ('service', 'B', 0))

class UnconnectedDataItemHdr(dpkt.Packet):
    __byte_order__ = '<'
    __hdr__ = (('type_id', 'H', 0),
               ('length', 'H', 0))

class UnconnectedDataItemResp(dpkt.Packet):
    __byte_order__ = '<'
    __hdr__ = (('type_id', 'H', 0),
               ('length', 'H', 0),
               ('service', 'B', 0),
               ('resv', 'B', 0),
               ('status', 'B', 0),
               ('additional_status_size', 'B', 0))

class ForwardOpenReq(dpkt.Packet):
    # network connection parameter bit offsets
    FORWARD_OPEN_CONN_PARAM_BIT_CONN_SIZE   = 0
    FORWARD_OPEN_CONN_PARAM_BIT_FIXED_VAR   = 9
    FORWARD_OPEN_CONN_PARAM_BIT_PRIORITY    = 10
    FORWARD_OPEN_CONN_PARAM_BIT_CONN_TYPE   = 13
    FORWARD_OPEN_CONN_PARAM_BIT_REDAN_OWN   = 15

    __byte_order__ = '<'
    __hdr__ = (('mkpath', '5s', b"00000"), # len, 2 path
               ('prio_tick', 'B', 0x0A), # 4 Bit prio, 4 Bit tick time
               ('timeout_ticks', 'B', 0xF0), 
               ('otconnid', 'I', 0xdeadbeaf),
               ('toconnid', 'I', 0xaffedead),
               ('conn_serial', 'H', 0x4949),
               ('vendor', 'H', 1),
               ('orig_serial', 'I', 0xbeeff00d),
               ('multiplier', 'B', 1),
               ('reserved', '3s', b"000"),
               ('otrpi', 'I', 0x186a0), # 100 ms
               ('otparams', 'H', 0x480c),
               ('torpi', 'I', 0x186A0), # 100 ms
               ('toparams', 'H', 0x2808), 
               ('type_trigger', 'B', 0x01),
               ('plen', 'B', 9))

class ForwardOpenResp(dpkt.Packet):
    __byte_order__ = '<'
    __hdr__ = (('reserved', '3s', ''),
               ('otconnid', 'I', 0),
               ('toconnid', 'I', 0),
               ('conn_serial', 'H', 0),
               ('vendor', 'H', 0),
               ('orig_serial', 'I', 0),
               ('otapi', 'I', 0),
               ('toapi', 'I', 0),
               ('appl_reply_size', 'B', 0),
               ('reserved2', 'B', 0)
              )

class ForwardCloseReq(dpkt.Packet):
    __byte_order__ = '<'
    __hdr__ = (('mkpath', '5s', b"00000"), # len, 2 path
               ('prio_tick', 'B', 0x0A), # 4 Bit prio, 4 Bit tick time
               ('timeout_ticks', 'B', 0xF0), 
               ('conn_serial', 'H', 0x4949),
               ('vendor', 'H', 1),
               ('orig_serial', 'I', 0xbeeff00d),
               ('plen', 'B', 9),
               ('reserved', 'B', 0)
              )
              
class ForwardCloseResp(dpkt.Packet):
    __byte_order__ = '<'
    __hdr__ = (('reserved', '3s', ''),
               ('conn_serial', 'H', 0),
               ('vendor', 'H', 0),
               ('orig_serial', 'I', 0),
               ('appl_reply_size', 'B', 0),
               ('reserved2', 'B', 0)
              )

class RegisterSessionPacket(dpkt.Packet):
    __byte_order__ = '<'
    __hdr__ = (('protocol_version', 'H', 1),
               ('option_flags', 'H', 0))

class ListServicesReply(dpkt.Packet):
    # capcability flags
    CAP_CIP_ENCAP_VIA_TCP   = 0x0020
    CAP_CIP_VIA_UDP         = 0x0100

    __byte_order__ = '<'
    __hdr__ = (('version', 'H', 0),
               ('capability_flags', 'H', 0),
               ('name_of_service', '16s', ''))

class ListIdentifyReply(dpkt.Packet):
    # status is a bit encoded word
    LIST_IDENT_STATUS_OWNED                     = 0x0001
    LIST_IDENT_STATUS_CONFIGURED                = 0x0004
    LIST_IDENT_STATUS_EXTENDED_DEVICE_STATUS    = 0x00F0
    LIST_IDENT_STATUS_MINOR_RECOVERABLE_FAULT   = 0x0100
    LIST_IDENT_STATUS_MINOR_UNRECOVERABLE_FAULT = 0x0200
    LIST_IDENT_STATUS_MAJOR_RECOVERABLE_FAULT   = 0x0400
    LIST_IDENT_STATUS_MAJOR_UNRECOVERABLE_FAULT = 0x0800
    LIST_IDENT_STATUS_EXTENDED_DEVICE_STATUS2   = 0xF000
    # states
    LIST_IDENT_STATE_NONEXISTENT         = 0x00
    LIST_IDENT_STATE_SELF_TESTING        = 0x01
    LIST_IDENT_STATE_STANDBY             = 0x02
    LIST_IDENT_STATE_OPERATIONAL         = 0x03
    LIST_IDENT_STATE_RECOVERABLE_FAULT   = 0x04
    LIST_IDENT_STATE_UNRECOVERABLE_FAULT = 0x05
    LIST_IDENT_STATE_DEFAULT             = 0xFF

    __byte_order__ = '<'
    __hdr__ = (('version', 'H', 1),
               ('socket_addr', '16s', ''),
               ('vendor_id', 'H', 0),
               ('device_type', 'H', 0),
               ('product_code', 'H', 0),
               ('revision_major', 'B', 0),
               ('revision_minor', 'B', 0),
               ('status', 'H', 0),
               ('serial_no', 'I', 0),
               ('product_name_length', 'B', 0),
               ('product_name', '0s', ''), 
               ('state', 'B', 0))

    def unpack(self, buf):
        # product name can be a string upto 32 chars, but python does not
        # support variable string length, so we have to write a little
        # work-a-round and first unpack it check the length and calculate it
        # again
        tmp = dpkt.Packet.unpack(self, buf)
        self.__hdr_fmt__ = "<H16sHHHBBHIB" + str(self.product_name_length) + "sB"
        self.__hdr_len__ = struct.calcsize(self.__hdr_fmt__)
        dpkt.Packet.unpack(self, buf)

class SendRRPacket(dpkt.Packet):
    __byte_order__ = '<'
    __hdr__ = (('interface_handle', 'I', 0),
               ('timeout', 'H', 10))

class SocketAddressInfo(dpkt.Packet):
    __byte_order__ = '>' # big endian 
    __hdr__ = (('sin_family', 'H', 0),
               ('sin_port', 'H', 0),
               ('sin_addr', 'I', 0),
               ('sin_zero', '8s', ''))

class UdpSendDataPacket(dpkt.Packet):
    __byte_order__ = '<'
    __hdr__ = (('count', 'H', 2),
               ('type_id_seq_addr', 'H', 0x8002),
               ('len_seq_addr', 'H', 8),
               ('conn_id', 'I', 0),
               ('seq_num', 'I', 0),
               ('type_id_conn_data', 'H', 0x00b1),
               ('len_conn_data', 'H', 12),
               ('seq_count', 'H', 0))

class UdpRecvDataPacket(dpkt.Packet):
    __byte_order__ = '<'
    __hdr__ = (('count', 'H', 2),
               ('type_id_seq_addr', 'H', 0x8002),
               ('len_seq_addr', 'H', 8),
               ('conn_id', 'I', 0),
               ('seq_num', 'I', 0),
               ('type_id_conn_data', 'H', 0x00b1),
               ('length', 'H', 12),
               ('unknown', 'H', 0)) # TODO check for what the first two bytes of data are

class EthernetIOThread(threading.Thread):
    def __init__(self, typ, enip=None, conn=None):
        self.typ = typ
        self.enip = enip
        self.conn = conn
        threading.Thread.__init__(self)

    def run(self):
        if self.typ == 1:
            self.enip.listenUDP()
        elif self.typ == 2:
            self.conn.prodThread()

class EtherNetIP(object):
    ENIP_IO_TYPE_INPUT  = 0
    ENIP_IO_TYPE_OUTPUT = 1

    def __init__(self, ip="127.0.0.1"):
        self.assembly  = {}
        self.explicit  = []
        self.udpsock   = None
        self.udpthread = None
        self.io_state  = 0
        self.ip = ip

    def registerAssembly(self, iotype, size, inst, conn):
        if inst in self.assembly:
            print("Reg assembly failed for iotype=", iotype)
            return None
        bits = []
        for i in range(size*8):
            bits.append(0)
        self.assembly[inst] = (conn, iotype, bits)
        if conn != None:
            if iotype == EtherNetIP.ENIP_IO_TYPE_INPUT:
                conn.mapIn(bits)
            elif iotype == EtherNetIP.ENIP_IO_TYPE_OUTPUT:
                conn.mapOut(bits)
        return bits

    def startIO(self):
        if self.io_state == 0:
            self.udpsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.udpsock.bind(("0.0.0.0", ENIP_UDP_PORT))
            self.udpthread = EthernetIOThread(1,self)
            self.io_state = 1
            self.udpthread.start()

    def stopIO(self):
        if self.io_state == 1:
            self.io_state = 0
            self.udpsock.close()

    def listenUDP(self):
        while 1 == self.io_state:
            inp, out, err = select.select([self.udpsock], [], [], 2)
            if len(inp) != 0:
                try:
                    buf, addr = self.udpsock.recvfrom(1024)
                except OSError:
                    # If we close the socket asynchronously, the recv will
                    # fail
                    if self.io_state == 0:
                        return
                    raise

                addr = addr[0]
                pkt = UdpRecvDataPacket(buf)

                for inst in self.assembly:
                    conn = self.assembly[inst][0]
                    iotype = self.assembly[inst][1]
                    bits = self.assembly[inst][2]
                    # update i/o
                    if conn.ipaddr == addr and iotype == EtherNetIP.ENIP_IO_TYPE_INPUT and pkt.conn_id == conn.toconnid:
                        i = 0
                        for byte in pkt.data:
                            for s in range(8):
                                if byte & (1 << s):
                                    bits[i] = True
                                else:
                                    bits[i] = False
                                i += 1

    def explicit_conn(self, ipaddr=None):
        if ipaddr is None:
            ipaddr = self.ip
        exp = EtherNetIPExpConnection(ipaddr)
        self.explicit.append(exp)
        return exp

    def listIDUDP(self, ipaddr=None, timeout=5):
        udpsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udpsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        context = random.randint(1, 4026531839)
        pkt = EncapsulationPacket(command=EncapsulationPacket.ENCAP_CMD_LISTIDENTITY,
                                  sender_context=context.to_bytes(8, byteorder='big'))
        if ipaddr is None:
            ipaddr = self.ip
        udpsock.sendto(pkt.pack(),(ipaddr, ENIP_TCP_PORT))
        inp, out, err = select.select([udpsock], [], [], timeout)
        if len(inp) != 0:
            data = udpsock.recv(1024)
            pkt = EncapsulationPacket()
            pkt.unpack(data)
            if pkt.status == EncapsulationPacket.ENCAP_STATUS_SUCCESS and pkt.command == EncapsulationPacket.ENCAP_CMD_LISTIDENTITY:
                csd = CommandSpecificData(pkt.data)
                if csd.type_id == CommandSpecificData.TYPE_ID_LIST_IDENT_RESPONSE:
                    lid = ListIdentifyReply(csd.data)
                    return lid
        return None

class EtherNetIPSocket(object):
    def __init__(self, ip):
        self.ipaddr = ip
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.ipaddr, ENIP_TCP_PORT))
        self.conn_serial_num = 0

    def delete(self):
        self.sock.close()
    
    def mkReqPath(self, clas, inst, attr):
        if clas > 255: 
            clas_data = struct.pack("BBH", 0x21, 0, 0x300)
        else:
            clas_data = struct.pack("BB", 0x20, clas)
        inst_data = struct.pack("BB", 0x24, inst)
        attr_data = b''
        if attr != None:
             attr_data = struct.pack("BB", 0x30, attr)
        data = bytes([(int((len(clas_data) + len(inst_data) + len(attr_data))/2))])
        data += clas_data
        data += inst_data
        data += attr_data
        return data

    def scanNetwork(self, broadcastAddress="255.255.255.0", timeout=10):
        import time
        listOfNodes = []
        udpsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        #udpsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        udpsock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        context = random.randint(1, 4026531839)
        pkt = EncapsulationPacket(command=EncapsulationPacket.ENCAP_CMD_LISTIDENTITY,
                                  sender_context=context.to_bytes(8, byteorder='big'))
        udpsock.sendto(pkt.pack(),(broadcastAddress, ENIP_TCP_PORT))
        tStart = time.time()
        while time.time() < (tStart+timeout):
            timeout = tStart + timeout - time.time()
            inp, out, err = select.select([udpsock], [], [], timeout)
            if len(inp) != 0:
                data = udpsock.recv(1024)
                pkt = EncapsulationPacket()
                pkt.unpack(data)
                if pkt.status == EncapsulationPacket.ENCAP_STATUS_SUCCESS and pkt.command == EncapsulationPacket.ENCAP_CMD_LISTIDENTITY:
                    csd = CommandSpecificData(pkt.data)
                    if csd.type_id == CommandSpecificData.TYPE_ID_LIST_IDENT_RESPONSE:
                        lid = ListIdentifyReply(csd.data)
                        listOfNodes.append(lid)
        return listOfNodes

    def listID(self):
        context = random.randint(1, 4026531839)
        pkt = EncapsulationPacket(command=EncapsulationPacket.ENCAP_CMD_LISTIDENTITY,
                                               sender_context=context.to_bytes(8, byteorder='big'))
        self.sock.send(pkt.pack())
        inp, out, err = select.select([self.sock], [], [], 10)
        if len(inp) != 0:
            data = self.sock.recv(1024)
            pkt = EncapsulationPacket()
            pkt.unpack(data)
            if pkt.status == EncapsulationPacket.ENCAP_STATUS_SUCCESS and pkt.command == EncapsulationPacket.ENCAP_CMD_LISTIDENTITY:
                csd = CommandSpecificData(pkt.data)
                if csd.type_id == CommandSpecificData.TYPE_ID_LIST_IDENT_RESPONSE:
                    lid = ListIdentifyReply(csd.data)
                    return lid
        return None

    def listServices(self):
        context = random.randint(1,4026531839)
        pkt = EncapsulationPacket(command=EncapsulationPacket.ENCAP_CMD_LISTSERVICES,
                                  sender_context=context.to_bytes(8, byteorder='big'))
        self.sock.send(pkt.pack())
        inp, out, err = select.select([self.sock], [], [], 10)
        if len(inp) != 0:
            data = self.sock.recv(1024)
            pkt = EncapsulationPacket()
            pkt.unpack(data)
            if pkt.status == EncapsulationPacket.ENCAP_STATUS_SUCCESS and pkt.command == EncapsulationPacket.ENCAP_CMD_LISTSERVICES:
                csd = CommandSpecificData(pkt.data)
                if csd.type_id == CommandSpecificData.TYPE_ID_LISTSERVICES_RESPONSE:
                    lsr = ListServicesReply(csd.data)
                    return lsr
        return None

class EtherNetIPSession(EtherNetIPSocket):
    def __init__(self, ipaddr):
        EtherNetIPSocket.__init__(self,ipaddr)
        self.session = 0

    def delete(self):
        self.session = 0

    def registerSession(self):
        context = random.randint(1,4026531839)
        csd = RegisterSessionPacket(protocol_version=1, option_flag=0)
        pkt = EncapsulationPacket(command=EncapsulationPacket.ENCAP_CMD_REGISTERSESSION,\
                                  length=len(csd), sender_context=context.to_bytes(8, byteorder='big'), data=csd)
        self.sock.send(pkt.pack())
        inp, out, err = select.select([self.sock], [], [], 10)
        if len(inp) != 0:
            data = self.sock.recv(1024)
            pkt = EncapsulationPacket()
            pkt.unpack(data)
            if pkt.status == EncapsulationPacket.ENCAP_STATUS_SUCCESS and pkt.command == EncapsulationPacket.ENCAP_CMD_REGISTERSESSION:
                self.session = pkt.session
                return 0
        return None

    def unregisterSession(self):
        context = random.randint(1,4026531839)
        pkt = EncapsulationPacket(command=EncapsulationPacket.ENCAP_CMD_UNREGISTERSESSION,\
                                  length=0, session=self.session, sender_context=context.to_bytes(8, byteorder='big'), data=b'')
        self.sock.send(pkt.pack())
        self.session=0
        

    def sendEncap(self, command, data):
        context = random.randint(1,4026531839)
        pkt = EncapsulationPacket(command=command, length=len(data), sender_context=context.to_bytes(8, byteorder='big'), data=data)
        return self.sock.send(pkt.pack())
    
    def unconnSend(self, service, data, context=0, chk=0, chkdata="\x00"):
        sz = len(data) + 17
        # add service field
        dsz = len(data) + 1
        cpf2 = \
        UnconnectedDataItem(type_id=CommandSpecificData.TYPE_ID_UNCONNECTED_MESSAGE, \
                            length=dsz, data=data, \
                            service=(service|UnconnectedDataItem.UNCONN_DATA_ITEM_SERVICE_REQUEST))
        cpf = CommandSpecificData(type_id=CommandSpecificData.TYPE_ID_NULL, \
                                  item_count=2, length=0, data=cpf2)
        srr = SendRRPacket(interface_handle=0, timeout=10, data=cpf); 
        pkt = EncapsulationPacket(command=EncapsulationPacket.ENCAP_CMD_SENDRRDATA, \
                                  length=len(srr),session=self.session, sender_context=context.to_bytes(8, byteorder='big'), data=srr)
        self.sock.send(pkt.pack())
        inp, out, err = select.select([self.sock], [], [], 10)
        if len(inp) != 0:
            data = self.sock.recv(4096)
            if len(data) > 0:
                pkt = EncapsulationPacket()
                pkt.unpack(data)
                if pkt.status == EncapsulationPacket.ENCAP_STATUS_SUCCESS and \
                        pkt.command == EncapsulationPacket.ENCAP_CMD_SENDRRDATA:
                    srr = SendRRPacket(pkt.data)
                    csd = CommandSpecificData(srr.data)
                    cpf = UnconnectedDataItemResp(csd.data)
                    ret = [cpf.status, cpf.data]
                    if chk != 0:
                        rsppkt = self.unconnSendValidRsp(service, chkdata, context)
                        if str(rsppkt) != str(pkt):
                            print("Packets differ")
                            assert(0)
                    return ret
        return None

    def unconnSendValidRsp(self, service, data, context=0):
        sz = len(data) + 17
        dsz = len(data) + 1
        cpf2 = \
        UnconnectedDataItem(type_id=CommandSpecificData.TYPE_ID_UNCONNECTED_MESSAGE, \
                            length=dsz, data=data, \
                            service=(service|UnconnectedDataItem.UNCONN_DATA_ITEM_SERVICE_RESPONSE))
        cpf = CommandSpecificData(type_id=CommandSpecificData.TYPE_ID_NULL, length=0, data=cpf2)
        srr = SendRRPacket(interface_handle=0, timeout=10, data=cpf); 
        pkt = EncapsulationPacket(command=EncapsulationPacket.ENCAP_CMD_SENDRRDATA, \
                                  length=len(srr),session=self.session, sender_context=context.to_bytes(8, 'big'), data=srr)
        return pkt

    def getAttrSingle(self, clas, inst, attr, data=b'', chk=0, chkdata="\x00", service=CI_SRV_GET_ATTR_SINGLE):
        path = self.mkReqPath(clas, inst, attr)
        return self.unconnSend(service, path+data, \
                               random.randint(1,4026531839), chk, chkdata)

    def getAttrAll(self, clas, inst, data=b'', chk=0, chkdata="\x00"):
        path = self.mkReqPath(clas, inst, None)
        return self.unconnSend(CI_SRV_GET_ALL, path+data, \
                               random.randint(1,4026531839), chk, chkdata)
                            
    def setAttrSingle(self, clas, inst, attr, data):
        if str == type(data): 
            # string values need a special attention (add length before and a padding byte behind)
            data_len = len(data)
            data = struct.pack("BB", data_len, 0) + data.encode()
            if data_len&1:
                data += b"\x00"
        path = self.mkReqPath(clas, inst, attr)
        return self.unconnSend(CI_SRV_SET_ATTR_SINGLE, path+data, \
                        random.randint(1,4026531839), 0, "")

    def setAttrAll(self, clas, inst, data):
        if str == type(data): 
            # string values need a special attention (add length before and a padding byte behind)
            data_len = len(data)
            data = struct.pack("BB", data_len, 0) + data.encode()
            if data_len&1:
                data += b"\x00"
        path = self.mkReqPath(clas, inst, None)
        return self.unconnSend(CI_SRV_SET_ATTR_ALL, path+data, \
                        random.randint(1,4026531839), 0, "")


    def resetService(self, inst=1, resetType=0):
        path = self.mkReqPath(CIP_OBJ_IDENTITY, inst, attr=None)
        data = struct.pack("B", resetType)
        return self.unconnSend(CI_SRV_RESET, path+data, random.randint(1,4026531839), 0, "")

class EtherNetIPExpConnection(EtherNetIPSession):
    def __init__(self, ipaddr):
        EtherNetIPSession.__init__(self, ipaddr)
        self.inAssem = None
        self.outAssem = None
        self.otconnid = 0
        self.toconnid = 0
        self.otapi = 100
        self.toapi = 100
        self.prod_state = 0
        self.prod_thread = None
        self.prodsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.seqnum = 0

    def mapIn(self, inAssem):
        self.inAssem = inAssem

    def mapOut(self, outAssem):
        self.outAssem = outAssem

    def sendFwdOpenReq(self, inputinst, outputinst, configinst, multiplier=1, \
                       torpi=1000, otrpi=1000, multicast=False, inputsz=None, \
                       outputsz=None, fwdo=None, configData=None):
        rand = random.randint(1, 0xffff) + 0xE4190000
        torpi *= 1000
        otrpi *= 1000
        if None == inputsz:
            if None != self.inAssem:
                inputsz = len(self.inAssem) / 8
            else:
                inputsz = 8
        if None == outputsz:
            if None != self.outAssem:
                outputsz = len(self.outAssem) / 8
            else:
                outputsz = 8
        outputsz += 6 # seq num and run/idle header
        inputsz += 2 # seq num
        if multicast == False:
            mcast = 2 # p2p
        else:
            mcast = 1
        path = struct.pack(">I",0x34040000) + struct.pack("I",0) + \
               struct.pack(">I",0x00002004) + struct.pack("B",0x24) + struct.pack("B",configinst) + \
               struct.pack("B",0x2c) + struct.pack("B",outputinst) + struct.pack("B",0x2c) +        \
               struct.pack("B",inputinst)
        plen = int(len(path) / 2)
        if configData != None:
                # 0x80 = simple data segment, with length in words => max 512 bytes of data
                if len(configData) > 512:
                        return 1    
                path += struct.pack("BB", 0x80, int(len(configData)/2) )
                path += configData
                plen = int(len(path) / 2)
        if fwdo == None:
            self.conn_serial_num += 1
            fwdo = ForwardOpenReq( \
                                  otconnid=rand, toconnid=rand-1, \
                                  conn_serial=self.conn_serial_num, \
                                  multiplier=multiplier, \
                                  mkpath=self.mkReqPath(clas=0x06,inst=0x01,attr=None), \
                                  torpi=torpi, \
                                  otrpi=otrpi, \
                                  toparams=(int(inputsz)| \
                                            (0x2<<ForwardOpenReq.FORWARD_OPEN_CONN_PARAM_BIT_PRIORITY) | \
                                            (mcast<<ForwardOpenReq.FORWARD_OPEN_CONN_PARAM_BIT_CONN_TYPE) \
                                           ), \
                                  otparams=(int(outputsz) | \
                                            0x2<<ForwardOpenReq.FORWARD_OPEN_CONN_PARAM_BIT_PRIORITY | \
                                            0x2<<ForwardOpenReq.FORWARD_OPEN_CONN_PARAM_BIT_CONN_TYPE \
                                           ), \
                                  plen=plen, \
                                  data=path \
                                 )
        # add service field
        dsz = len(fwdo) + 1
        cpf2 = \
        UnconnectedDataItem(type_id=CommandSpecificData.TYPE_ID_UNCONNECTED_MESSAGE, \
                            length=dsz, data=fwdo, \
                            service=(CI_SRV_FORWARD_OPEN|UnconnectedDataItem.UNCONN_DATA_ITEM_SERVICE_REQUEST))
        cpf = CommandSpecificData(type_id=CommandSpecificData.TYPE_ID_NULL, \
                                  item_count=2, length=0, data=cpf2)
        srr = SendRRPacket(interface_handle=0, timeout=0, data=cpf); 
        pkt = EncapsulationPacket(command=EncapsulationPacket.ENCAP_CMD_SENDRRDATA, \
                                  length=len(srr),session=self.session, \
                                  sender_context=random.randint(1,4026531839).to_bytes(8, byteorder='big'), \
                                  data=srr
                                 )
        self.sock.send(pkt.pack())
        inp, out, err = select.select([self.sock], [], [], 10)
        if len(inp) != 0:
            data = self.sock.recv(1024)
            pkt = EncapsulationPacket()
            pkt.unpack(data)
            if pkt.status == EncapsulationPacket.ENCAP_STATUS_SUCCESS and \
            pkt.command == EncapsulationPacket.ENCAP_CMD_SENDRRDATA:
                srr = SendRRPacket(pkt.data)
                csd = CommandSpecificData(srr.data)
                udi = UnconnectedDataItem(csd.data)
                if udi.data[1] == 0: # Forward Open Status
                    fworsp = ForwardOpenResp(udi.data)
                    # socket address info O->T
                    ucdih = UnconnectedDataItemHdr(fworsp.data)
                    otaddrinfo = SocketAddressInfo(ucdih.data)
                    if b'' != otaddrinfo.data:
                        ucdih2 = UnconnectedDataItemHdr(otaddrinfo.data)
                        toaddrinfo = SocketAddressInfo(ucdih2.data)
                    self.otconnid = fworsp.otconnid
                    self.toconnid = fworsp.toconnid
                    self.otapi = fworsp.otapi / 1000
                    if self.otapi < 8:
                        self.otapi = 8
                    self.toapi = fworsp.toapi / 1000
                    if self.toapi < 8:
                        self.toapi = 8
                    return 0
                elif udi.data[1] == 0x01: # Forward open failed with Connection Failure
                    if udi.data[2] > 0:
                        extended_status, = struct.unpack("H", udi.data[3:5])
                        return extended_status
        return None

    def sendFwdCloseReq(self, inputinst, outputinst, configinst):
        path = struct.pack(">HB",0x2004, 0x24) + struct.pack("B",configinst) + \
               struct.pack("B",0x2c) + struct.pack("B",outputinst) + struct.pack("B",0x2c) + \
               struct.pack("B",inputinst)
        fwdc = ForwardCloseReq(conn_serial=self.conn_serial_num, \
                               mkpath=self.mkReqPath(clas=0x06,inst=0x01,attr=None), \
                               plen=4, \
                               data=path \
                              )
        # add service field
        dsz = len(fwdc) + 1
        cpf2 = \
        UnconnectedDataItem(type_id=CommandSpecificData.TYPE_ID_UNCONNECTED_MESSAGE, \
                            length=dsz, data=fwdc, \
                            service=(CI_SRV_FORWARD_CLOSE|UnconnectedDataItem.UNCONN_DATA_ITEM_SERVICE_REQUEST))
        cpf = CommandSpecificData(type_id=CommandSpecificData.TYPE_ID_NULL, \
                                  item_count=2, length=0, data=cpf2)
        srr = SendRRPacket(interface_handle=0, timeout=0, data=cpf); 
        pkt = EncapsulationPacket(command=EncapsulationPacket.ENCAP_CMD_SENDRRDATA, \
                                  length=len(srr),session=self.session, \
                                  sender_context=random.randint(1,4026531839).to_bytes(8, byteorder='big'), \
                                  data=srr
                                 )
        self.sock.send(pkt.pack())
        inp, out, err = select.select([self.sock], [], [], 10)
        if len(inp) != 0:
            data = self.sock.recv(1024)
            pkt = EncapsulationPacket()
            pkt.unpack(data)
            if pkt.status == EncapsulationPacket.ENCAP_STATUS_SUCCESS and \
            pkt.command == EncapsulationPacket.ENCAP_CMD_SENDRRDATA:
                srr = SendRRPacket(pkt.data)
                csd = CommandSpecificData(srr.data)
                udi = UnconnectedDataItem(csd.data)
                fwcrsp = ForwardCloseResp(udi.data)
                return 0 
        return None


    def sendUdpIO(self, runidle=True):
        output = b""
        if runidle:
            output += b"\x01\x00\x00\x00"
        cnt = 0
        val = 0
        for bit in self.outAssem:
            if bit == True:
                val += 1 << cnt
            cnt += 1
            if cnt == 8:
                cnt = 0
                output += struct.pack("B", val)
                val = 0

        pkt = UdpSendDataPacket(seq_num=self.seqnum, seq_count=self.seqnum, \
                            conn_id=self.otconnid, \
                            len_conn_data=int((len(self.outAssem)/8)+6), \
                            data=output \
                          )
        self.seqnum += 1
        self.prodsock.sendto(pkt.pack(), (self.ipaddr,ENIP_UDP_PORT))

    def prodThread(self):
        import time
        while self.prod_state == 1:
            self.sendUdpIO()
            time.sleep(self.otapi/1000)

    def produce(self):
        if self.prod_state == 0:
            self.prod_thread = EthernetIOThread(2, None, self)
            self.prod_state = 1
            self.prod_thread.start()

    def stopProduce(self):
        if self.prod_state == 1:
            self.prod_state = 0
        
def testENIP():
    hostname = "192.168.1.32"
    broadcast = "192.168.255.255"
    inputsize = 1
    outputsize = 1
    EIP = EtherNetIP(hostname)
    C1 = EIP.explicit_conn(hostname)

    """    
    listOfNodes = C1.scanNetwork(broadcast,5)
    print("Found ", len(listOfNodes), " nodes")
    for node in listOfNodes:
        name = node.product_name.decode()
        sockinfo = SocketAddressInfo(node.socket_addr)
        ip = socket.inet_ntoa(struct.pack("!I",sockinfo.sin_addr))
        print(ip, " - ", name)
    """

    pkt = C1.listID()
    if pkt != None:
        print("Product name: ", pkt.product_name.decode())

    pkt = C1.listServices()
    print("ListServices:", str(pkt))


    path = C1.mkReqPath(0x300, 1, None)
    data = struct.pack("HB", 0x12, 0)
    r = C1.unconnSend(0x32, path+data, random.randint(1,4026531839))
    #r = C1.getAttrSingle(0x300, 1, None, struct.pack("HB", 0x12, 0))
    if 0 == r[0]:
        print("Could read 0x300")
    else:
        print("Failed to read 0x300")

    """
    # read input size from global system object (obj 0x84, attr 4)
    r = C1.getAttrSingle(0x84, 1, 4)
    if 0 == r[0]:
        print("Read CPX input size from terminal success (data: "+ str(r[1]) + ")")
        inputsize = struct.unpack("B", r[1])[0]
    else:
        print("Failed to read CPX input size")

    # read output size from global system object (obj 0x84, attr 5)
    r = C1.getAttrSingle(0x84, 1, 5)
    if 0 == r[0]:
        print("Read CPX output size from terminal sucess (data: " + str(r[1]) + ")")
        outputsize = struct.unpack("B", r[1])[0]
    else:
        print("Failed to read CPX output size")
    """
    """
    # configure i/o
    print("Configure with {0} bytes input and {1} bytes output".format(inputsize, outputsize))
    EIP.registerAssembly(EtherNetIP.ENIP_IO_TYPE_INPUT,  inputsize, 101, C1)
    EIP.registerAssembly(EtherNetIP.ENIP_IO_TYPE_OUTPUT, outputsize, 100, C1)
    EIP.startIO()

    C1.registerSession()

    C1.setAttrSingle(CIP_OBJ_TCPIP, 1, 6, "fbxxx")

    for i in range(1,8):
        r = C1.getAttrSingle(CIP_OBJ_IDENTITY, 1, i)
        if 0 == r[0]:
            print("read ok attr (" + str(i) + ") data: " + str(r[1]))
        else:
            print("Err: " + str(r[0]))

    C1.sendFwdOpenReq(101,100,1)
    C1.produce()

    while True:
        try: 
            time.sleep(0.2)
            C1.outAssem[random.randint(0, len(C1.outAssem)-1)] = True
            C1.outAssem[random.randint(0, len(C1.outAssem)-1)] = False
        except KeyboardInterrupt:
            break
    C1.stopProduce()
    C1.sendFwdCloseReq(101,100,1)
    EIP.stopIO()
    """

#testENIP()
