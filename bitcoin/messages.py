'''
Created on Jul 13, 2012

@author: cdecker
'''
from time import time
import struct
import socket
from io import BytesIO

from BitcoinProtocol import protocol_services, IPv4_prefix, protocol_user_agent, protocol_version
from utils import decodeVarLength, decodeVarString, encodeVarLength, encodeVarString, doubleSha256

class Packet(object):
    type = None

    def parse(self, payload):
        """
        This should be implemented by each packet in order to parse the
        contents of a message
        """
    def toWire(self, buf):
        """
        This should be implemented by the subclasses
        Writes the packet to the buffer
        """

class Address(Packet):
    """
    Not really a packet on its own but as it is serialized on several occasions
    we just implement it as such.
    """
    type = None
    def __init__(self, ip = None, isIPv4 = True, port = 8333, services = protocol_services, timestamp = None):
        self.isIPv4 = isIPv4
        if ip:
            self.ip = socket.gethostbyname(ip)
        else:
            self.ip = None
        self.timestamp = timestamp
        self.port = port
        self.services = services
        
    def parse(self, payload, timestamp = True):
        Packet.parse(self, payload)
        if timestamp:
            self.timestamp, = struct.unpack_from("<I", payload.read(4))
        self.services, ip = struct.unpack_from("<Q16s",payload.read(24))
        (self.port,) = struct.unpack_from(">H", payload.read(2))
        if ip[:12] == IPv4_prefix:
            self.isIPv4 = True
            self.ip = socket.inet_ntop(socket.AF_INET, ip[12:])
        else:
            self.isIPv4 = False
            self.ip = socket.inet_ntop(socket.AF_INET6, ip)
        
    def toWire(self, buf, timestamp = True):
        Packet.toWire(self, buf)
        if timestamp:
            buf.write(struct.pack("<I",self.timestamp))
        buf.write(struct.pack("<Q", self.services))
        if self.isIPv4:
            buf.write(IPv4_prefix)
            buf.write(socket.inet_pton(socket.AF_INET, self.ip))
        else:
            buf.write(socket.inet_pton(socket.AF_INET6, self.ip))
        buf.write(struct.pack(">H", self.port))
        
class VersionPacket(Packet):
    type = "version"
    def __init__(self):
        self.timestamp = time()
        self.services = protocol_services
        self.version = protocol_version
        self.nonce = "__ETHZ__"
        self.user_agent = protocol_user_agent
        self.best_height = 0
        
    def parse(self, payload):
        Packet.parse(self, payload)
        self.version, self.services, self.timestamp = struct.unpack("<IQQ", payload.read(20))
        self.addr_recv = Address()
        self.addr_recv.parse(payload, False)
        self.addr_from = Address()
        self.addr_from.parse(payload, False)
        self.nonce = payload.read(8)
        self.user_agent = decodeVarString(payload)
        self.best_height, = struct.unpack("<I", payload.read(4))
        
    def toWire(self, buf):
        Packet.toWire(self, buf)
        buf.write(struct.pack("<IQQ", self.version, self.services, self.timestamp))
        self.addr_recv.toWire(buf, False)
        self.addr_from.toWire(buf, False)
        buf.write(self.nonce)
        buf.write(encodeVarString(self.user_agent))
        buf.write(struct.pack("<I", self.best_height))
        
class InvPacket(Packet):
    type = "inv"
    def __init__(self):
        self.hashes = []
        
    def parse(self, payload):
        length = decodeVarLength(payload)
        while len(self.hashes) < length:
            t, = struct.unpack("<I",payload.read(4))
            h = payload.read(32)[::-1]
            self.hashes.append((t, h))
            
    def toWire(self, buf):
        buf.write(encodeVarLength(len(self.hashes)))
        for h in self.hashes:
            buf.write(struct.pack("<I", h[0]))
            buf.write(h[1][::-1])
            
class GetDataPacket(InvPacket):
    def __init__(self):
        Packet.__init__(self, "getdata")
        self.hashes = []

class TxPacket(Packet):
    type = "tx"
    def __init__(self):
        self._hash = None
        self.inputs = []
        self.outputs = []
        self.lock_time = 0

    def parse(self, payload):
        Packet.parse(self, payload)
        
        self.version, = struct.unpack("<I", payload.read(4))
        txInputCount = decodeVarLength(payload)
        for _i in range(0,txInputCount):
            prev_out = (payload.read(32)[::-1], struct.unpack("<I", payload.read(4))[0])
            script_length = decodeVarLength(payload)
            script = payload.read(script_length)
            sequence, = struct.unpack("<I", payload.read(4))
            self.inputs.append((prev_out, script, sequence))
            
        txOutputCount = decodeVarLength(payload)
        for _i in range(0, txOutputCount):
            value, = struct.unpack("<Q", payload.read(8))
            script = decodeVarString(payload)
            self.outputs.append((value, script))
        self.lock_time, = struct.unpack("<I", payload.read(4))
        
    def toWire(self, buf):
        Packet.toWire(self, buf)
        buf.write(struct.pack("<I", self.version))
        buf.write(encodeVarLength(len(self.inputs)))
        for i in self.inputs:
            prev_out, script, sequence = i 
            buf.write(prev_out[0][::-1])
            buf.write(struct.pack("<I", prev_out[1]))
            buf.write(encodeVarString(script))
            buf.write(struct.pack("<I", sequence))
            
        buf.write(encodeVarLength(len(self.outputs)))
        for o in self.outputs:
            value, script = o
            buf.write(struct.pack("<Q", value))
            buf.write(encodeVarString(script))
            
        buf.write(struct.pack("<I", self.lock_time))
        
        
        #buf.write(self.binrep)
    
    def __len__(self):
        buf = BytesIO()
        self.toWire(buf)
        return len(buf.getvalue())
    
    def hash(self):
        """
        If we have the hash saved from a parsing action we just return it
        otherwise we serialize this transaction and calculate the 2xSha256.
        If the hash is derived from a serialization we do not cache the result
        should happen rarely though.
        """
        if self._hash:
            return self._hash
        else:
            buf = BytesIO()
            self.toWire(buf)
            return doubleSha256(buf.getvalue())[::-1]
        
class BlockPacket(Packet):
    type = "block"
    def __init__(self):
        self._hash = None
        self.version = 1
        self.prev_block = None
        self.merkle_root = None
        self.timestamp = time()
        self.bits = None
        self.nonce = None
        self.transactions = []

    def parse(self, payload):
        Packet.parse(self, payload)
        # TODO this is just a shortcut for now
        self.binrep = payload.getvalue()
        
        self.version, self.prev_block, self.merkle_root = struct.unpack("<I32s32s", payload.read(68))
        self.prev_block = self.prev_block[::-1]
        self.merkle_root = self.merkle_root[::-1]
        self.timestamp, self.bits, self.nonce = struct.unpack("<III", payload.read(12))
        transactionCount = decodeVarLength(payload)
        while len(self.transactions) < transactionCount:
            t = TxPacket()
            t.parse(payload)
            self.transactions.append(t)
        self._hash = doubleSha256(payload.getvalue()[:80])[::-1]
        
    def toWire(self, buf):
        Packet.toWire(self, buf)
        buf.write(struct.pack("<I32s32sIII", self.version, self.prev_block[::-1], self.merkle_root[::-1], self.timestamp, self.bits, self.nonce))
        buf.write(encodeVarLength(len(self.transactions)))
        for t in self.transactions:
            t.toWire(buf)
        #buf.write(self.binrep)
        
        
    def hash(self):
        """
        If we have the hash saved from a parsing action we just return it
        otherwise we serialize this transaction and calculate the 2xSha256.
        If the hash is derived from a serialization we do not cache the result
        should happen rarely though.
        """
        if self._hash:
            return self._hash
        else:
            buf = BytesIO()
            self.toWire(buf)
            return doubleSha256(buf.getvalue()[:80])[::-1]


class AddrPacket(Packet):
    type = "addr"
    def __init__(self):
        self.addresses = []
    
    def parse(self, payload):
        l = decodeVarLength(payload)
        for _ in range(0,l):
            a = Address()
            a.parse(payload)
            self.addresses.append(a)
            
    def toWire(self, buf):
        buf.write(encodeVarLength(len(self.addresses)))
        for a in self.addresses:
            a.toWire(buf)
