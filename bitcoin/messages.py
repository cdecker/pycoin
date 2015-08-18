"""
Created on Jul 13, 2012

@author: cdecker
"""
from time import time
import six
import struct
import socket
from io import BytesIO

from bitcoin.utils import decodeVarLength, decodeVarString, encodeVarLength, \
    encodeVarString, doubleSha256


PROTOCOL_VERSION = 60001
MIN_PROTOCOL_VERSION = 60001
IPV4_PREFIX = "00000000000000000000FFFF".decode("hex")
USER_AGENT = "/Snoopy:0.1/"
PROTOCOL_SERVICES = 1


class Packet(object):
    """Superclass of all packets that are sent/received by bitcoin."""
    type = None

    def parse(self, payload, version):
        """
        This should be implemented by each packet in order to parse the
        contents of a message
        """

    def toWire(self, buf, version):
        """
        This should be implemented by the subclasses
        Writes the packet to the buffer
        """

    def __len__(self):
        buf = six.BytesIO()
        self.toWire(buf, PROTOCOL_VERSION)
        return len(buf.getvalue())


class Address(Packet):
    """
    Not really a packet on its own but as it is serialized on several occasions
    we just implement it as such.
    """
    type = None

    def __init__(self, ip=None, isIPv4=True, port=8333,
                 services=PROTOCOL_SERVICES, timestamp=None):
        self.isIPv4 = isIPv4
        if ip:
            self.ip = socket.gethostbyname(ip)
        else:
            self.ip = None
        self.timestamp = timestamp
        self.port = port
        self.services = services

    def parse(self, payload, version):
        Packet.parse(self, payload, version)
        if version >= 31402:
            self.timestamp, = struct.unpack_from("<I", payload.read(4))
        self.services, ip = struct.unpack_from("<Q16s", payload.read(24))
        (self.port,) = struct.unpack_from(">H", payload.read(2))
        if ip[:12] == IPV4_PREFIX:
            self.isIPv4 = True
            self.ip = socket.inet_ntop(socket.AF_INET, ip[12:])
        else:
            self.isIPv4 = False
            self.ip = socket.inet_ntop(socket.AF_INET6, ip)

    def toWire(self, buf, version):
        Packet.toWire(self, buf, version)
        if version >= 31402:
            buf.write(struct.pack("<I", self.timestamp))
        buf.write(struct.pack("<Q", self.services))
        if self.isIPv4:
            buf.write(IPV4_PREFIX)
            buf.write(socket.inet_pton(socket.AF_INET, self.ip))
        else:
            buf.write(socket.inet_pton(socket.AF_INET6, self.ip))
        buf.write(struct.pack(">H", self.port))


class VersionPacket(Packet):
    type = "version"

    def __init__(self):
        self.timestamp = time()
        self.services = PROTOCOL_SERVICES
        self.version = PROTOCOL_VERSION
        self.nonce = "__ETHZ__"
        self.user_agent = USER_AGENT
        self.best_height = 0
        self.relay = True
        self.addr_from = None
        self.addr_recv = None

    def parse(self, payload, unused_version=None):
        Packet.parse(self, payload, unused_version)
        self.version, self.services, self.timestamp = struct.unpack(
            "<IQQ", payload.read(20))
        version = self.version
        if version >= 106:
            self.addr_recv = Address()
            self.addr_recv.parse(payload, False)
            self.addr_from = Address()
            self.addr_from.parse(payload, False)
            self.nonce = payload.read(8)
            self.user_agent = decodeVarString(payload)
            self.best_height, = struct.unpack("<I", payload.read(4))
        if version >= 70001:
            relay_flag, = struct.unpack('B', payload.read(1))
            self.relay = bool(relay_flag & 1)

    def toWire(self, buf, unused_version):
        Packet.toWire(self, buf, unused_version)
        buf.write(struct.pack("<IQQ", self.version, self.services,
                              self.timestamp))
        self.addr_recv.toWire(buf, False)
        self.addr_from.toWire(buf, False)
        buf.write(self.nonce)
        buf.write(encodeVarString(self.user_agent))
        buf.write(struct.pack("<I", self.best_height))


class InvPacket(Packet):
    type = "inv"

    def __init__(self):
        self.hashes = []

    def parse(self, payload, unused_version):
        length = decodeVarLength(payload)
        while len(self.hashes) < length:
            t, = struct.unpack("<I", payload.read(4))
            h = payload.read(32)[::-1]
            self.hashes.append((t, h))

    def toWire(self, buf, unused_version):
        buf.write(encodeVarLength(len(self.hashes)))
        for h in self.hashes:
            buf.write(struct.pack("<I", h[0]))
            buf.write(h[1][::-1])


class GetDataPacket(InvPacket):
    type = 'getdata'


class PingPacket(Packet):
    type = 'ping'

    def __init__(self):
        self.nonce = None

    def parse(self, payload, version):
        if payload:
            self.nonce = payload

    def toWire(self, buf, unused_version):
        if self.nonce:
            buf.write(self.nonce)


class PongPacket(PingPacket):
    """Response to ping."""


class TxPacket(Packet):
    type = "tx"

    def __init__(self):
        self._hash = None
        self.inputs = []
        self.outputs = []
        self.lock_time = 0
        self.version = 1

    def parse(self, payload, version):
        Packet.parse(self, payload, version)

        self.version, = struct.unpack("<I", payload.read(4))
        txInputCount = decodeVarLength(payload)
        for _i in range(0, txInputCount):
            prev_out = (
                payload.read(32)[::-1],
                struct.unpack("<I", payload.read(4))[0]
            )
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

    def toWire(self, buf, version):
        Packet.toWire(self, buf, version)
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

    def hash(self):
        """
        If we have the hash saved from a parsing action we just return it
        otherwise we serialize this transaction and calculate the 2xSha256.
        If the hash is derived from a serialization we do not cache the result
        should happen rarely though.
        """
        buf = BytesIO()
        self.toWire(buf, PROTOCOL_VERSION)
        return doubleSha256(buf.getvalue())[::-1]

    def is_coinbase(self):
        return (len(self.inputs) == 1 and
                self.inputs[0][0][0] == '\0'*32 and
                self.inputs[0][0][1] == 4294967295)

    def normalized_hash(self):
        if self.is_coinbase():
            return self.hash()
        else:
            copy = TxPacket()
            buf = BytesIO()
            self.toWire(buf, None)
            copy.parse(BytesIO(buf.getvalue()), None)

            for pos, iput in enumerate(copy.inputs):
                copy.inputs[pos] = (iput[0], "", iput[2])
            buf = BytesIO()
            copy.toWire(buf, None)
            buf.write(struct.pack('<I', 1))
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

    def parse(self, payload, version):
        Packet.parse(self, payload, version)

        self.version, self.prev_block, self.merkle_root = struct.unpack(
            '<I32s32s', payload.read(68))
        self.prev_block = self.prev_block[::-1]
        self.merkle_root = self.merkle_root[::-1]
        self.timestamp, self.bits, self.nonce = struct.unpack(
            '<III', payload.read(12))
        transactionCount = decodeVarLength(payload)
        while len(self.transactions) < transactionCount:
            t = TxPacket()
            t.parse(payload, version)
            self.transactions.append(t)
        self._hash = doubleSha256(payload.getvalue()[:80])[::-1]

    def toWire(self, buf, version):
        Packet.toWire(self, buf, version)
        buf.write(struct.pack("<I32s32sIII",
                              self.version,
                              self.prev_block[::-1],
                              self.merkle_root[::-1],
                              self.timestamp,
                              self.bits,
                              self.nonce))
        buf.write(encodeVarLength(len(self.transactions)))
        for t in self.transactions:
            t.toWire(buf, version)

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
            self.toWire(buf, PROTOCOL_VERSION)
            return doubleSha256(buf.getvalue()[:80])[::-1]


class AddrPacket(Packet):
    type = "addr"

    def __init__(self):
        self.addresses = []

    def parse(self, payload, version):
        l = decodeVarLength(payload)
        for _ in range(0, l):
            a = Address()
            a.parse(payload, version)
            self.addresses.append(a)

    def toWire(self, buf, version):
        buf.write(encodeVarLength(len(self.addresses)))
        for a in self.addresses:
            a.toWire(buf, version)


class VerackMessage(Packet):
    type = 'verack'


parsers = {
    AddrPacket.type: AddrPacket,
    TxPacket.type: TxPacket,
    PongPacket.type: PongPacket,
    InvPacket.type: InvPacket,
    GetDataPacket.type: GetDataPacket,
    BlockPacket.type: BlockPacket,
    VersionPacket.type: VersionPacket,
    VerackMessage.type: VerackMessage,
}
