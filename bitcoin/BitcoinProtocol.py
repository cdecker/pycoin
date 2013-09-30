'''
Created on Jul 9, 2012

@author: cdecker
'''
from twisted.internet.protocol import ClientFactory
from twisted.internet.protocol import Protocol
from io import BytesIO
from twisted.internet import reactor

mainnetMagic = "D9B4BEF9".decode("hex")[::-1]
testnetMagic = "DAB5BFFA".decode("hex")[::-1]
IPv4_prefix = "00000000000000000000FFFF".decode("hex")
protocol_version = 60001
protocol_services = 1
protocol_user_agent = "/Snoopy:0.1/"
import urllib
import re
import logging
from time import time

from messages import BlockPacket, TxPacket, Address, VersionPacket, InvPacket, AddrPacket
from utils import checksum
import struct

class BitcoinProtocolFactory(ClientFactory):
    """
    Implements all the necessary abstractions needed to keep track of open
    connections and has callbacks for all relevant actions observable on
    the network.
    """
    
    def __init__(self, port=8333):
        self.logger = logging.getLogger(__name__)
        self.logger.info("Starting")
        self.port = port
        # An associative dict for all the connections indexed by the (IP, port)
        # tuple of the connection
        self.connections = {}
        
        self.best_height = 0
        
        # Get my external IP so I can announce it correctly hereon
        self.external_ip = re.search("(\d+\.\d+\.\d+\.\d+)", urllib.urlopen("http://checkip.dyndns.com/").read()).groups(0)[0]
        self.logger.debug("External IP: %s", self.external_ip)
        
        self.protocol = BitcoinClientProtocol
        LoopingCall(self._sendAddr).start(60, False)
    
    def _sendAddr(self):
        addr = AddrPacket()
        a = Address()
        a.ip = self.external_ip
        a.isIPv4 = True
        a.port = self.port
        a.services = 1
        a.timestamp = time()
        addr.addresses.append(a)
        buf = BytesIO()
        addr.toWire(buf)
        self.broadcast("addr", addr)
    
    def buildProtocol(self, addr):
        addrT = (addr.host, addr.port)
        #if str(addrT[0]) in self.connections.keys():
        #    raise Exception("Connection to %s:%d already opened, refusing to open multiple connections" % addrT)
        connection = self.protocol(addrT)
        self.connections[connection.key] = connection
        connection.factory = self
        return connection
    
    def broadcast(self, packetType, payload, exclude = []):
        """
        Send the packet to all connected clients.
        Exclude allows to specify connections either by their object or by
        their address tuple that are to be excluded. Reasons for this include
        them being the source of the original message.
        """
        for c in self.connections.values():
            if c in exclude or c.addrT in exclude:
                continue
            c._send(packetType, payload)
    
    def clientConnectionLost(self, connector, reason):
        ClientFactory.clientConnectionLost(self, connector, reason)
        del(self.connections[str(connector.host)])
        
    def clientConnectionFailed(self, connector, reason):
        ClientFactory.clientConnectionFailed(self, connector, reason)
    
from sets import Set
from functools import partial
import random, socket
from twisted.internet.task import LoopingCall

class PooledBitcoinProtocolFactory(BitcoinProtocolFactory):
    """
    A BitcoinProtocolFactory that attempts to keep a given number of
    connections open at all times.
    """
    def __init__(self, pool_size=100, port=8333, dns_bootstrap = True):
        BitcoinProtocolFactory.__init__(self, port=port)
        self.pool_size = pool_size
        self.open_connections = Set()
        self.unreachable_peers = Set()
        self.known_peers = Set()

        if dns_bootstrap:
            self.known_peers |= dnsBootstrap()
            self.logger.info("I now know %d distinct peers", len(self.known_peers))
            
        LoopingCall(self.poolMaintenance).start(15, True)
    
        
        
    def buildProtocol(self, addr):
        connection = BitcoinProtocolFactory.buildProtocol(self, addr)
        connection.handlers["verack"].append(partial(self.handleVerack, connection))
        connection.handlers["addr"].append(partial(self.handleAddr, connection))
        return connection
        
    def connect(self, hostT):
        """
        Open a new connection to a given (host, port)
        """
        self.logger.debug("Opening a new connection to %s", hostT)
        self.open_connections |= Set([hostT])
        reactor.connectTCP(hostT[0], hostT[1], self, timeout=300) #@UndefinedVariable
        
    def handleAddr(self, connection, addr):
        """
        """
        temp = []
        for a in addr.addresses:
            temp.append((a.ip, a.port))
        self.known_peers |= Set(temp)
    
    def handleVerack(self, connection, verack):
        connection._send("getaddr","")
    
    def poolMaintenance(self):
        self.logger.debug("Current connection pool: %d connections, %d known peers, %d marked as unreachable", len(self.open_connections), len(self.known_peers), len(self.unreachable_peers))
        if len(self.open_connections) >= self.pool_size:
            return
        available_peers = self.known_peers - self.open_connections - self.unreachable_peers
        if len(available_peers) < 1:
            self.logger.debug("No more peers available for connection")
        for c in random.sample(available_peers,min(len(available_peers), 20, self.pool_size - len(self.open_connections))):
            self.connect(c)
    
    def clientConnectionLost(self, connector, reason):
        BitcoinProtocolFactory.clientConnectionLost(self, connector, reason)
        self.open_connections -= Set([(connector.host, connector.port)])
        self.poolMaintenance()
    
    def clientConnectionFailed(self, connector, reason):
        BitcoinProtocolFactory.clientConnectionFailed(self, connector, reason)
        connectionId = Set([(connector.host, connector.port)])
        self.open_connections -= connectionId
        self.unreachable_peers |= connectionId
        #self.poolMaintenance()

class BitcoinClientProtocol(Protocol):
    '''
    classdocs
    '''
    
    def __init__(self, addrT):
        '''
        Constructor
        '''
        self.addrT = addrT
        self.key = str(addrT[0])
        self.buf = ""
        self.incoming = (addrT[1] != 8333)
        self.message_len = -1
        self.last_message = time()
        self.bytes_in = 0
        self.bytes_out = 0
        self.parsers = {
                        "version": self.parseVersion,
                        "inv": self.parseInv,
                        "tx": self.parseTx,
                        "block": self.parseBlock,
                        "getdata": self.parseGetData,
                        }
        self.handlers = {
                         "version": [self.handleVersion],
                         "verack": [],
                         "inv": [self.handleInv],
                         "addr": [],
                         "block": [],
                         "tx": [],
                         "getdata": [],
                         "getaddr": [],
                         }
        self.logger = logging.getLogger(__name__)
        
    def connectionLost(self, reason):
        Protocol.connectionLost(self, reason=reason)
    
    def connectionMade(self):
        if not self.incoming:
            # Make sure we send a handshake
            self.sendVersion()
        
    def dataReceived(self, data):
        #Protocol.dataReceived(self, data)
        self.buf += data
        self.bytes_in += len(data)
        if self.message_len == -1 and len(self.buf) >= 24:
            # We want to read the header of the next message and we have enough
            if self.buf[:4] != mainnetMagic:
                self.transport.loseConnection()
                raise Exception("Connection magic did not match")
            self.command = self.buf[4:16].strip(chr(0))
            self.message_len, = struct.unpack("<I", self.buf[16:20])
            self.buf = self.buf[24:]
        
        if self.message_len > -1 and self.message_len <= len(self.buf):
            # We have collected enough and can now parse the message as a whole
            message = BytesIO(self.buf[:self.message_len])
            self.buf = self.buf[self.message_len:]
            
            self.logger.debug("Got a '%s' message (%d bytes)", self.command, self.message_len)
            
            # Deprecated
            packet = message
            if self.command in self.parsers.keys():
                packet = self.parsers[self.command](message)
            # Use this instead
            if self.command in ["addr"]:
                packet = self.parsePacket("addr", message)
            if self.command in self.handlers.keys():
                for handler in self.handlers[self.command]:
                    handler(packet)
                
            
            self.message_len = -1
            if len(self.buf) > 24:
                # We have another header queued, just process it now
                self.dataReceived("")
            self.last_message = time()
        
    def sendVersion(self):
        v = VersionPacket()
        v.addr_from = Address(self.factory.external_ip, True, self.factory.port, 1)
        v.addr_recv = Address(self.addrT[0], True, self.addrT[1], 1)
        v.best_height = self.factory.best_height
        self._send("version", v)
        
    def sendVerack(self):
        self._send("verack", "")
        #self.sendPing()
    
    def sendPing(self):
        """
        Used to send a ping message at regular intervals
        """
        self._send("ping", "")
        #reactor.callLater(300, self.sendPing) #@UndefinedVariable
    
    def _send(self, packetType, payload):
        """
        Utility method to calculate the checksum, the payload length and combine
         everything into a nice package.
        """
        if not isinstance(payload, str):
            buf = BytesIO()
            payload.toWire(buf)
            payload = buf.getvalue()
        message = mainnetMagic
        message += packetType.ljust(12, chr(0))
        message += struct.pack("<I", len(payload))
        message += checksum(payload)
        message += payload
        self.bytes_out += len(message)
        self.transport.write(message)
    
    def parsePacket(self, packetType, message):
        if packetType == "addr":
            res = AddrPacket()
        res.parse(message)
        return res
    
    def parseVersion(self, message):
        v = VersionPacket()
        v.parse(message)
        return v
    
    def parseGetData(self, message):
        gd = InvPacket()
        gd.parse(message)
        return gd
    
    def parseInv(self, message):
        i = InvPacket()
        i.parse(message)
        return i
    
    def parseTx(self, message):
        t = TxPacket()
        t.parse(message)
        return t
    
    def parseBlock(self, message):
        b = BlockPacket()
        b.parse(message)
        return b
    
    def handleVersion(self, packet):
        self.logger.info("Connected to %s:%d, Protocol version %d, User Agent '%s', Incoming %s", self.addrT[0], self.addrT[1], packet.version, packet.user_agent, str(self.incoming))
        if self.incoming:
            self.sendVersion()
        self.sendVerack()
        
    def handleInv(self, packet):
        # Simply request all the announced stuff
        #self._send("getdata", packet)
        pass
    def __str__(self):
        return '%s:%d' % self.addrT


def dnsBootstrap():
    peers = []
    for seed in [
        #"seed.bitcoin.sipa.be",
        #"dnsseed.bluematt.me",
        "dnsseed.bitcoin.dashjr.org",
        "bitseed.xf2.org"
        ]:
        try:
            dns_info = socket.getaddrinfo(seed, None)
            for entry in dns_info:
                peers.append((entry[4][0], 8333))
        except:
            pass
    return Set(peers)
