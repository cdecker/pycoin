'''
Rather simple wrapper around the Twisted callback version until we have time
to migrate the BitcoinClientProtocol using gevent.

Created on Dec 15, 2013

@author: cdecker
'''

#from gevent.server import StreamServer
from gevent import socket, spawn_later, spawn
import struct
import time
#from gevent.socket import create_connection
#from gevent import socket as gsocket

from bitcoin.messages import GetDataPacket, BlockPacket, TxPacket, InvPacket,\
    VersionPacket, Address, AddrPacket
from _pyio import BytesIO
from bitcoin.BitcoinProtocol import get_external_ip, serialize_packet, dnsBootstrap
from gevent.pool import Group
import random
import gevent

class ConnectionLostException(Exception):
    pass

network_params = {
    "magic": "D9B4BEF9".decode("hex")[::-1],
    "port": 8333,
}

parsers = {
           "version": VersionPacket,
           "inv": InvPacket,
           "tx": TxPacket,
           "block": BlockPacket,
           "getdata": GetDataPacket,
           "addr": AddrPacket,
}

class Connection(object):
    
    def __init__(self, address, client, incoming=False, socket=None):
        self.address = address
        self.socket = socket
        self.incoming = incoming
        self.client = client
        self.bytes_out = 0
        self.bytes_in = 0
        self.version = None
        self.handlers = {
                         "ping": [],
                         "inv": [],
                         "addr": [],
                         "block": [],
                         "tx": [],
                         "version": [self.on_version_message],
                         # Virtual events for connection and disconnection
                         "connect": [],
                         "disconnect": [],
                         }
        
    def connect(self, timeout=5):
        self.socket = socket.create_connection(self.address,timeout=timeout)
        self.socket.settimeout(None)
        self.connected = True
        for h in self.handlers.get("connect", []):
            h(self)

    def send_ping(self):
        if not self.connected:
            return
        gevent.spawn_later(30, self.send_ping)
        self._send("ping", "12345678")
        self.version.addr_recv.timestamp = time.time()
        addr = AddrPacket()
        addr.addresses = [self.version.addr_recv]
        self._send("addr", addr)

    def on_version_message(self, connection, version):
        self.version = version
        self._send("verack")
        self.send_ping()

    def connect_and_run(self, timeout=10):
        try:
            self.connect(timeout)
            self.run()
        except Exception as e:
            self.terminate(e)
            raise
        
    def run(self):
        try:
            if not self.socket:
                raise Exception("Not connected")

            if not self.incoming:
                # We have to send a version message first
                self.send_version()
        
            while self.connected:
                command = self.read_command()
                if command == None:
                    continue
                for h in self.handlers.get(command.type, []):
                    h(self, command)
        except Exception as e:
            self.terminate(e)
            raise

    def terminate(self, reason):
        self.connected = False
        if self.socket and not self.socket.closed:
            self.socket.close()
        for h in self.handlers.get("disconnect", []):
            h(self, reason)
        self.client.remove_connection(self)        
        
    def read_command(self):
        header = self.socket.recv(24)

        if len(header) < 24:
            raise ConnectionLostException("Underread header on connection %s:%d %d bytes read" % (self.address[0], self.address[1], len(header)))
        
        # Drop the checksum for now
        magic, command, length, _ = struct.unpack("<4s12sII", header)
        if network_params['magic'] != magic:
            raise ConnectionLostException()
        
        # gevent does not like allocating arbitrary size buffers. We need to
        # reassemble it here, otherwise large packets kill the connection.
        payload = ""
        while len(payload) < length:
            b = self.socket.recv(length - len(payload))
            if len(b) == 0:
                raise ConnectionLostException("Underread payload: should be %d bytes, was %d" % (length, len(payload)))
            payload += b 

        command = command.strip("\x00")
        if command not in parsers.keys():
            return None
        packet = parsers[command.strip()]()
        packet.parse(BytesIO(payload))
        return packet
        
    def handle_ping(self):
        pass
    
    def send_version(self):
        v = VersionPacket()
        v.addr_from = Address(self.client.external_ip, True, self.client.port, 1)
        v.addr_recv = Address(self.address[0], True, self.address[1], 1)
        v.best_height = 0
        self._send("version", v)
    
    def _send(self, packetType, payload=""):
        """
        Utility method to calculate the checksum, the payload length and combine
        everything into a nice package.
        """
        message = serialize_packet(packetType, payload, network_params)
        self.bytes_out += len(message)
        self.socket.send(message)

class NetworkClient(object):
    """
    Class that collects all the necessary meta information about this client. 
    """
    protocol = Connection
    
    def __init__(self):
        self.external_ip = get_external_ip()
        self.port = 8333
        self.connections = {}
        self.connection_group = Group()

    def connect(self, host):
        c = self.protocol(host, self)
        g = gevent.spawn(c.connect_and_run)
        self.connection_group.add(g)
        self.connections[host] = c
        return c
    
    def join(self):
        self.connection_group.join()
    
    def remove_connection(self, connection):
        self.connections.pop(connection.address, None)

class PooledNetworkClient(NetworkClient):
    def __init__(self, pool_size=500):
        NetworkClient.__init__(self)
        self.pool_size = pool_size
        self.open_connections = set()
        self.unreachable_peers = set()
        self.known_peers = set()
        self.connection_group.add(spawn(self.pool_maintenance))
        # TODO implement
        
    def connect(self, host):
        """
        Patch into connection creation in order to catch addr messages.
        """
        self.open_connections |= set([host])
        c = NetworkClient.connect(self, host)
        c.handlers['addr'].append(self.on_addr_message)
        c.handlers['disconnect'].append(self.on_disconnect)
        return c
    
    def on_disconnect(self, connection, reason):
        self.open_connections -= set([connection.address])
        # TODO distinguish whether this is a failure or regular closure
        if not isinstance(reason, ConnectionLostException):
            self.unreachable_peers |= set([connection.address])
    
    def on_addr_message(self, connection, message):
        self.known_peers |= set([(a.ip, a.port) for a in message.addresses])
        
    def pool_maintenance(self):
        self.connection_group.add(spawn_later(10, self.pool_maintenance))
        
        # Select a random connection and ask the peer `getaddr`
        try:
            if len(self.connections) > 1:
                c = random.choice(self.connections.values())
                c._send("getaddr")
        except:
            pass
        
        if len(self.known_peers) == 0:
            self.known_peers |= dnsBootstrap()
        
        print "Current connection pool: %d connections, %d known peers, %d marked as unreachable" % (len(self.open_connections), len(self.known_peers), len(self.unreachable_peers))
        if len(self.open_connections) >= self.pool_size:
            return
        available_peers = self.known_peers - self.open_connections - self.unreachable_peers
        if len(available_peers) < 1:
            print "No more peers available for connection"
        for c in random.sample(available_peers,min(len(available_peers), 20, self.pool_size - len(self.open_connections))):
            self.connect(c)
