'''
Rather simple wrapper around the Twisted callback version until we have time
to migrate the BitcoinClientProtocol using gevent.

Created on Dec 15, 2013

@author: cdecker
'''

#from gevent.server import StreamServer
#from gevent.socket import create_connection
import struct
from utils import checksum

from bitcoin.messages import GetDataPacket, BlockPacket, TxPacket, InvPacket,\
    VersionPacket
from _pyio import BytesIO

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
}

class Connection(object):
    
    def __init__(self, socket, address, incoming=False):
        self.address = address
        self.socket = socket
        self.incoming = incoming
        self.handlers = {
                         "ping": [self.handle_ping]
                         }
        
    def run(self):
        if not self.incoming:
            # We have to send a version message first
            pass
        
        while True:
            command = self.read_command()
            if command == None:
                continue
            for h in self.handlers.get(command.type, []):
                h(self, command)
        
    def read_command(self):
        header = self.socket.recv(24)
        if header < 24:
            raise ConnectionLostException()
        
        # Drop the checksum for now
        magic, command, length, _ = struct.unpack("<4s12sII", header)
        if network_params['magic'] != magic:
            raise ConnectionLostException()
        
        payload = self.socket.recv(length)
        if len(payload) < length:
            raise ConnectionLostException()
        
        command = command.strip("\x00")
        if command not in parsers.keys():
            return None
        packet = parsers[command.strip()]()
        packet.parse(BytesIO(payload))
        return packet
        
    def handle_ping(self):
        pass
    
    def _send(self, packetType, payload):
        """
        Utility method to calculate the checksum, the payload length and combine
        everything into a nice package.
        """
        if not isinstance(payload, str):
            buf = BytesIO()
            payload.toWire(buf)
            payload = buf.getvalue()
        message = network_params['magic']
        message += packetType.ljust(12, chr(0))
        message += struct.pack("<I", len(payload))
        message += checksum(payload)
        message += payload
        self.bytes_out += len(message)
        self.socket.send(message)