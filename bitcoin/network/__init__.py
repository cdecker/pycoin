from io import BytesIO
import threading
import struct
import gevent
from gevent import pool
from gevent import event
from gevent import socket
import hashlib

__author__ = 'cdecker'

from bitcoin.messages import parsers
from bitcoin import messages
import logging


MAGIC = 'D9B4BEF9'.decode("hex")[::-1]
VERSION = 70001
SERVICES = 1
USER_AGENT = "/Snoopy:0.1/"


def checksum(payload):
    return doubleSha256(payload)[:4]


def doubleSha256(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


class ConnectionEvent(messages.Packet):
    """Superclass for a few connection based events."""


class ConnectionEstablishedEvent(ConnectionEvent):
    type = 'ConnectionEstablishedEvent'


class ConnectionLostEvent(ConnectionEvent):
    type = 'ConnectionLostEvent'


class ConnectionFailedEvent(ConnectionEvent):
    type = 'ConnectionFailedEvent'


class Connection:
    """Base class for connections to another peer."""

    def __init__(self, network_client, host, incoming=False):
        self.network_client = network_client
        self.connected = False
        self.incoming = incoming
        self.host = host
        self.version = None

    def disconnect(self):
        """Close the connection."""
        raise NotImplementedError()

    def send(self, message_type, payload):
        raise NotImplementedError()

    def parse_message(self, msg_type, payload):
        """ Look up parser for msg_type and use it to parse payload.

        :param msg_type:
        :param payload:
        :return:
        """
        parser = parsers.get(msg_type)
        if not parser:
            logging.debug('No parser found for message of type %s', msg_type)
            return None
        else:
            packet = parser()
            packet.parse(payload, self.version)
            return packet

    def serialize_message(self, message_type, payload):
        if not isinstance(payload, str):
            buf = BytesIO()
            payload.toWire(buf, self.version)
            payload = buf.getvalue()
        message = MAGIC
        message += message_type.ljust(12, chr(0))
        message += struct.pack("<I", len(payload))
        message += checksum(payload)
        message += payload
        return message


class NetworkClient(object):
    """Class managing a number of connections to peers."""

    connection_class = Connection

    def __init__(self):
        super(NetworkClient, self).__init__()
        self.lock = threading.Lock()
        self.connections = {}
        self.handlers = {}
        self.register_handler(messages.VersionPacket.type, self.handle_version)

    def connect(self, host, timeout=10):
        """Open a connection to a peer.

        Method is asynchronous, returns a connection that is currently being
        connected.
        """
        logging.debug('Connecting to %s:%d', host[0], host[1])
        with self.lock:
            if host in self.connections:
                raise ValueError('Attempting to open a duplicate connection to '
                                 '%s:%d' % (host[0], host[1]))
            connection = self.connection_class(self, host, incoming=False)
            self.connections[host] = connection
            return connection

    def disconnect(self, host):
        """Close the connection to the peer."""
        logging.debug('Disconnecting from %s:%d', host[0], host[1])
        with self.lock:
            connection = self.connections.get(host)
            if not connection:
                raise ValueError('Attempting to close a non-existent connection'
                                 ' to %s:%d' % (host[0], host[1]))
            del self.connections[host]
        connection.disconnect()

    def handle_message(self, connection, message):
        """Dispatch incoming message to handler."""
        for handler in self.handlers.get(message.type, []):
            try:
                handler(connection, message)
            except Exception as e:
                logging.warn('Error while invoking handler %r for message of '
                             'type %s (%r)', handler, message.type, e,
                             exc_info=True)

    def register_handler(self, msg_type, handler):
        """Register a handler-function for messages of type msg_type.

        The handler will be called for each message of type msg_type that is
        received by any connection.

        Args:
            msg_type: str, the type of the message to register for.
            handler: func, a function accepting a connection and a parsed
                message as arguments.
        """
        if msg_type not in self.handlers:
            self.handlers[msg_type] = []
        self.handlers[msg_type].append(handler)

    def handle_version(self, connection, version):
        connection.version = version.version

    def run_forever(self):
        """Start the reactor and start processing messages."""
        raise NotImplementedError()


class MessageHandler(object):
    """Behavioral unit that can be attached to a NetworkClient.

    The aim of this class is to be a superclass for other classes that implement
    some behavior. For example a PoolMaintainer will listen for incoming `addr`
    messages, keep track of potential peers and react to connection and
    disconnection events in order to maintain a given pool of open connections.
    """


class BaseBehavior(MessageHandler):

    def handle_connect(self, connection, message):
        if connection.incoming:
            connection.send('version')


class GeventConnection(Connection):
    """Connection implementation using gevent.
    """

    def __init__(self, network_client, host, incoming):
        Connection.__init__(self, network_client, host, incoming)
        self.socket = None
        self.lock = gevent.lock.RLock()

    def connect(self, timeout=10):
        try:
            self.socket = socket.create_connection(self.host, timeout=timeout)
            self.socket.settimeout(None)
            self.connected = True
            self.network_client.handle_message(
                self, ConnectionEstablishedEvent()
            )
        except socket.error as e:
            self.network_client.handle_message(self, ConnectionFailedEvent())
            del self.network_client.connections[self.host]

    def connect_and_run(self, timeout=10):
        self.connect(timeout)
        if self.connected:
            self.run()

    def run(self):
        try:
            while self.socket and self.connected:
                message = self.read_message()
                if message:
                    self.network_client.handle_message(self, message)
        except (socket.error, ValueError):
            pass
        self.connected = False
        del self.network_client.connections[self.host]
        logging.debug('Connection to %s:%d closed.', self.host[0], self.host[1])
        self.network_client.handle_message(self, ConnectionLostEvent())

    def send(self, message_type, payload=''):
        """Utility method to calculate the checksum, the payload length and
        combine everything into a nice package.
        """
        message = self.serialize_message(message_type, payload)
        with self.lock:
            self.socket.send(message)

    def read(self, length):
        """Read exactly read_len bytes or raise ValueError.

        gevent does not like allocating arbitrary size buffers. We need to
        reassemble it here, otherwise large packets kill the connection.
        """
        payload = BytesIO()
        read_len = 0
        while read_len < length:
            b = self.socket.recv(length - read_len)
            l = len(b)
            if not l:
                raise ValueError('Short read from socket (%d != %d)'
                                 % (length, len(b)))
            read_len += l
            payload.write(b)
        payload.seek(0)
        return payload

    def read_message(self):
        header = self.read(24)

        magic, command, length, unused_checksum = struct.unpack(
            "<4s12sII", header.getvalue())
        if MAGIC != magic:
            raise ValueError('Message separator magic did not match protocol '
                             '(%s)' % magic.encode('hex'))
        payload = self.read(length)

        command = command.strip('\x00')
        message = self.parse_message(command, payload)
        return message

    def disconnect(self):
        self.connected = False
        #self.socket.shutdown(socket.SHUT_RD)
        self.socket.close()


class GeventNetworkClient(NetworkClient):
    """Implementation using gevent.
    """

    connection_class = GeventConnection

    def __init__(self):
        NetworkClient.__init__(self)
        self.shutdown_event = event.Event()
        self.connection_group = pool.Group()

    def connect(self, host, timeout=10):
        connection = super(GeventNetworkClient, self).connect(host)
        g = gevent.spawn(connection.connect_and_run, timeout)
        connection.greenlet = g
        self.connection_group.add(g)
        return connection

    def run_forever(self):
        self.connection_group.join()


class ClientBehavior(object):
    def __init__(self, network_client):
        network_client.register_handler(
            ConnectionEstablishedEvent.type, self.on_connect
        )
        network_client.register_handler(
            messages.VersionPacket.type, self.send_verack
        )

    def on_connect(self, connection, unused_message):
        if not connection.incoming:
            self.send_version(connection)

    def on_version(self, connection, unused_message):
        if connection.incoming:
            self.send_version(connection)

    def send_version(self, connection):
        v = messages.VersionPacket()
        v.addr_from = messages.Address('127.0.0.1', True, 8333, 1)
        v.addr_recv = messages.Address(connection.host[0], True,
                                       connection.host[1], 1)
        v.best_height = 0
        connection.send('version', v)

    def send_verack(self, connection, unused_message):
        connection.send('verack', '')

