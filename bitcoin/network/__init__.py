from bitcoin import messages
from bitcoin.utils import checksum
from six import BytesIO
from gevent import pool
from gevent import event
from gevent import socket
import logging
import threading
import struct
import gevent

__author__ = 'cdecker'
__version__ = '0.2.1'


SERVICES = 1
USER_AGENT = "/Snoopy:%s/" % __version__

mainnet_params = {
    'magic': 'D9B4BEF9'.decode("hex")[::-1],
    'port': 8333,
}

testnet_params = {
    'magic': '0B110907'.decode("hex"),
    'port': 18333,
}

params = mainnet_params

DNS_SEEDS = [
    "seed.bitcoinstats.com",
    "seed.bitcoin.sipa.be",
    "dnsseed.bluematt.me",
    "dnsseed.bitcoin.dashjr.org",
    "bitseed.xf2.org"
]


def configure(new_params):
    global params
    params = new_params


def bootstrap():
    jobs = [gevent.spawn(socket.getaddrinfo, seed, None) for seed in DNS_SEEDS]
    gevent.joinall(jobs, timeout=10)

    # Filter out None results from failed lookups
    results = [j.value for j in jobs if j.value]
    peers = [(v[4][0], 8333) for sublist in results for v in sublist]
    return list(set(peers))


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
        self.bytes_received = 0
        self.bytes_sent = 0

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
        parser = messages.parsers.get(msg_type)
        if not parser:
            logging.debug('No parser found for message of type %s', msg_type)
            packet = messages.DummyPacket()
            packet.parse(payload, self.version)
            packet.type = msg_type
            return packet
        else:
            packet = parser()
            packet.parse(payload, self.version)
            return packet

    def serialize_message(self, message_type, payload):
        if not isinstance(payload, str):
            buf = BytesIO()
            payload.toWire(buf, self.version)
            payload = buf.getvalue()
        message = params['magic']
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
        self.bytes_received = 0
        self.bytes_sent = 0

    def connect(self, host, timeout=10):
        """Open a connection to a peer.

        Method is asynchronous, returns a connection that is currently being
        connected.
        """
        logging.debug('Connecting to %s:%d', host[0], host[1])
        with self.lock:
            if host in self.connections:
                raise ValueError(
                    'Attempting to open a duplicate connection to %s:%d' % (
                        host[0], host[1])
                )
            connection = self.connection_class(self, host, incoming=False)
            self.connections[host] = connection
            return connection

    def disconnect(self, host):
        """Close the connection to the peer."""
        logging.debug('Disconnecting from %s:%d', host[0], host[1])
        with self.lock:
            connection = self.connections.get(host)
            if not connection:
                raise ValueError('Attempting to close a non-existent '
                                 'connection to %s:%d' % (host[0], host[1]))
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
        connection.services = version.services

    def run_forever(self):
        """Start the reactor and start processing messages."""
        raise NotImplementedError()


class MessageHandler(object):
    """Behavioral unit that can be attached to a NetworkClient.

    The aim of this class is to be a superclass for other classes that
    implement some behavior. For example a PoolMaintainer will listen
    for incoming `addr` messages, keep track of potential peers and
    react to connection and disconnection events in order to maintain
    a given pool of open connections.

    """


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
        except socket.error:
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
                if message is not None:
                    self.network_client.handle_message(self, message)
        except socket.error as e:
            logging.warn("Error while reading from socket %s:%d: %r",
                         self.host[0], self.host[1], e)
        except ValueError as e:
            logging.debug("Error while reading from socket %s:%d: %r",
                         self.host[0], self.host[1], e)

        self.connected = False
        del self.network_client.connections[self.host]
        logging.debug(
            'Connection to %s:%d closed.', self.host[0], self.host[1]
        )
        self.network_client.handle_message(self, ConnectionLostEvent())

    def send(self, message_type, payload=''):
        """Utility method to calculate the checksum, the payload length and
        combine everything into a nice package.
        """
        message = self.serialize_message(message_type, payload)
        self.bytes_sent += len(message)
        self.network_client.bytes_sent += len(message)
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
        self.bytes_received += read_len
        self.network_client.bytes_received += read_len
        return payload

    def read_message(self):
        header = self.read(24)

        magic, command, length, unused_checksum = struct.unpack(
            "<4s12sII", header.getvalue())
        if params['magic'] != magic:
            raise ValueError('Message separator magic did not match protocol '
                             '(%s)' % magic.encode('hex'))
        payload = self.read(length)

        command = command.strip('\x00')
        message = self.parse_message(command, payload)
        return message

    def disconnect(self):
        self.connected = False
        self.socket.close()


class GeventNetworkClient(NetworkClient):
    """Implementation using gevent.
    """
    IDLE_TIMEOUT = 30

    connection_class = GeventConnection

    def __init__(self):
        NetworkClient.__init__(self)
        self.shutdown_event = event.Event()
        self.connection_group = pool.Group()
        self.socket = None
        self.lock = gevent.lock.RLock()

    def connect(self, host, timeout=10):
        connection = super(GeventNetworkClient, self).connect(host)
        g = gevent.spawn(connection.connect_and_run, timeout)
        connection.greenlet = g
        self.connection_group.add(g)
        return connection

    def run_forever(self):
        self.connection_group.join()

    def listen(self, host='0.0.0.0', port=8333, backlog=5):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((host, port))
        self.socket.listen(backlog)
        self.connection_group.add(gevent.spawn(self.accept))
        logging.debug("Socket bound to %s:%d", host, port)

    def accept(self):
        def disconnect_idle(host):
            if host in self.connections and not self.connections[host].version:
                logging.debug("Closing idle connection %s:%d", *host)
                connection = self.connections[host]
                connection.disconnect()
                del self.connections[host]
                self.handle_message(connection, ConnectionLostEvent())

        while True:
            conn, addr = self.socket.accept()
            connection = self.connection_class(self, addr, incoming=True)
            connection.connected = True
            connection.socket = conn
            self.connections[addr] = connection
            self.handle_message(connection, ConnectionEstablishedEvent())
            g = gevent.spawn(connection.run)
            self.connection_group.add(g)
            logging.debug("Accepted incoming connection from %s:%d", *addr)
            gevent.spawn_later(self.IDLE_TIMEOUT, disconnect_idle, addr)


class ClientBehavior(object):
    def __init__(self, network_client):
        network_client.register_handler(
            ConnectionEstablishedEvent.type, self.on_connect
        )
        network_client.register_handler(
            messages.VersionPacket.type, self.on_version
        )

    def on_connect(self, connection, unused_message):
        if not connection.incoming:
            self.send_version(connection)

    def on_version(self, connection, unused_message):
        if connection.incoming:
            self.send_version(connection)
            self.send_verack(connection)
        else:
            self.send_verack(connection)

    def send_version(self, connection):
        v = messages.VersionPacket()
        v.addr_from = messages.Address('127.0.0.1', True, 8333, 1)
        v.addr_recv = messages.Address(connection.host[0], True,
                                       connection.host[1], 1)
        v.best_height = 0
        connection.send('version', v)

    def send_verack(self, connection):
        connection.send('verack', '')
