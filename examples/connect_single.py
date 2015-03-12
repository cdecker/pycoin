from bitcoin import network
from socket import gethostbyname
import logging


__author__ = 'cdecker'


network_client = network.GeventNetworkClient()
ip = gethostbyname('seed.bitcoinstats.com')
network_client.connect((ip, 8333))


def send_version(connection, message):
    v = network.messages.VersionPacket()
    v.addr_from = network.messages.Address('127.0.0.1', True, 8333, 1)
    v.addr_recv = network.messages.Address(
        connection.host[0], True, connection.host[1], 1
    )
    v.best_height = 0
    connection.send('version', v)


def send_verack(connection, message):
    connection.send('verack', '')


def handle_message(connection, message):
    logging.info('%s message from %s:%d', message.type, *connection.host)
    print '%s message from %s:%d' % (
        message.type, connection.host[0], connection.host[1]
    )


network_client.register_handler(
    network.ConnectionEstablishedEvent.type, send_version
)
network_client.register_handler(
    network.messages.VersionPacket.type, send_verack
)

for t in network.messages.parsers:
    network_client.register_handler(t, handle_message)

network_client.run_forever()
