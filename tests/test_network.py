from bitcoin import network
from bitcoin import messages
from io import BytesIO
from mock import patch
from gevent import socket
import mock
import os
import unittest


__author__ = 'cdecker'


BASENAME = os.path.dirname(__file__)


class TestNetworkClient(unittest.TestCase):
    def test_parser(self):
        """Test parser selection.

        Test to see whether we are selecting the correct parser.
        """
        tx = BytesIO(open(
            os.path.join(BASENAME, 'resources', 'tx-9c0f7b2.dmp'),
            'r'
        ).read())
        connection = network.Connection(None, ('host', 8333))
        message = connection.parse_message('tx', tx)
        self.assertEqual('tx', message.type)
        self.assertIsInstance(message, messages.TxPacket)

    def test_misc(self):
        nc = network.NetworkClient()
        self.assertRaises(NotImplementedError, nc.run_forever)
        v = mock.Mock()
        c = mock.Mock()
        nc.handle_version(c, v)
        self.assertEquals(v.version, c.version)


class TestConnection(unittest.TestCase):

    def test_misc(self):
        c = network.Connection(None, ('127.0.0.1', 8333))
        self.assertRaises(NotImplementedError, c.disconnect)

    def testConnectDisconnect(self):
        nc = network.NetworkClient()
        nc.connection_class = mock.MagicMock()
        conn = nc.connect(('1.2.3.4', 8333))
        nc.connect(('1.2.3.4', 8334))
        nc.connect(('1.2.3.5', 8333))
        self.assertRaises(ValueError, nc.connect, ('1.2.3.4', 8333))
        self.assertTrue(('1.2.3.4', 8333) in nc.connections)
        self.assertEqual(len(nc.connections), 3)

        self.assertFalse(conn.disconnect.called)
        nc.disconnect(('1.2.3.4', 8333))
        self.assertTrue(conn.disconnect.called)
        self.assertTrue(('1.2.3.4', 8333) not in nc.connections)
        self.assertEqual(len(nc.connections), 2)

        self.assertRaises(ValueError, nc.disconnect, ('1.2.3.4', 8333))
        self.assertEqual(len(nc.connections), 2)

    def test_roundtrip(self):
        """ Do a full roundtrip of the network stack.

        Use Connection to serialize a message and GeventConnection to
        deserialize it again.
        """
        network_client = mock.MagicMock()
        connection = network.GeventConnection(network_client,
                                              ('127.0.0.1', 8333),
                                              False)
        connection.socket = mock.Mock()
        p = messages.GetDataPacket()
        connection.send(p.type, p)
        wire = BytesIO(connection.socket.send.call_args[0][0])

        def recv(n):
            return wire.read(n)

        connection.socket.recv = recv
        message = connection.read_message()
        self.assertTrue(isinstance(message, messages.GetDataPacket))

        # This should produce a short read
        wire = BytesIO(connection.socket.send.call_args[0][0][:-2])
        self.assertRaises(ValueError, connection.read_message)

        # This will raise a non-matching magic error
        wire = BytesIO("BEEF" + connection.socket.send.call_args[0][0][4:])
        self.assertRaises(ValueError, connection.read_message)


class TestGeventNetworkClient(unittest.TestCase):

    def test_init(self):
        network.GeventNetworkClient()

    @mock.patch('bitcoin.network.gevent')
    def test_connect(self, mgevent):
        nc = network.GeventNetworkClient()
        conn = nc.connect(('10.0.0.1', 8333))
        self.assertTrue(conn)
        self.assertTrue(mgevent.spawn.called)

    def test_run_forever(self):
        nc = network.GeventNetworkClient()
        nc.connection_group = mock.Mock()
        nc.run_forever()
        self.assertTrue(nc.connection_group.join.called)

    @mock.patch('bitcoin.network.socket')
    def test_listen(self, msocket):
        nc = network.GeventNetworkClient()
        group_size = len(nc.connection_group)

        nc.listen()

        self.assertTrue(nc.socket.bind.called)
        self.assertTrue(nc.socket.listen.called)
        self.assertEquals(len(nc.connection_group), group_size + 1)

    @mock.patch('bitcoin.network.gevent.spawn_later')
    @mock.patch('bitcoin.network.gevent.spawn')
    def test_accept(self, mspawn, mspawn_later):
        nc = network.GeventNetworkClient()

        nc.socket = mock.Mock()
        connection_handler = mock.Mock()
        nc.register_handler(
            network.ConnectionEstablishedEvent.type,
            connection_handler
        )
        nc.socket.accept = mock.Mock(side_effect=[
            (mock.Mock(), ('10.0.0.1', 8333)),
            StopIteration()
        ])
        self.assertRaises(StopIteration, nc.accept)
        self.assertTrue(connection_handler.called)

    @mock.patch('bitcoin.network.gevent.spawn_later')
    @mock.patch('bitcoin.network.gevent.spawn')
    def test_accept_idle_timeout(self, mspawn, mspawn_later):
        nc = network.GeventNetworkClient()

        nc.socket = mock.Mock()
        connection_handler = mock.Mock()
        nc.register_handler(
            network.ConnectionLostEvent.type,
            connection_handler
        )
        nc.socket.accept = mock.Mock(side_effect=[
            (mock.Mock(), ('10.0.0.1', 8333)),
            StopIteration()
        ])

        def spawn_later(t, callable, *args, **kwargs):
            callable(*args, **kwargs)

        # Wire the idle timeout handler to be called immediately
        mspawn_later.side_effect = spawn_later

        self.assertRaises(StopIteration, nc.accept)

        self.assertEquals(len(nc.connections), 0)
        self.assertTrue(connection_handler.called)


class TestUtil(unittest.TestCase):

    def test_bootstrap(self):
        res = network.bootstrap()
        self.assertTrue(res)

    @patch('bitcoin.network.socket.getaddrinfo')
    def test_bootstrap_fail(self, getaddrinfo):
        """ socket.getaddrinfo may return None. """
        def side_effect(a, b):
            if a == network.DNS_SEEDS[0]:
                raise socket.gaierror()
            else:
                return [(2, 2, 17, '', ('68.48.214.241', 0))]
        getaddrinfo.side_effect = side_effect
        res = network.bootstrap()
        self.assertListEqual(res, [('68.48.214.241', 8333)])


class TestBehavior(unittest.TestCase):

    def setUp(self):
        self.network_client = mock.Mock()
        self.network_client.bytes_sent = 0
        self.connection = mock.Mock(incoming=False, host=('127.0.0.1', 8333))

    def test_client_behavior_init(self):
        network.ClientBehavior(self.network_client)
        args = self.network_client.register_handler.call_args_list
        types = [a[0][0] for a in args]

        # Ensure we have at least handlers for the connection established event
        # and an incoming version message
        self.assertTrue(network.ConnectionEstablishedEvent.type in types)
        self.assertTrue(messages.VersionPacket.type in types)

    def test_client_behavior_on_connect(self):
        b = network.ClientBehavior(self.network_client)
        message = mock.Mock(type=network.ConnectionEstablishedEvent.type)

        # We should not send anything on new incoming connections
        self.connection.incoming = True
        b.on_connect(self.connection, message)
        self.assertFalse(self.connection.send.called)

        # On outgoing connections we initiate the handshake
        self.connection.incoming = False
        b.on_connect(self.connection, message)
        self.assertTrue(self.connection.send.called)

    def test_client_behavior_send_verack(self):
        b = network.ClientBehavior(self.network_client)
        b.send_verack(self.connection)
        self.connection.send.assert_called_with('verack', '')
        self.assertEquals(self.connection.send.call_count, 1)

    def test_client_behavior_on_version(self):
        b = network.ClientBehavior(self.network_client)
        b.send_version = mock.Mock()
        b.send_verack = mock.Mock()

        # This is an outgoing connection, so we should send just one verack
        self.connection.incoming = False
        b.on_version(self.connection, mock.Mock())
        self.assertFalse(b.send_version.called)
        self.assertEquals(b.send_verack.call_count, 1)

        # Now on an incoming connection, we also respond with a version
        self.connection.incoming = True
        b.send_verack.reset()
        b.on_version(self.connection, mock.Mock())
        self.assertTrue(b.send_verack.call_count, 1)
        self.assertTrue(b.send_version.call_count, 1)


if __name__ == '__main__':
    unittest.main()
