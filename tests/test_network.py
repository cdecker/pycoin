from bitcoin import network
from bitcoin import messages
from io import BytesIO
from mock import patch
from gevent import socket
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

        self.assertFalse(connection.parse_message('unknown', ''))

    def test_misc(self):
        nc = network.NetworkClient()
        self.assertRaises(NotImplementedError, nc.run_forever)


class TestConnection(unittest.TestCase):

    def test_misc(self):
        c = network.Connection(None, ('127.0.0.1', 8333))
        self.assertRaises(NotImplementedError, c.disconnect)


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

if __name__ == '__main__':
    unittest.main()
