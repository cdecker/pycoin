__author__ = 'cdecker'

from bitcoin import network
from bitcoin import messages
from io import BytesIO
import os
import unittest


BASENAME = os.path.dirname(__file__)


class TestNetworkClient(unittest.TestCase):
    def test_parser(self):
        """Test parser selection.

        Test to see whether we are selecting the correct parser.
        """
        tx = BytesIO(open(os.path.join(BASENAME, 'resources', 'tx-9c0f7b2.dmp'),
                          'r').read())
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


class TestMisc(unittest.TestCase):

    def testDoubleSha256(self):
        self.assertEqual(
            network.doubleSha256('test').encode('hex'),
            '954d5a49fd70d9b8bcdb35d252267829957f7ef7fa6c74f88419bdc5e82209f4'
        )

    def testChecksum(self):
        self.assertEqual(
            network.checksum('test').encode('hex'),
            '954d5a49'
        )

if __name__ == '__main__':
    unittest.main()
