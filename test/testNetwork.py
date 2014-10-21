__author__ = 'cdecker'

from bitcoin import network
from bitcoin import messages
from io import BytesIO
from mock import MagicMock
import os
import unittest


BASENAME = os.path.dirname(__file__)


class TestNetworkClient(unittest.TestCase):
    def test_parser(self):
        """Test parser selection.

        Test to see whether we are selecting the correct parser.
        """
        tx = BytesIO(open(
            os.path.join(BASENAME, 'resources', 'tx-9c0f7b2.dmp'),
            'r').read())
        connection = network.Connection(None, ('host', 8333))
        message = connection.parse_message('tx', tx)
        self.assertEqual('tx', message.type)
        self.assertIsInstance(message, messages.TxPacket)

        self.assertFalse(connection.parse_message('unknown', ''))

    def test_misc(self):
        nc = network.NetworkClient()
        self.assertRaises(NotImplementedError, nc.run_forever)

    def testConnectDisconnect(self):
        nc = network.NetworkClient()
        nc.connection_class = MagicMock()
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


class TestConnection(unittest.TestCase):

    def test_misc(self):
        c = network.Connection(None, ('127.0.0.1', 8333))
        self.assertRaises(NotImplementedError, c.disconnect)

    def testSerializeMessage(self):
        c = network.Connection(None, ('127.0.0.1', 8333))
        msg = c.serialize_message('getaddr', '')
        self.assertEqual(
            msg.encode('hex'),
            'f9beb4d9676574616464720000000000000000005df6e0e2'
        )

        p = MagicMock()
        ping = messages.PingPacket()
        p.toWire.side_effect = ping.toWire
        ping.nonce = 'BEEF'
        ser = c.serialize_message('ping', p)
        self.assertTrue(p.toWire.called)
        self.assertEqual(
            ser.encode('hex'),
            'f9beb4d970696e670000000000000000040000001c614e6f42454546'
        )


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
