'''
Created on Jul 9, 2012

@author: cdecker
'''
import unittest
from cStringIO import StringIO

from bitcoin.utils import encodeVarLength, decodeVarLength
from _pyio import BytesIO
class Test(unittest.TestCase):


    def testVarLength(self):
        self.assertEqual("01", encodeVarLength(1).encode("hex"), "Simple 1 char number")
        self.assertEqual("fd0004", encodeVarLength(1024).encode("hex"), "2 + 1 byte number")
        self.assertEqual("feefbeadde", encodeVarLength(3735928559).encode("hex"), "4 + 1 byte number")
        self.assertEqual("ffdeadbeefdeadbeef", encodeVarLength(17275436393656397278).encode("hex"), "8 + 1 byte number")
    
    def testVarLengthDecode(self):
        self.assertEqual(decodeVarLength(StringIO("01DEAD".decode("hex"))), 1, "Simple 1 char number")
        self.assertEqual(decodeVarLength(StringIO("fd000401DEAD".decode("hex"))),1024, "2 + 1 byte number")
        self.assertEqual(decodeVarLength(StringIO("feefbeadde01DEAD".decode("hex"))), 3735928559, "4 + 1 byte number")
        self.assertEqual(decodeVarLength(StringIO("ffdeadbeefdeadbeef01DEAD".decode("hex"))),17275436393656397278, "8 + 1 byte number")
        
    def testAddressSerialization(self):
        """
        Network address:
         01 00 00 00 00 00 00 00                         - 1 (NODE_NETWORK: see services listed under version command)
         00 00 00 00 00 00 00 00 00 00 FF FF 0A 00 00 01 - IPv6: ::ffff:10.0.0.1 or IPv4: 10.0.0.1
         20 8D
        """
        from bitcoin.BitcoinProtocol import Address
        b = "010000000000000000000000000000000000FFFF0A000001208D".decode("hex")
        a = Address()
        a.parse(BytesIO(b), False)
        self.assertTrue(a.isIPv4, "Is IPv4")
        self.assertEqual("10.0.0.1", a.ip, "IP")
        self.assertEqual(8333, a.port, "Port")
        self.assertEqual(1, a.services, "Services")
        buf = BytesIO()
        a.toWire(buf, False)
        self.assertEqual(b.encode("hex"), buf.getvalue().encode("hex"), "Serialization matches")

    def testVersionSerialization(self):
        """
        Version message:
         9C 7C 00 00                                                                   - 31900 (version 0.3.19)
         01 00 00 00 00 00 00 00                                                       - 1 (NODE_NETWORK services)
         E6 15 10 4D 00 00 00 00                                                       - Mon Dec 20 21:50:14 EST 2010
         01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 FF FF 0A 00 00 01 20 8D - Recipient address info - see Network Address
         01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 FF FF 0A 00 00 02 20 8D - Sender address info - see Network Address
         DD 9D 20 2C 3A B4 57 13                                                       - Node random unique ID
         00                                                                            - "" sub-version string (string is 0 bytes long)
         55 81 01 00                                                                   - Last block sending node has is block #98645
        """
        b = ("9C7C00000100000000000000E615104D00000000010000000000000000000000" + \
            "000000000000FFFF0A000001208D010000000000000000000000000000000000" + \
            "FFFF0A000002208DDD9D202C3AB457130055810100").decode("hex")
        from bitcoin.BitcoinProtocol import VersionPacket
        p = VersionPacket()
        p.parse(BytesIO(b), 70001)
        self.assertEquals(p.version, 31900, "Version")
        self.assertEquals(p.services, 1, "Services")
        self.assertEquals(p.timestamp, 1292899814)
        self.assertEqual("dd9d202c3ab45713", p.nonce.encode("hex"))
        self.assertEqual(98645, p.best_height)
        
        buf = BytesIO()
        p.toWire(buf, 70001)
        self.assertEquals(b.encode("hex"), buf.getvalue().encode("hex"), "Serialization")
    def testInvPacket(self):
        from bitcoin.BitcoinProtocol import InvPacket
        b = ("030100000013789a2379fc190f292c9bc8087205a2dd4ee49f18cc5e9247ccc" + \
             "32525009550010000009c2c5169e550e49c118f9e57a06fd709e23b4f75cc2f" + \
             "c9af618c3ceda4e35eb20100000017e644fbcb3e92589ece8c42d88b2930c4d" + \
             "787d89e45415883ec61303bf88e42").decode("hex")
        i = InvPacket()
        i.parse(BytesIO(b), 70001)
        
        buf = BytesIO()
        i.toWire(buf, 70001)
        self.assertEquals(b.encode("hex"), buf.getvalue().encode("hex"))
        
    def testTxPacket(self):
        from bitcoin.BitcoinProtocol import TxPacket
        b = BytesIO(open("test/resources/tx-9c0f7b2.dmp").read())
        t = TxPacket()
        t.parse(b, 70001)
        self.assertEquals(b.tell(), len(b.getvalue()))
        
        self.assertEquals(1, len(t.inputs))
        self.assertEquals(2, len(t.outputs))
        self.assertEquals(t.lock_time, 0)
        
        buf = BytesIO()
        t.toWire(buf, 70001)
        self.assertEquals(b.getvalue().encode("hex"), buf.getvalue().encode("hex"))
        
    def testBlockPacket(self):
        from bitcoin.BitcoinProtocol import BlockPacket
        by = BytesIO(open("test/resources/block-188817.dmp").read())
        b = BlockPacket()
        b.parse(by, 70001)
        
        self.assertEquals(1342158910, b.timestamp)
        self.assertEquals(1, b.version)
        self.assertEquals("000000000000051d9fa2edb8bb1a7e2466a91e2244222218e94057e0aba50545", b.prev_block.encode("hex"))
        self.assertEquals(436835377, b.bits)
        self.assertEquals(2064516359, b.nonce)
        self.assertEquals(88, len(b.transactions))
        
        buf = BytesIO()
        b.toWire(buf, 70001)
        self.assertEquals(len(by.getvalue()), len(buf.getvalue()))
        
    def testAddrPacket(self):
        from bitcoin.BitcoinProtocol import AddrPacket
        b = BytesIO("01E215104D010000000000000000000000000000000000FFFF0A000001208D".decode("hex"))
        a = AddrPacket()
        a.parse(b, 70001)
        
        self.assertEqual(1, len(a.addresses))
        address = a.addresses[0]
        self.assertEquals("addr", a.type)
        self.assertTrue(address.isIPv4)
        self.assertEquals(1292899810, address.timestamp)
        self.assertEqual(1, address.services)
        self.assertEquals("10.0.0.1", address.ip)
        self.assertEquals(8333, address.port)

        buf = BytesIO()
        a.toWire(buf, 70001)
        self.assertEquals(b.getvalue().encode("hex"), buf.getvalue().encode("hex"))

