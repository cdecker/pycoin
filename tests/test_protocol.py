"""
Created on Jul 9, 2012

@author: cdecker
"""
from cStringIO import StringIO
from bitcoin.utils import encodeVarLength, decodeVarLength
from _pyio import BytesIO
import os
import unittest
from bitcoin import messages


BASENAME = os.path.dirname(__file__)


class Test(unittest.TestCase):

    def testVarLength(self):
        self.assertEqual(
            '01', encodeVarLength(1).encode("hex")
        )
        self.assertEqual(
            'fd0004', encodeVarLength(1024).encode("hex")
        )
        self.assertEqual(
            'feefbeadde', encodeVarLength(3735928559).encode("hex")
        )
        self.assertEqual(
            'ffdeadbeefdeadbeef',
            encodeVarLength(17275436393656397278).encode("hex")
        )

    def testVarLengthDecode(self):
        self.assertEqual(
            decodeVarLength(StringIO("01DEAD".decode("hex"))),
            1
        )
        self.assertEqual(
            decodeVarLength(StringIO("fd000401DEAD".decode("hex"))),
            1024
        )
        self.assertEqual(
            decodeVarLength(StringIO("feefbeadde01DEAD".decode("hex"))),
            3735928559
        )
        self.assertEqual(
            decodeVarLength(
                StringIO('ffdeadbeefdeadbeef01DEAD'.decode("hex"))
            ),
            17275436393656397278
        )

    def testAddressSerialization(self):
        b = (
            '010000000000000000000000000000000000FFFF0A000001208D'
        ).decode("hex")
        a = messages.Address()
        a.parse(BytesIO(b), False)
        self.assertTrue(a.isIPv4, "Is IPv4")
        self.assertEqual("10.0.0.1", a.ip, "IP")
        self.assertEqual(8333, a.port, "Port")
        self.assertEqual(1, a.services, "Services")
        buf = BytesIO()
        a.toWire(buf, False)
        self.assertEqual(
            b.encode("hex"),
            buf.getvalue().encode("hex")
        )

    def testVersionSerialization(self):
        b = (
            '9C7C00000100000000000000E615104D00000000010000000000000000000000'
            '000000000000FFFF0A000001208D010000000000000000000000000000000000'
            'FFFF0A000002208DDD9D202C3AB457130055810100'
        ).decode("hex")
        p = messages.VersionPacket()
        p.parse(BytesIO(b), 70001)
        self.assertEquals(p.version, 31900, "Version")
        self.assertEquals(p.services, 1, "Services")
        self.assertEquals(p.timestamp, 1292899814)
        self.assertEqual("dd9d202c3ab45713", p.nonce.encode("hex"))
        self.assertEqual(98645, p.best_height)

        buf = BytesIO()
        p.toWire(buf, 70001)
        self.assertEquals(
            b.encode("hex"),
            buf.getvalue().encode("hex")
        )

    def testInvPacket(self):
        b = (
            '030100000013789a2379fc190f292c9bc8087205a2dd4ee49f18cc5e9247ccc'
            '32525009550010000009c2c5169e550e49c118f9e57a06fd709e23b4f75cc2f'
            'c9af618c3ceda4e35eb20100000017e644fbcb3e92589ece8c42d88b2930c4d'
            '787d89e45415883ec61303bf88e42').decode("hex")
        i = messages.InvPacket()
        i.parse(BytesIO(b), 70001)

        buf = BytesIO()
        i.toWire(buf, 70001)
        self.assertEquals(b.encode("hex"), buf.getvalue().encode("hex"))

    def testTxPacket(self):
        b = BytesIO(open(
            os.path.join(BASENAME, 'resources', "tx-9c0f7b2.dmp")
        ).read())
        t = messages.TxPacket()
        t.parse(b, 70001)
        self.assertEquals(b.tell(), len(b.getvalue()))

        self.assertEquals(1, len(t.inputs))
        self.assertEquals(2, len(t.outputs))
        self.assertEquals(t.lock_time, 0)

        buf = BytesIO()
        t.toWire(buf, 70001)
        self.assertEquals(
            b.getvalue().encode("hex"),
            buf.getvalue().encode("hex")
        )

    def testBlockPacket(self):
        by = BytesIO(open(
            os.path.join(BASENAME, 'resources', "block-188817.dmp")
        ).read())
        b = messages.BlockPacket()
        b.parse(by, 70001)

        self.assertEquals(1342158910, b.timestamp)
        self.assertEquals(1, b.version)
        self.assertEquals(
            '000000000000051d9fa2edb8bb1a7e2466a91e2244222218e94057e0aba50545',
            b.prev_block.encode("hex")
        )
        self.assertEquals(436835377, b.bits)
        self.assertEquals(2064516359, b.nonce)
        self.assertEquals(88, len(b.transactions))

        buf = BytesIO()
        b.toWire(buf, 70001)
        self.assertEquals(len(by.getvalue()), len(buf.getvalue()))

    def testAddrPacket(self):
        b = BytesIO((
            '01E215104D010000000000000000000000000000000000FFFF0A000001208D'
        ).decode("hex"))
        a = messages.AddrPacket()
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
        self.assertEquals(
            b.getvalue().encode("hex"),
            buf.getvalue().encode("hex")
        )
