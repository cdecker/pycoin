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
        a.parse(BytesIO(b), {'version': 0})
        self.assertTrue(a.isIPv4, "Is IPv4")
        self.assertEqual("10.0.0.1", a.ip, "IP")
        self.assertEqual(8333, a.port, "Port")
        self.assertEqual(1, a.services, "Services")
        buf = BytesIO()
        a.toWire(buf, {'version': 0})
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
        p.parse(BytesIO(b), None)
        self.assertEquals(p.version, 31900, "Version")
        self.assertEquals(p.services, 1, "Services")
        self.assertEquals(p.timestamp, 1292899814)
        self.assertEqual("dd9d202c3ab45713", p.nonce.encode("hex"))
        self.assertEqual(98645, p.best_height)

        self.assertEquals(p.addr_from.ip, '10.0.0.2')
        self.assertEquals(p.addr_recv.ip, '10.0.0.1')
        
        buf = BytesIO()
        p.toWire(buf, {'version': p.version})
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
        i.parse(BytesIO(b), None)

        buf = BytesIO()
        i.toWire(buf, None)
        self.assertEquals(b.encode("hex"), buf.getvalue().encode("hex"))

    def testTxPacket(self):
        b = BytesIO(open(
            os.path.join(BASENAME, 'resources', "tx-9c0f7b2.dmp")
        ).read())
        t = messages.TxPacket()
        t.parse(b, None)
        self.assertEquals(b.tell(), len(b.getvalue()))

        self.assertEquals(1, len(t.inputs))
        self.assertEquals(2, len(t.outputs))
        self.assertEquals(t.lock_time, 0)

        buf = BytesIO()
        t.toWire(buf, {'version': 70001})
        self.assertEquals(
            b.getvalue().encode("hex"),
            buf.getvalue().encode("hex")
        )

    def testTxHashing(self):
        real_hash = ("9c0f7b2e9aac5c283f451915a04ec71a1da0e2215dbf9388990a7e99"
                     "b7f3d3fd")
        b = BytesIO(open(
            os.path.join(BASENAME, 'resources', "tx-9c0f7b2.dmp")
        ).read())
        t = messages.TxPacket()
        t.parse(b, None)

        t._hash = None
        self.assertEquals(t.hash().encode("hex"), real_hash)

    def testBlockPacket(self):
        by = BytesIO(open(
            os.path.join(BASENAME, 'resources', "block-188817.dmp")
        ).read())
        b = messages.BlockPacket()
        b.parse(by, None)

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
        b.toWire(buf, None)
        self.assertEquals(len(by.getvalue()), len(buf.getvalue()))

    def testBlockHashing(self):
        by = BytesIO(open(
            os.path.join(BASENAME, 'resources', "block-188817.dmp")
        ).read())
        b = messages.BlockPacket()
        b.parse(by, None)

        # Try the cached hash from parsing first
        self.assertEquals(
            b.hash().encode("hex"),
            "0000000000000295df119db2d63b6f2d6ea33196fae5f825cb4323e06d0c46f8"
        )

        # Unset cached hash and try again
        b._hash = None
        self.assertEquals(
            b.hash().encode("hex"),
            "0000000000000295df119db2d63b6f2d6ea33196fae5f825cb4323e06d0c46f8"
        )

    def testAddrPacket(self):
        b = BytesIO((
            '01E215104D010000000000000000000000000000000000FFFF0A000001208D'
        ).decode("hex"))
        a = messages.AddrPacket()
        a.parse(b, None)

        self.assertEqual(1, len(a.addresses))
        address = a.addresses[0]
        self.assertEquals("addr", a.type)
        self.assertTrue(address.isIPv4)
        self.assertEquals(1292899810, address.timestamp)
        self.assertEqual(1, address.services)
        self.assertEquals("10.0.0.1", address.ip)
        self.assertEquals(8333, address.port)

        buf = BytesIO()
        a.toWire(buf, {})
        self.assertEquals(
            b.getvalue().encode("hex"),
            buf.getvalue().encode("hex")
        )

    def test_length(self):
        p = (
            '01E215104D010000000000000000000000000000000000FFFF0A000001208D'
        ).decode("hex")
        b = BytesIO(p)
        a = messages.AddrPacket()
        a.parse(b, None)
        self.assertEquals(len(p), len(a))

    def test_normalized_hash(self):
        p = messages.TxPacket()
        p.inputs.append([
            ['12b5633bad1f9c167d523ad1aa1947b2732a865bf5414eab2f9e5ae5d5c191ba'.decode('hex'), 0],
            ('473044022041d56d649e3ca8a06ffc10dbc6ba37cb958d1177cc8a155e83d064'
             '6cd5852634022047fd6a02e26b00de9f60fb61326856e66d7a0d5e2bc9d01fb9'
             '5f689fc705c04b01').decode('hex'),
            4294967295
        ])

        p.outputs.append([
            100000000,
            ('4104fe1b9ccf732e1f6b760c5ed3152388eeeadd4a073e621f741eb157e6a62e'
             '3547c8e939abbd6a513bf3a1fbe28f9ea85a4e64c526702435d726f7ff14da40'
             'bae4ac').decode('hex')
        ])
        p.version = 1
        p.lock_time = 0
        self.assertEquals(
            p.hash().encode('hex'),
            '4385fcf8b14497d0659adccfe06ae7e38e0b5dc95ff8a13d7c62035994a0cd79'
        )
        self.assertEquals(
            p.normalized_hash().encode('hex'),
            '48b5b698c8646e0bc89381cc936a3cb859254607ef12974e1f4d728a12a5d416'
        )

        p2 = messages.TxPacket()
        p2.version = 1
        p2.inputs.append((
            ('\0'*32, 4294967295),
            ('04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368'
             '616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c'
             '6f757420666f722062616e6b73').decode('hex'),
            4294967295
        ))
        p2.outputs.append((
            5000000000,
            ('4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61'
             'deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf1'
             '1d5fac').decode('hex')
        ))
        p2.lock_time = 0

        self.assertEquals(
            p2.hash().encode('hex'),
            '4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b'
        )

        self.assertEquals(
            p2.normalized_hash().encode('hex'),
            p2.hash().encode('hex')
        )

    def testSegwitTx(self):
        txhash = "85b2c5e202950eb7dc87ff570d68e366d02a801759283c8c8ca66986e7f25242"
        b = BytesIO(open(
            os.path.join(BASENAME, 'resources', "segwit-tx.dmp")
        ).read())
        t = messages.TxPacket()
        self.assertTrue(t.parse(b, {'segwit': True}))
        self.assertEquals(b.tell(), len(b.getvalue()))

        self.assertEquals(txhash, t.hash().encode('hex'))
        
        self.assertEquals(11, len(t.inputs))
        self.assertEquals(11, len(t.outputs))
        self.assertEquals(t.lock_time, 0)
        self.assertEquals(11, len(t.witnesses))
        self.assertTrue(t.is_segwit)
        self.assertFalse(t.is_coinbase())

        buf = BytesIO()
        opts = {'segwit': True, 'version': 70001}
        t.toWire(buf, opts)
        self.assertEquals(
            b.getvalue().encode("hex"),
            buf.getvalue().encode("hex")
        )
