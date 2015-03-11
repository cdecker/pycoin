from bitcoin import network


import unittest


class UtilTest(unittest.TestCase):
    def testChecksum(self):
        data = [
            ('test', '954d5a49'),
            ('pycoin', '58709a9f')
        ]

        for d, h in data:
            self.assertEquals(network.checksum(d).encode('hex'), h)
            self.assertEquals(network.doubleSha256(d)[:4].encode('hex'), h)
