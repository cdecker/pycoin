from bitcoin import utils


import unittest


class UtilTest(unittest.TestCase):
    def testChecksum(self):
        data = [
            ('test', '954d5a49'),
            ('pycoin', '58709a9f')
        ]

        for d, h in data:
            self.assertEquals(utils.checksum(d).encode('hex'), h)
            self.assertEquals(utils.doubleSha256(d)[:4].encode('hex'), h)
