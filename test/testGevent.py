import unittest
from cStringIO import StringIO

from bitcoin.utils import encodeVarLength, decodeVarLength
from _pyio import BytesIO
from mock import MagicMock, Mock
from bitcoin.gevent import Connection

version_message = "".join("""
        f9 be b4 d9 76 65 72 73 69 6f 6e 00 00 00 00 00
        64 00 00 00 35 8d 49 32 62 ea 00 00 01 00 00 00
        00 00 00 00 11 b2 d0 50 00 00 00 00 01 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 ff ff
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 ff ff 00 00 00 00 00 00
        3b 2e b3 5d 8c e6 17 65 0f 2f 53 61 74 6f 73 68
        69 3a 30 2e 37 2e 32 2f c0 3e 03 00
        """.split()).decode("hex")


class Test(unittest.TestCase):


    def testConnectionRead(self):
        
        def recv_result(l):
            global version_message
            r = version_message[:l]
            version_message = version_message[l:]
            return r
        
        socket = Mock()
        socket.recv = MagicMock(side_effect=recv_result)
        c = Connection(socket, ('127.0.0.1', 8333), False)
        c.run()
        
        
        