
pycoin
======

Minimalistic python implementation of the Bitcoin networking stack

Installation
------------

To install just checkout the git repository and use the included
`setup.py` script to build and bundle it:

```bash
git clone git@github.com:cdecker/pycoin.git
python setup.py install
```

Getting started
---------------

The following example creates a connection pool. It rewires the
message handler on each connection to call the `on_inv_received`
handler on the `InvTracker` instead, adding the connection as
additional argument. When receiving an `inv` message it loops through
the hashes and prints their type and hash to stdout.

```python
from bitcoin import PooledBitcoinProtocolFactory
from functools import partial
from twisted.internet import reactor

class InvTracker(PooledBitcoinProtocolFactory):

    def buildProtocol(self, addr):
        connection = PooledBitcoinProtocolFactory.buildProtocol(self, addr)
        connection.handlers['inv'].append(partial(self.on_inv_received, connection))
        return connection

    def on_inv_received(self, connection, inv):
        for item in inv.hashes:
            print connection.key, item[0], item[1].encode("hex")

def start():
    factory = InvTracker(1000)
    desiredPort = 8333
    reactor.listenTCP(desiredPort, factory) #@UndefinedVariable

    print "Listening to port %d" % factory.port
    reactor.run() #@UndefinedVariable

if __name__=="__main__":
    start()
```

License
-------
This code is distributed under the [BSD 3-clause license](http://en.wikipedia.org/wiki/BSD_licenses#3-clause_license_.28.22Revised_BSD_License.22.2C_.22New_BSD_License.22.2C_or_.22Modified_BSD_License.22.29).


