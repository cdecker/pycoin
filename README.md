
pycoin
======

Minimalistic python implementation of the Bitcoin networking
stack. This library was developed to facilitate measurements in the
Bitcoin network for some of my papers. It does include everything that
is needed to connect and participate in the network, it does however
not contain any crypto implementations other than the checksum
mechanism. If you find this work useful please contribute back your
modifications or give me a
[shout](http://www.disco.ethz.ch/members/cdecker.html). Should you
have a nice idea for a project, we're always looking for fun stuff to
implement.

[![Build Status](https://travis-ci.org/cdecker/pycoin.png?branch=master)](https://travis-ci.org/cdecker/pycoin)
[![Coverage Status](https://coveralls.io/repos/cdecker/pycoin/badge.svg?branch=master)](https://coveralls.io/r/cdecker/pycoin?branch=master)


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
from bitcoin import network

def on_inv_received(connection, inv):
    for item in inv.hashes:
        print connection.host, item[0], item[1].encode("hex")

def start():
    client = network.GeventNetworkClient()
    client.register_handler('inv', on_inv_received)
    network.ClientBehavior(client)
    client.connect(('seed.bitcoinstats.com', 8333))
    client.run_forever()
    
if __name__=="__main__":
    start()
```

Changelog
---------
**v0.1**
This release breaks some of the existing functionality and moves networking code into the `bitcoin.network` package. The twisted implementation is currenty broken since I concentrate mainly on gevent for my own clients.

**v0.1.1**
Added listening for incoming connection to GeventNetworkClient.

**v0.2**
 - Removed legacy twisted API
 - Increased test coverage (py.test)
 - Code is now PEP8 compliant

**v0.2.1**
Minor bugfix release.
 - Added six dependency for compatibility
 - Fixed parsing of relay flag in `version` message
 - Bumped gevent dependency to allow support for python 3 in some distant future

License
-------
This code is distributed under the [BSD 3-clause license](http://en.wikipedia.org/wiki/BSD_licenses#3-clause_license_.28.22Revised_BSD_License.22.2C_.22New_BSD_License.22.2C_or_.22Modified_BSD_License.22.29).
