'''
Created on May 13, 2015

@author: cdecker
'''

from bitcoin import network
from bitcoin import messages


def on_inv_received(connection, inv):
    # only request the items if it is announced alone, not in bulk
    if len(inv.hashes) == 1:
        p = messages.GetDataPacket()
        p.hashes.append(inv.hashes[0])
        connection.send('getdata', p)


def on_block_received(connection, block):
    print "Block", block.hash().encode('hex')


def on_tx_received(connection, tx):
    print "Transaction", tx.hash().encode('hex')


def start():
    client = network.GeventNetworkClient()
    client.register_handler('inv', on_inv_received)
    client.register_handler('tx', on_tx_received)
    client.register_handler('block', on_block_received)
    network.ClientBehavior(client)
    client.connect(('seed.bitcoinstats.com', 8333))
    client.run_forever()


if __name__ == "__main__":
    start()
