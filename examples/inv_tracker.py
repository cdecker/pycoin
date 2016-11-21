'''
Created on Mar 4, 2013

@author: cdecker
'''

from bitcoin import network, messages
import logging

logging.getLogger().setLevel(logging.DEBUG)
network.configure(network.testnet_params)


def on_inv_received(connection, inv):
    for item in inv.hashes:
        print connection.host, item[0], item[1].encode("hex")

    gd = messages.GetDataPacket()
    gd.hashes = inv.hashes
    gd.convertToWitness()
    for i, h in enumerate(gd.hashes):
        gd.hashes[i] = (h[0] | 1 << 30, h[1])
    connection.send(gd.type, gd)


def on_tx(connection, tx):
    #print len(tx.inputs), tx.hash().encode("hex"), tx.is_segwit
    pass

def on_block(connection, b):
    print len(b.transactions), b.hash().encode("hex")

def start():
    client = network.GeventNetworkClient()
    client.register_handler('inv', on_inv_received)
    client.register_handler('tx', on_tx)
    client.register_handler('block', on_block)
    network.ClientBehavior(client)
    client.connect(('localhost', network.params['port']))
    client.run_forever()


if __name__ == "__main__":
    start()
