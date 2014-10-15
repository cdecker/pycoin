'''
Created on Mar 4, 2013

@author: cdecker
'''

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
