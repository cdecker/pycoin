'''
Created on Mar 4, 2013

@author: cdecker
'''

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
