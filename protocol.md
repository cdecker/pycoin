Protocol Version Changes
========================

While the protocol specification does a reasonable job at explaining the format of the packets collecting all the changes needed to claim support for each verison of the protocol.
This documents serves as a chronological (as in increasing version numbers) of what changes were introduced by each protocol version.

106
---
 * Added `addr_from`, `nonce`, `user_agent`, `start_height` to version packet

209
---
 * `addr` message contains multiple addresses serialized as `Address`

31402
-----
 * Added `timestamp` field to `Address` format (notice, this is not the `addr` packet, but the serialization format for addresses contained within).
60001
-----
 * Added `relay` to Version packet as a result of [BIP 37](https://github.com/bitcoin/bips/blob/master/bip-0037.mediawiki)
 * `ping` message expects peers to respond with a `pong` message.
 
### Optional
 * [BIP 37](https://github.com/bitcoin/bips/blob/master/bip-0037.mediawiki)
    introduces bloom filtering support:
   * New messages `filterload`, `filteradd` and `filterclear` are introduced.
   * Upon connection establishment no `inv` messages are relayed if relay is not
     specified in the version message. Announcement is selectively enabled by
     `filteradd` and `filterload`.

60002
-----
This appears to be a simple version bump to enable reliance on service bits.

 
70001
-----
 * 
