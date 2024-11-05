"""
Kerma: Protocol Description
1 Project Description
For this course, we will develop our own blockchain. In groups of up to three members, students will write their own independent implementation of a node for our blockchain in their programming language of choice (we recommend using either Python or Typescript). This document specifies the protocol and defines how nodes will communicate.
During your implementation, be aware that neighbouring nodes can be malicious. Your imple- mentation must be resilient to simple and complex attacks. Simple attacks can be the supply of invalid data. Complex attacks can involve signatures, proof-of-work, double spending, and blocks, all of which must be validated carefully.
The chain is a static difficulty proof-of-work UTXO-based blockchain over a TCP network pro- tocol. The chain is called Kerma, but you should name your node something else.
1.1 Notation disambiguation
MUST or MUST NOT: This term is used to specify a property that must hold, and a node that violates such a property is considered faulty.
SHOULD or SHOULD NOT: This term is used to specify intended behaviour. A node that does not adhere to that behaviour is not necessarily faulty. However, in order to get points for your solution, you must also adhere to these specifications.
1.2 Networking
The peer-to-peer network works over TCP. The default TCP port of the protocol is 18018, but you can use any port. If your node is running behind NAT, make sure your port is forwarded.
1.3 Bootstrapping
Your node will initially connect to a list of known peers. From there, it will build its own list of known peers. We will maintain a list of bootstrapping peer IPs / domains in TUWEL as they become available.
1.4 Data Validation
Your client must disconnect from a peer it is connect to in case it receives invalid data from it. Be rigorous about network data validation and do not accept malformed data.
Cryptocurrencies - Project Kerma
 2 Cryptographic Primitives 2.1 Hash
We use blake2s as our hash function. This is used both for content-addressable application objects as well as proof-of-work. When hashes appear in JSON, they should be in hexadecimal format as described in below.
2.2 Signatures
We use Ed25519 digital signature scheme. Public keys and signatures should be byte-encoded as described in RFC 8032. A library will typically take care of this process, e.g., crypto/ed25519 in Go programming language. Once a signature or public key is byte-encoded, it is converted to hex in order to represent as a string within JSON. Whenever we refer to a “public key" or a “signature" in this protocol, we mean the byte-encoded and hexified data.
2.3 Hexification
Hex strings must be in lower case.
3 Application Objects
Application objects are objects that must be stored by each node. These are content-addressed by the blake2s hash of their JSON representation. Therefore, it is important to have the same JSON representation as other clients so that the same objects are addressed by the same hash. You must normalize your JSON and ensure it is in canonical JSON form. The examples in this document contain extra whitespace for readability, but these must not be sent over the network. The blake2s of the JSON contents is the objectid.
An application object is a JSON dictionary containing the type key and further keys depend- ing on its type. There are two types of application objects: transactions and blocks. Their objectids are called txid and blockid, respectively.
An application object must only contain keys that are specified, i.e., it must not contain addi- tional keys. The same applies to messages.
3.1 Transactions
This represents a transaction and has the type transaction. It contains the key inputs containing a non-empty array of inputs and the key outputs containing an array of outputs.
An output is a dictionary with keys value and pubkey. The value is a non-negative integer indicating how much value is carried by the output. The value is denominated in picaker, the smallest denomination in Kerma. 1 ker = 1012 picaker. The pubkey is a public key of the
2

Cryptocurrencies - Project Kerma
 recipient of the money. The money carried by an output can be spend by its owner by using it as an input in a future transaction.
An input contains a pointer to a previous output in the outpoint key and a signature in the sig key. The outpoint key contains a dictionary of two keys: txid and index. The txid is the objectid of the previous transaction, while the index is the natural number (zero-based) indexing an output within that transaction. The sig key contains the signature.
Signatures are created using the private keys corresponding to the public keys that are pointed to by their respective outpoint. Signatures are created on the plaintext which con- sists of the transaction they (not their public keys!) are contained within, except that the sig values are all replaced with null. This is necessary because a signature cannot sign itself.
Transactions must satisfy the weak law of conservation: The sum of input values must be equal or exceed the sum of output values. Any remaining value can be collected as fees by the miner confirming the transaction.
This is an example of a (syntactically) valid transaction:
Valid normal transaction
{
"type":"transaction", "inputs ":[
{
"outpoint":{
" t x i d " : " f71408bf847d7dd15824574a7cd4afdfaaa2866286910675cd3fc371507aa196 " ,
"index":0 },
"sig":"3869a9ea9e7ed926a7c8b30fb71f6ed151a132b03fd5dae764f015c98271000e7 da322dbcfc97af7931c23c0fae060e102446ccff0f54ec00f9978f3a69a6f0f "
} ],
"outputs":[ {
"pubkey":"077a2683d776a71139fd4db4d00c16703ba0753fc8bdc4bd6fc56614e659cde3" ,
" value":5100000000 }
] }
However, this example transaction could in principle still be (semantically) invalid in the fol- lowing cases:
• An object with id f7140..aa196 exists but is a block (INVALID_FORMAT).
• The referenced transaction f7140...aa196 has no output with index 0 (INVALID_TX_OUTPOINT).
 3

Cryptocurrencies - Project Kerma
 • The referenced transaction f7140...aa196 is invalid (INVALID_ANCESTRY1).
• The output at index 0 in the referenced transaction f7140...aa196 holds less than 5100000000 picaker (INVALID_TX_CONSERVATION).
• Verifying the signature using the public key in output at index 0 in transaction f7140...aa196 failed (INVALID_TX_SIGNATURE).
3.1.1 Coinbase Transactions
A coinbase transaction is a special form of a transaction and is used by a miner to collect the block reward. See below section Blocks for more info. If the transaction is a coinbase transaction, then it must not contain an inputs key but it must contain an integer height key with the block’s height as the value.
This is an example of a valid coinbase transaction:
Valid coinbase transaction
{
"type":"transaction", "height":1, "outputs":[
{
"pubkey":"3f0bc71a375b574e4bda3ddf502fe1afd99aa020bf6049adfe525d9ad18ff33f" , " value":50000000000000
} ]
}
3.2 Blocks
This represents a block and has the type block. It must contain the following keys:
• txids, which is a list of the transaction identifiers within the block.
• nonce, which is a 32-byte hexified value that can be chosen arbitrarily.
• previd, which is the object identifier of the previous block in the chain. Only the genesis block is allowed to differ from that by having a previd set to null.
• created, which is an (integer) UNIX timestamp in seconds.
• T, which is a 32-byte hexadecimal integer and is the mining target.
1Since your node will never store invalid objects, upon receiving the transaction, it will attempt to fetch the referenced transaction from its peer, leaving the object verification pending. When the peer sends the (invalid) referenced transaction, your node will find out that it is invalid and will release the pending object verification by rejecting the transaction with an INVALID_ANCESTRY error
  4

Cryptocurrencies - Project Kerma
 Optionally it can contain a miner key and a note key, which can be any ASCII-printable2 strings up to 128 characters long each.
Here is an example of a valid block:
Valid block
{
"T":"00000000abc00000000000000000000000000000000000000000000000000000" , "created":1671148800,
"miner":"grader", "nonce":"1000000000000000000000000000000000000000000000000000000001aaf999 " , "note":"This block has a coinbase transaction", "previd":"0000000052a0e645eca917ae1c196e0d0a4fb756747f29ef52594d68484bb5e2" , " t x i d s " : [ " 6 ebfb4c8e8e9b19dcf54c6ce3e1e143da1f473ea986e70c5cb8899a4671c933a " ] , "type":"block"
}
Block validity mandates that the block satisfies the proof-of-work equation: blockid < T.
The genesis block has a null previd. This is our genesis block:
Genesis block
{
"T":"00000000abc00000000000000000000000000000000000000000000000000000" ,
"created":1671062400,
"miner":"Marabu",
"nonce":"000000000000000000000000000000000000000000000000000000021bea03ed" ,
"note":"The New York Times 2022−12−13: Scientists Achieve Nuclear Fusion Breakthrough With Blast of 192 Lasers", "previd":null ,
"txids ":[] ,
"type":"block"
}
All valid chains must extend genesis. Each block must have a timestamp which is later than its predecessor but not after the current time.
The transaction identifiers (txids) in a block may (but is not required to) contain one coinbase transaction. This transaction must be the first in txids. It has exactly one output which generates 50 · 1012 new picaker and also collects fees from the transactions confirmed in the block. The value in this output cannot exceed the sum of the new coins plus the fees, but it can be less than that. The height in the coinbase transaction must match the height of the block the transaction is contained in. This is so that coinbase transactions with the same public key in different blocks are distinct. The block height is defined as the distance to the genesis block: The genesis block has a height of 0, a block that has the genesis block as its parent has a height of 1 etc. The coinbase transaction cannot be spent in the same block. However, a transaction can spend from a previous, non-coinbase transaction in the same block. The order of the identifiers of the confirmed transactions in a block defines the order these transactions
2ASCII-printable characters have hexcodes 0x20 to 0x7e
   5

Cryptocurrencies - Project Kerma are "executed".
All blocks must have a target T of: 00000000abc00000000000000000000000000000000000000000000000000000.
The genesis blockid is: 0000000052a0e645eca917ae1c196e0d0a4fb756747f29ef52594d68484bb5e2.
Check this to ensure your implementation is performing correct JSON canonicalization.
4 Mempool
Every node should store a list of transactions that are not yet confirmed in a block. This is called the mempool. It should satisfy the following properties:
• It is possible to extend the current longest chain by a block containing precisely all transactions in the mempool.
• If a node receives a transaction Tx from the network, it should check whether it can be added to its mempool. This is possible if Tx spends only from unspent outputs that are also not spent by any transaction currently in the mempool. The same applies when re- ceiving a mempool message - a node should attempt to add every transaction referenced in that message to its mempool.
• If the current longest chain changes, i.e., a new block is found or there is a chain reor- ganization, the current mempool M needs to be re-computed. Then, attempt to add the transactions of M to M′. This is done in the following way. The node sets the mempool state to be equal to the state s(B) of the latest block B. Then, the node tries to apply all transactions in the old mempool against this new state s(B), one by one, in the order they appeared in its old mempool. If a transaction from the old mempool can be applied, it is added to the new mempool state. Otherwise, if it cannot be applied, it is thrown away. For instance, if block B contains a transaction that was in the old mempool, that transaction is discarded and does not make it into the new mempool, because it spends from outputs which are already spent. Similarly, if a transaction that was in the old mempool conflicts with the new state s(B), it is thrown away. This means that if two double spending transactions appear in a block and in the old mempool, the transaction in the block takes precedence.
It is not required to further optimize the placement of transactions in the mempool.
In case of reorgs the current state of the chain is rolled back until the latest common ancestor between the current longest chain C′ and the new longest chain C. Let us consider the following example: C′ has blocks {B0, B1′ , B2′ }, and C′ has blocks {B0, B1, B2, B3}. When a reorg takes place, this is what happens:
• the latest common ancestor B0 between C′ and C is identified, and its state s(B0) is the new state of the chain;
 6

Cryptocurrencies - Project Kerma
 • all transactions in blocks {B1′ , B2′ } are undone and transactions in blocks {B1, B2, B3} are applied against the state s(B0). If at any point a transaction cannot be applied, the whole block containing it is discarded;
• if C is the new valid longest chain, the chain with state s(B3) and ending with B3 is adopted: the new mempool can be computed by trying to apply transactions in {B1′ , B2′ } against the new state s(B3) (in the same order as they appear in {B1′ , B2′ }) and, finally, by trying to apply transactions in the old mempool (in the same order as they appeared in the old mempool).
5 Messages
Every message exchanged by two peers over TCP is a JSON message. These JSON messages are separated from one another using ’\n’. The JSON messages themselves must not contain new line endings (’\n’), but they may contain escaped line endings within their strings.
Every JSON message is a dictionary. This dictionary always has at least the key type set, which is a string and defines the message type. Each message may contain its own keys depending on its type.
5.1 Hello
When you connect to another client, you and the other client must perform a simple handshake by both sending a hello message. The message must also contain a version key, which is always set to 0.10.x with x a single decimal digit. The message must also contain an agent key which is an ascii-printable string up to 128 characters that can be chosen arbitrarily.
The hello message must be the first message sent by any communication partner. You can send subsequent messages immediately after the hello message, even before your receive the hello message of your communication partner. You must send an INVALID_HANDSHAKE error message and consider your communication partner as faulty in the following cases:
• A non-hello-message is sent prior to the hello message. • No hello-message has been sent 20s after connection.
• A hello message is sent after handshake was completed.
You must send an INVALID_FORMAT error message and consider your communication partner as faulty in the following cases:
• The version does not match the specified format.
• The agent key contains non-printable characters or is longer than 128 characters. • Any required key is omitted, or there are additional keys.
7

Cryptocurrencies - Project Kerma
This is an example of a valid hello message:
Valid hello message
{
"type":"hello", "version":"0.10.0", "agent":"Kerma−Core Client 0.10"
}
After a handshake is completed, the connection should be kept alive by both communication partners. So in principle, unless an error on the network layer occurs, a connection between two nodes should only be closed when one node detects that the other is faulty.
5.2 GetPeers
If you want to know what peers are known to your peer, you send them a getpeers message. This message has no additional keys and should be responded to with a peers message.
Valid getpeers message
{
" type " : " getpeers "
}
5.3 Peers
Every node should keep a set of known peer addresses to be able to actively connect to other nodes running the protocol.
The peers message can be volunteered or sent in response to a getpeers message. It contains a peers key which is an array of size in range [0, 30], i.e. contains at most 30 entries, but an empty array is also valid. Every peer is a string in the form of host:port. port is a valid port, i.e. a decimal number in range [1, 65535]. The default port is 18018. You can host your node on any port, but your submission must listen at port 18018. host is either a valid DNS entry or a syntactically valid IPv4 address in decimal form. A DNS entry in our protocol is considered valid if it satisfies the following properties:
• it matches the regular expression [a-zA-Z\d\.\-\_]{3,50}, i.e. it is a string of length in range [3, 50] and contains only letters (a-z and A-Z), digits (0-9), dots (.), hyphens (-) or underscores (_).
• there is at least one dot in the string which is not at the first or last position.
   8

Cryptocurrencies - Project Kerma
 • there is at least one letter (a-z or A-Z) in the string. 3 As an example, the following peers are invalid:
• 256.2.3.4:18018 (neither a valid ip address nor a valid DNS entry) • 1.2.3.4.5:678 (neither a valid ip address nor a valid DNS entry)
• 1.2.3.4:2000000 (invalid port)
• nodotindomain:1234 (no dot in domain)
• kermanode.net (no port given)
If a peer in a peers message is not syntactically valid, you must send an INVALID_FORMAT error message and consider your communication partner faulty. Otherwise, add all peers in this message to your known peers.
Optional - Further address checks
You are allowed to perform further checks and to apply heuristics to keep your list of known peers as best as possible by choosing not to store a new peer in your known peers. "As best as possible" means that you want to have as many reachable and correctly working nodes and as few unreachable or faulty nodes as possible in your known peers. However, your node must satisfy the following condition: As long as your node does not know more than 30 peers, if it receives a peer which has a syntactically valid address, is reachable and running the Kerma protocol, then your node must include this peer address in any subsequent reply to a peers message.
A node should include itself in the list of peers at the first position if it is listening for incoming connections. Your node should always listen for and accept new incoming connections.
3If we would not require this property, then the checks for syntactically valid ip addresses would be unneces- sary because the ip address format satisfies the first two properties, and e.g. 300.300.300.300 would be a valid host.
  9

Cryptocurrencies - Project Kerma
  Explanation - Why you should add yourself to peers messages
Consider the following scenario: Assume you have hosted your node on a server that has a non-static ip address which is currently 1.2.3.4 and the hostname "mykerman- ode.net" always points to your server. If you connect to the network for the first time, no one knows that the address of your node can be determined by looking up "mykerman- ode.net". The only thing your connected peer knows about you is that you connected from 1.2.3.4. Provided your node is listening on the standard port 18018, the connected node can guess correctly that your node can be reached at 1.2.3.4:18018. This knowl- edge will eventually reach other nodes, which might want to connect to you. But in the meantime, your ip address might have already been updated, causing any connection attempt to fail. Therefore, your node should behave in the following way:
• It should not try to guess the listening address of a communication partner.
• It should add its DNS entry + listening port at the first position to every "peers" message it sends. If you do not use a DNS entry but have a static ip address, add this ip + port instead.
It is fine if you hardcode these values or pass them as cli arguments, they don’t have to match the ip address of the machine on which we will locally test your node during grading.
The same argument also applies if you host your node on a static ip address on a non- standard port: The port used for outgoing connections will be different from your lis- tening port, therefore any node you connect to will not know on which port your node is listening for incoming connections.
Here is an example of a valid peers message: Valid peers message
{
"type":"peers", "peers":[
"kermanode.net:18017",
"138.197.191.170:18018" ]
}
If you find that a node is faulty, disconnect from it and remove it from your set of known peers (i.e., forget them). Likewise, if you discover that a node is offline, you should forget it. You must not, however, block further communication requests from this node or refuse to add this node again to your known nodes if another node reports this as known. Note that there may are (edge) cases where forgetting a node is not possible - we will not check this behaviour. The idea behind this is that your node will not create lots of traffic by running in
 10

Cryptocurrencies - Project Kerma
 an infinite loop: Connecting to a node, downloading its (invalid) chain, disconnecting because an erroneous object was sent, and connecting again.
Explanation - Edge cases when forgetting nodes
Whenever a remote node that initiated a connection to your node turns out to be faulty, you cannot correctly "forget" it. If the remote node is hosted on a dynamic ip address and a DNS entry points to it, you will only get the current ip address from the connection, not the hostname of this node. You then would need to look up all DNS entries know to you and if you find a match, you know the hostname of the remote node. Still, if multiple nodes are hosted behind the same ip address, you would not be able to deduce which node connected to you. Therefore, this case also applies if the remote node is hosted on a static ip address known to you. Relying on the first entry in the peers message which should be the hostname of the remote node or even on the agent key would be possible, but very easily abusable by a dishonest adversary. Because of this, you should (at least for now) only forget the addresses of peers which you used yourself to initiate the connection, thus knowing exactly who you are connected to.
5.4 GetObject
This message requests an object addressed by the given hash. It contains an objectid key which is the address of the object. If the receiving peer knows about this object, it should respond with an object message. If the receiving peer does not know about this object, it should send an error message with name UNKNOWN_OBJECT.
Valid getobject message
{
"type":"getobject",
" objectid":"0000000052a0e645eca917ae1c196e0d0a4fb756747f29ef52594d68484bb5e2"
}
5.5 IHaveObject
This message advertises that the sending peer has an object with a given hash addressed by the objectid key. The receiving peer may request the object (using getobject) in case it does not have it.
  11

Cryptocurrencies - Project Kerma
  Valid IHaveObject message
{
"type": "ihaveobject",
"objectid": "0000000052a0e645eca917ae1c196e0d0a4fb756747f29ef52594d68484bb5e2"
}
In our gossiping protocol, whenever a peer receives a new object and validates the object, then it advertises the new object to its peers.
5.6 Object
This message sends an object from one peer to another. This can be voluntary, or as a response to a getobject message. It contains an object key which contains the object in question.
Valid object message
{
"type": "object", "object": {
"T":"00000000abc00000000000000000000000000000000000000000000000000000" ,
"created":1671062400,
"miner":"Marabu",
"nonce":"000000000000000000000000000000000000000000000000000000021bea03ed" ,
"note":"The New York Times 2022−12−13: Scientists Achieve Nuclear Fusion Breakthrough With Blast of 192 Lasers", "previd":null ,
"txids ":[] ,
"type":"block" }
}
5.7 GetChainTip
Request the current blockchain tip of the peer with a message of type getchaintip. There are no further keys in this message. A peer should respond with a chaintip message.
Valid GetChainTip message
{
"type": "getchaintip"
}
5.8 ChainTip
This message with type chaintip is sent as a response to the getchaintip message or it can be volunteered. It includes a single key called blockid with the block identifier of the tip of
  12

Cryptocurrencies - Project Kerma the current longest chain.
Valid ChainTip message
{
"type": "chaintip",
" b l o c k i d " : "0000000052a0e645eca917ae1c196e0d0a4fb756747f29ef52594d68484bb5e2 "
}
The receiving peer can then use getobject to retrieve the block contents, and then recur- sively follow up with more getobject messages for each parent block to retrieve the whole blockchain if needed.
5.9 GetMempool
Request the mempool of the peer with a message of type getmempool. There are no additional keys in this message. The peer should respond with a mempool message.
Valid getmempool message
{
"type":"getmempool"
}
5.10 Mempool
This message with type mempool is sent as a response to a getmempool message, or it can be volunteered. It includes a list of all transaction identifiers that the sending peer has in its mempool, i.e., are not yet confirmed. These are included in an array with the key txids.
Valid Mempool message
{
"type": "mempool", "txids": []
}
The receiving peer should attempt to add these transactions into their own mempool.
    13

Cryptocurrencies - Project Kerma
 5.11 Error
If your node receives an invalid message or object, you must send a message with type error. An error message must contain a standardized key name. Possible values for name are:
• INVALID_FORMAT:
– A message was sent that could not be parsed as valid JSON.
– A message is not a JSON object.
– A required key is missing or an additional key is present.
– An incorrect data type is encountered (e.g., a number was expected in the created key but a string was sent instead).
– A key that should hold a fixed value contains a different value (e.g., different block target) or does not meet the required format (e.g., non-printable characters in key note).
– A block was referenced at a position where a transaction was expected, or vice versa.
– A non-coinbase transaction has no inputs.
– A transaction has an output that holds a negative amount of coins.
– A peer in a peers message is syntactically invalid.
• INVALID_HANDSHAKE: A (semantic) error occurred related to the handshake, as spec- ified in section Hello.
• INVALID_TX_CONSERVATION:
– A transaction creates outputs holding more coins than the sum of the inputs.
– A transaction itself double spends, i.e. it uses the same output multiple times as input.
• INVALID_TX_SIGNATURE: A signature is not valid.
• INVALID_TX_OUTPOINT:
– A transaction in a block spends from the coinbase transaction in the same block.
– A transaction in a block double spends or references a transaction output that is not
in the current chain.
– A transaction references an outpoint (txid, index) but there is no such outpoint in
the transaction with id txid (i.e., index is too high).
• INVALID_BLOCK_POW: A block does not meet the required mining target.
• INVALID_BLOCK_TIMESTAMP:Thecreatedkeycontainsatimestampnotstrictlygreater than that of the parent block, or is in the future.
• INVALID_BLOCK_COINBASE:
14

Cryptocurrencies - Project Kerma
 – The coinbase transaction creates more coins than allowed.
– A coinbase transaction was referenced but is not at the first position.
– More than one coinbase transaction is referenced in a block.
– The height of a coinbase transaction does not match the height of the block that references it.
• INVALID_GENESIS: A block other than the genesis block with previd set to null was sent.
• UNKNOWN_OBJECT: An object was requested from a node that does not know about it. This does not indicate a faulty node.
• UNFINDABLE_OBJECT: The node could not verify an object because it failed to receive a dependent object after 5s. Note that when this error occurs, it does not necessarily mean that your communication partner is faulty - therefore you should not close the connection and remove your communication partner from your known nodes. Send this error also for every object whose verification you put on hold and must discard for now.
• INVALID_ANCESTRY: If verification of an ancestor of an object failed because it was found out to be invalid, send this error for every object whose verification you put on hold and can now be considered invalid.
The msg key of the error message contains a specific explanation explaining why this error occurred. You do not have to reply to an error message that is sent to you or perform any action. You can rely on TCP to detect if your communication partner has closed the connection because it considered your node as faulty. However, it might be interesting to log errors you receive because they might lead you to implementation errors in your node.
Valid error message
{
"type":"error",
"name":"INVALID_BLOCK_POW" ,
"msg":"Block 000b7379afe3c40e6f19677d2e6e098c631eb495d13b24dc8998091f91c4be26 does not meet mining target"
}
 
"""


from Peer import Peer
import constants as const
from message.msgexceptions import *
from jcs import canonicalize

import mempool
import objects
import peer_db
import object_db 

import asyncio
import ipaddress
import json
import random
import re
import sqlite3
import sys

PEERS = set()
CONNECTIONS = dict()
PENDING_PEERS = set()
BACKGROUND_TASKS = set()
BLOCK_VERIFY_TASKS = dict()
BLOCK_WAIT_LOCK = None
TX_WAIT_LOCK = None
MEMPOOL = mempool.Mempool(const.GENESIS_BLOCK_ID, {})
LISTEN_CFG = {
        "address": const.ADDRESS,
        "port": const.PORT
}

# Add peer to your list of peers
def add_peer(peer_host, peer_port):
    try:
        if not Peer.validate_peer(peer_host, peer_port):
            print(f"Invalid peer format: {peer_host}:{peer_port}")
            return
        new_peer = Peer(peer_host, peer_port)
        
        # Do not add banned peer addresses
        if new_peer.host in const.BANNED_HOSTS:
            print(f"Peer {new_peer} is banned.")
            return
            
        # Do not add loopback or multicast addresses
        try:
            # Try to interpret the host as an IP address
            ip = ipaddress.ip_address(new_peer.host)
            # Check if the IP address is loopback or multicast
            if ip.is_loopback or ip.is_multicast:
                print(f"Peer {new_peer} is a loopback or multicast address.")
                return
        except ValueError:
            # If it's not an IP address, just continue
            pass
            
        if new_peer in PEERS:
            #print(f"Peer {new_peer} is already known.")
            return
        else:
            peer_db.store_peer(new_peer, PEERS)
            PEERS.add(new_peer)
            print(f"New peer {new_peer} added to the list.")
    except Exception as e:
            print(f"Failed to add peer {peer_host}:{peer_port}: {str(e)}")

# Add connection if not already open
def add_connection(peer, queue, writer):
    ip, port = peer

    p = Peer(ip, port)
    if p in CONNECTIONS:
        raise Exception("Connection with {} already open!".format(peer))

    CONNECTIONS[p] = (queue, writer)


# Delete connection
def del_connection(peer):
    ip, port = peer
    del CONNECTIONS[Peer(ip, port)]

# Error message generator
def mk_error_msg(error_name, error_str):
    return {
        "type": "error",
        "name": error_name,
        "msg": error_str
    }

# Hello message generator
def mk_hello_msg():
    return{
        "type": "hello",
        "version": const.VERSION,
        "agent": const.AGENT
    }
    

def mk_getpeers_msg():
    return {
        "type": "getpeers"
    }

def mk_peers_msg():
    # Initialize the list of peers to include in the message
    peers_list = []

    # Add the current node (self) as the first peer if it's listening for connections
    if LISTEN_CFG['address'] and LISTEN_CFG['port']:
        self_peer = f"{LISTEN_CFG['address']}:{LISTEN_CFG['port']}"
        peers_list.append(self_peer)
    
    # Add up to 29 other known peers (to keep total size <= 30)
    known_peers = list(PEERS)  # Get a list from the set of known peers
    random.shuffle(known_peers)  # Randomize the peer order
    
    # Limit to 29 additional peers
    for peer in known_peers[:29]:
        peers_list.append(str(peer))  # Convert the Peer object to string (host:port)

    # Create and return the peers message
    peers_msg = {
        "type": "peers",
        "peers": peers_list
    }

    return peers_msg


def mk_getobject_msg(objid):
    return {
        "type": "getobject",
        "objectid": objid
    }

def mk_object_msg(obj_dict):
    return {
        "type": "object",
        "object": obj_dict
    }

def mk_ihaveobject_msg(objid):
    return {
        "type": "ihaveobject",
        "objectid": objid
    }

def mk_chaintip_msg(blockid):
    pass # TODO

def mk_mempool_msg(txids):
    pass # TODO

def mk_getchaintip_msg():
    pass # TODO

def mk_getmempool_msg():
    pass # TODO

# parses a message as json. returns decoded message
def parse_msg(msg_str):
    try:
        msg_dict = json.loads(msg_str)
        return msg_dict
    except json.JSONDecodeError:
        raise ErrorInvalidFormat("Invalid JSON format.")

# Send data over the network as a message
async def write_msg(writer, msg_dict):
    msg_str = json.dumps(msg_dict,separators=(',', ':')) + "\n"

    msg_bytes = msg_str.encode('utf-8')

    try:
        writer.write(msg_bytes)
        await writer.drain()
    except Exception as e:
        print(f"Failed to send message: {str(e)}")

def validate_keys(msg_dict, required_keys, optional_keys, msg_type):
    allowed_keys = required_keys | optional_keys

    # Check for invalid keys
    for key in msg_dict.keys():
        if key not in allowed_keys:
            raise ErrorInvalidFormat(f"Invalid key '{key}' in '{msg_type}' message.")
    
    # Check for missing required keys
    for key in required_keys:
        if key not in msg_dict.keys():
            raise ErrorInvalidFormat(f"Missing required key '{key}' in '{msg_type}' message.")

# Parse and validate the 'hello' message
def validate_hello_msg(msg_dict):

    required_keys = {"type", "version", "agent"}
    optional_keys = set()  # No optional keys for 'hello' message
    validate_keys(msg_dict, required_keys, optional_keys, "hello")
    
    version = msg_dict.get("version")
    if not version or not version.startswith(const.HELLO_VERSION) or len(version) != 6:
        raise ErrorInvalidFormat("Invalid 'version' in 'hello' message.")

    agent = msg_dict.get("agent")
    if not agent or len(agent) > const.HELLO_AGENT_MAX_LEN or not agent.isascii() or not agent.isprintable():
        raise ErrorInvalidFormat("Invalid 'agent' in 'hello' message.")

# Validate the 'peers' message
def validate_peers_msg(msg_dict):
    required_keys = {"type", "peers"}
    optional_keys = set()
    validate_keys(msg_dict, required_keys, optional_keys, "peers")
    
    if msg_dict.get("type") != "peers":
        raise ErrorInvalidFormat("Invalid 'peers' message type.")

    peers_list = msg_dict.get("peers")
    if not isinstance(peers_list, list) or len(peers_list) > 30:
        raise ErrorInvalidFormat("Invalid 'peers' list.")
    
    
    # Validate each peer in the list
    for peer in peers_list:
        # Ensure each peer entry has the correct format with host:port
        try:
            peer_host, peer_port = peer.split(':')
            peer_port = int(peer_port)  # Convert port to integer
            
            # Use Peer class to validate format
            if not Peer.validate_peer(peer_host, peer_port):
                raise ValueError  # Invalid format if not validated by Peer.validate_peer
            
        except (ValueError, AttributeError):
            # Raise error if any peer entry is malformed
            raise ErrorInvalidFormat(f"Invalid peer format: {peer}")
    


# Validate the 'getpeers' message
def validate_getpeers_msg(msg_dict):
    required_keys = {"type"}
    optional_keys = set()
    validate_keys(msg_dict, required_keys, optional_keys, "getpeers")
    if msg_dict.get("type") != "getpeers":
        raise ErrorInvalidFormat("Invalid 'getpeers' message type.")


# raise an exception if not valid
def validate_getchaintip_msg(msg_dict):
    pass # TODO

# raise an exception if not valid
def validate_getmempool_msg(msg_dict):
    pass # TODO

# raise an exception if not valid
def validate_error_msg(msg_dict):
    pass # TODO

# raise an exception if not valid
def validate_ihaveobject_msg(msg_dict):
    required_keys = {"type", "objectid"}
    optional_keys = set()
    validate_keys(msg_dict, required_keys, optional_keys, "ihaveobject")
    
    if not objects.validate_objectid(msg_dict.get("objectid")):
        raise ErrorInvalidFormat("Invalid 'objectid' in 'ihaveobject' message.")
    
    
# raise an exception if not valid
def validate_getobject_msg(msg_dict):
    required_keys = {"type", "objectid"}
    optional_keys = set()
    validate_keys(msg_dict, required_keys, optional_keys, "getobject")
    
    if not objects.validate_objectid(msg_dict.get("objectid")):
        raise ErrorInvalidFormat("Invalid 'objectid' in 'getobject' message.")

# raise an exception if not valid
def validate_object_msg(msg_dict):
    required_keys = {"type", "object"}
    optional_keys = set()
    validate_keys(msg_dict, required_keys, optional_keys, "object")
    
    obj_dict = msg_dict.get("object")
    if not obj_dict or not objects.validate_object(obj_dict):
        raise ErrorInvalidFormat("Invalid 'object' in 'object' message.")

# raise an exception if not valid
def validate_chaintip_msg(msg_dict):
    pass # todo
    
# raise an exception if not valid
def validate_mempool_msg(msg_dict):
    pass # todo
        
def validate_msg(msg_dict):
    
    # Check for missing type key
    if 'type' not in msg_dict.keys():
        raise ErrorInvalidFormat(f"Missing required key 'type' in message.")
    
    #Check if type is a string
    if not isinstance(msg_dict['type'], str):
        raise ErrorInvalidFormat(f"Invalid 'type' key in message (not a string).")
        
    msg_type = msg_dict['type']
    
    if msg_type == 'hello':
        validate_hello_msg(msg_dict)
    elif msg_type == 'getpeers':
        validate_getpeers_msg(msg_dict)
    elif msg_type == 'peers':
        validate_peers_msg(msg_dict)
    elif msg_type == 'getchaintip':
        validate_getchaintip_msg(msg_dict)
    elif msg_type == 'getmempool':
        validate_getmempool_msg(msg_dict)
    elif msg_type == 'error':
        validate_error_msg(msg_dict)
    elif msg_type == 'ihaveobject':
        validate_ihaveobject_msg(msg_dict)
    elif msg_type == 'getobject':
        validate_getobject_msg(msg_dict)
    elif msg_type == 'object':
        validate_object_msg(msg_dict)
    elif msg_type == 'chaintip':
        validate_chaintip_msg(msg_dict)
    elif msg_type == 'mempool':
        validate_mempool_msg(msg_dict)
    else:
        raise ErrorInvalidFormat(f"Unknown message type: {msg_type}")
        


def handle_peers_msg(msg_dict):
    peers_list = msg_dict.get("peers")
    
    for peer_str in peers_list:
        try:
            # Extract the host and port
            host, port = peer_str.split(':')
            port = int(port)
            
            # Add valid peers to known peers
            add_peer(host, port)
        except Exception as e:
            print(f"Failed to add peer {peer_str}: {str(e)}")



def handle_error_msg(msg_dict, peer_self):
    pass # TODO


async def handle_ihaveobject_msg(msg_dict, writer):
    # get the objectid from the message
    objid = msg_dict['objectid']
    
    # check if the object is already in the database
    if object_db.check_object_in_db(objid):
        print(f"Object {objid} already in database.")
        return
    
    await write_msg(writer, mk_getobject_msg(objid))


async def handle_getobject_msg(msg_dict, writer):
    # get the objectid from the message
    objid = msg_dict['objectid']
    
    # check if the object is in the database
    if not object_db.check_object_in_db(objid):
        # send an error message
        await write_msg(writer, mk_error_msg("UNKNOWN_OBJECT", f"Object {objid} not found."))
        return
    
    # get the object from the database
    obj_dict = object_db.get_object(objid)
    
    # send the object to the sender
    await write_msg(writer, mk_object_msg(obj_dict))
    
async def handle_object_msg(msg_dict, peer_self, writer):
    # get the object from the message
    obj_dict = msg_dict['object']
    
    # get the objectid
    objid = object_db.get_objid(obj_dict)
    print(f"Received object {objid}")
    
    # check if the object is already in the database
    if object_db.check_object_in_db(objid):
        print(f"Object {objid} already in database.")
        return
    
    # check if the object is valid
    if not objects.validate_object(obj_dict):
        print(f"Object {objid} is invalid.")
        return
    
    # store the object in the database
    object_db.store_object(obj_dict)
    
    print(f"Object {objid} stored in database.")
        
    
    # send an ihaveobject message to all connected peers
    for peer, (queue, peer_writer) in CONNECTIONS.items():
        if peer == Peer(peer_self[0], peer_self[1]):
            print(f"Skipping self: {peer}")
            continue
        await write_msg(peer_writer, mk_ihaveobject_msg(objid))

# return a list of transactions that tx_dict references
def gather_previous_txs(db_cur, tx_dict):
    # coinbase transaction
    if 'height' in tx_dict:
        return {}

    pass # TODO

# get the block, the current utxo and block height
def get_block_utxo_height(blockid):
    # TODO
    block = ''
    utxo = ''
    height = ''
    return (block, utxo, height)

# get all transactions as a dict txid -> tx from a list of ids
def get_block_txs(txids):
    pass # TODO


# Stores for a block its utxoset and height
def store_block_utxo_height(block, utxo, height: int):
    pass # TODO

# runs a task to verify a block
# raises blockverifyexception
async def verify_block_task(block_dict):
    pass # TODO

# adds a block verify task to queue and starting it
def add_verify_block_task(objid, block, queue):
    pass # TODO

# abort a block verify task
async def del_verify_block_task(task, objid):
    pass # TODO

# returns the chaintip blockid
def get_chaintip_blockid():
    pass # TODO


async def handle_getchaintip_msg(msg_dict, writer):
    pass # TODO


async def handle_getmempool_msg(msg_dict, writer):
    pass # TODO


async def handle_chaintip_msg(msg_dict):
    pass # TODO


async def handle_mempool_msg(msg_dict):
    pass # TODO

# Helper function
async def handle_queue_msg(msg_dict, writer):
    pass # TODO

async def handle_connection(reader, writer):
    read_task = None
    queue_task = None
    peer = None
    queue = asyncio.Queue()

    try:
        peer = writer.get_extra_info('peername')
        if not peer:
            raise Exception("Failed to get peername!")
        
        
        add_connection(peer, queue, writer)
        
        print(f"New connection with {peer}")
        

        # Send initial hello and getpeers messages
        await write_msg(writer, mk_hello_msg())
        print(f"Sent 'hello' message to {peer}")
        
        await write_msg(writer, mk_getpeers_msg())
        print(f"Sent 'getpeers' message to {peer}")

        # Start processing with the initial handshake
        first_msg = await asyncio.wait_for(reader.readline(), timeout=const.HELLO_MSG_TIMEOUT)
        first_msg_dict = parse_msg(first_msg)
        validate_msg(first_msg_dict)
        
        if first_msg_dict['type'] != 'hello':
            raise ErrorInvalidHandshake("First message is not 'hello'")

        print(f"Handshake complete with {peer}")
        
        msg_str = None

        while True:
            # Set up tasks to read from network and queue
            if read_task is None:
                read_task = asyncio.create_task(reader.readline())
            if queue_task is None:
                queue_task = asyncio.create_task(queue.get())

            done, pending = await asyncio.wait([read_task, queue_task], return_when=asyncio.FIRST_COMPLETED)

            # Process network message if available
            if read_task in done:
                msg_str = read_task.result()
                read_task = None  # Reset for next read
                
            # Process queue message if available
            if queue_task in done:
                queue_msg = queue_task.result()
                queue_task = None
                await handle_queue_msg(queue_msg, writer)
                queue.task_done()
                
            # if no message was received over the network continue
            if read_task is not None:
                continue
            
            msg_dict = parse_msg(msg_str)
            validate_msg(msg_dict)
            await handle_message(msg_dict, writer, peer)

    except  FaultyNodeException as e:
        print("{}: Detected Faulty Node: {}: {}".format(peer, e.error_name, e.message))
        try:
            await write_msg(writer, mk_error_msg(e.message, e.error_name))
        except:
            pass
                
    except asyncio.TimeoutError:
        await write_msg(writer, mk_error_msg("INVALID_HANDSHAKE", "Timeout waiting for 'hello' message"))
        print(f"Timeout waiting for handshake with {peer}")

    finally:
        print(f"Closing connection with {peer}")
        writer.close()
        del_connection(peer)
        if read_task is not None and not read_task.done():
            read_task.cancel()
        if queue_task is not None and not queue_task.done():
            queue_task.cancel()


async def handle_message(msg_dict, writer, peer):
    """Helper function to handle post-handshake messages."""
    msg_type = msg_dict['type']
    if msg_type == 'hello':
        raise ErrorInvalidHandshake("Received 'hello' message after handshake.")
    elif msg_type == 'getpeers':
        print(f"Received 'getpeers' request from {peer}")
        # Create and send the peers message
        peers_msg = mk_peers_msg()
        await write_msg(writer, peers_msg)
        print(f"Sent 'peers' message to {peer}")
    elif msg_type == 'peers':
        print(f"Received 'peers' message from {peer}")
        handle_peers_msg(msg_dict)
    elif msg_type == 'getobject':
        print(f"Received 'getobject' request from {peer}")
        await handle_getobject_msg(msg_dict, writer)
    elif msg_type == 'object':
        print(f"Received 'object' message from {peer}")
        await handle_object_msg(msg_dict, peer, writer)
    elif msg_type == 'ihaveobject':
        print(f"Received 'ihaveobject' message from {peer}")
        await handle_ihaveobject_msg(msg_dict, writer)
        print(f"Sent 'getobject' message to {peer}")
    else:
        print(f"Unknown message type received from {peer}: {msg_dict['type']}")





async def connect_to_node(peer: Peer):
    try:
        reader, writer = await asyncio.open_connection(peer.host, peer.port,
                limit=const.RECV_BUFFER_LIMIT)
    except Exception as e:
        print(str(e))
        return

    await handle_connection(reader, writer)


async def listen():
    server = await asyncio.start_server(handle_connection, LISTEN_CFG['address'],
            LISTEN_CFG['port'], limit=const.RECV_BUFFER_LIMIT)

    print("Listening on {}:{}".format(LISTEN_CFG['address'], LISTEN_CFG['port']))

    async with server:
        await server.serve_forever()


# bootstrap peers. connect to hardcoded peers
async def bootstrap():
    
    # Load peers from the database
    global PEERS
    PEERS = peer_db.load_peers()
    
    ALL_PEERS = PEERS.union(const.PRELOADED_PEERS)
    
    print(f"ALL_PEERS: {ALL_PEERS}")
    
    for peer in ALL_PEERS:
        add_peer(peer.host, peer.port)
        t = asyncio.create_task(connect_to_node(peer))
        BACKGROUND_TASKS.add(t)
        t.add_done_callback(lambda t: BACKGROUND_TASKS.remove(t))

# Ensure the node has at least the threshold number of active connections.
def resupply_connections():
    
    connections = set(CONNECTIONS.keys())
    
    if len(connections) >= const.LOW_CONNECTION_THRESHOLD:
        return
    
    npeers = const.LOW_CONNECTION_THRESHOLD - len(connections)
    available_peers = PEERS - connections
    
    if len(available_peers) == 0:
        print("Not enough peers available to reconnect.")
        return
    
    if len(available_peers) < npeers:
        npeers = len(available_peers)
        
    print(f"Opening {npeers} new connections.")
        
    for peer in random.sample(tuple(available_peers), npeers):
        t = asyncio.create_task(connect_to_node(peer))
        BACKGROUND_TASKS.add(t)
        t.add_done_callback(lambda t: BACKGROUND_TASKS.remove(t))
        

async def init():
    global BLOCK_WAIT_LOCK
    BLOCK_WAIT_LOCK = asyncio.Condition()
    global TX_WAIT_LOCK
    TX_WAIT_LOCK = asyncio.Condition()

    # Create bootstrap and listen tasks
    bootstrap_task = asyncio.create_task(bootstrap())
    listen_task = asyncio.create_task(listen())
    
    # sleep to allow the listen task to start
    await asyncio.sleep(2)
    
    
    # Service loop
    while True:
        print("Service loop reporting in.")
        print("Open connections: {}".format(set(CONNECTIONS.keys())))
        
        # Open more connections if necessary
        resupply_connections()

        # Delay between service loop iterations
        await asyncio.sleep(const.SERVICE_LOOP_DELAY)

    # Await the completion of bootstrap and listen tasks
    await bootstrap_task
    await listen_task


def main():
    
    # Create the database and objects table
    object_db.main()
    
    # Run the main event loop
    asyncio.run(init())


if __name__ == "__main__":
    if len(sys.argv) == 3:
        LISTEN_CFG['address'] = sys.argv[1]
        LISTEN_CFG['port'] = sys.argv[2]

    main()
