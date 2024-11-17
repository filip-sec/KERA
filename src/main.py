"""
3 Application Objects
Application objects are objects that must be stored by each node. These are content-addressed
by the blake2s hash of their JSON representation. Therefore, it is important to have the same
JSON representation as other clients so that the same objects are addressed by the same
hash. You must normalize your JSON and ensure it is in canonical JSON form. The examples
in this document contain extra whitespace for readability, but these must not be sent over the
network. The blake2s of the JSON contents is the objectid.
An application object is a JSON dictionary containing the type key and further keys depend-
ing on its type. There are two types of application objects: transactions and blocks. Their
objectids are called txid and blockid, respectively.
An application object must only contain keys that are specified, i.e., it must not contain addi-
tional keys. The same applies to messages.
3.1 Transactions
This represents a transaction and has the type transaction. It contains the key inputs
containing a non-empty array of inputs and the key outputs containing an array of outputs.
An output is a dictionary with keys value and pubkey. The value is a non-negative integer
indicating how much value is carried by the output. The value is denominated in picaker,
the smallest denomination in Kerma. 1 ker = 1012 picaker. The pubkey is a public key of the
2
Cryptocurrencies - Project Kerma
recipient of the money. The money carried by an output can be spend by its owner by using it
as an input in a future transaction.
An input contains a pointer to a previous output in the outpoint key and a signature in the
sig key. The outpoint key contains a dictionary of two keys: txid and index. The txid is
the objectid of the previous transaction, while the index is the natural number (zero-based)
indexing an output within that transaction. The sig key contains the signature.
Signatures are created using the private keys corresponding to the public keys that are
pointed to by their respective outpoint. Signatures are created on the plaintext which con-
sists of the transaction they (not their public keys!) are contained within, except that the sig
values are all replaced with null. This is necessary because a signature cannot sign itself.
Transactions must satisfy the weak law of conservation: The sum of input values must be
equal or exceed the sum of output values. Any remaining value can be collected as fees by
the miner confirming the transaction.
This is an example of a (syntactically) valid transaction:
Valid normal transaction
{
" type " : " transaction " ,
" inputs " : [
{
" outpoint ":{
" txid " : " f71408bf847d7dd15824574a7cd4afdfaaa2866286910675cd3fc371507aa196 " ,
" index ":0
} ,
" sig ":"3869a9ea9e7ed926a7c8b30fb71f6ed151a132b03fd5dae764f015c98271000e7
da322dbcfc97af7931c23c0fae060e102446ccff0f54ec00f9978f3a69a6f0f"
}
] ,
" outputs " : [
{
"pubkey":"077a2683d776a71139fd4db4d00c16703ba0753fc8bdc4bd6fc56614e659cde3" ,
" value":5100000000
}
]
}
However, this example transaction could in principle still be (semantically) invalid in the fol-
lowing cases:
• An object with id f7140..aa196 exists but is a block (INVALID_FORMAT).
• The referenced transaction f7140...aa196 has no output with index 0
(INVALID_TX_OUTPOINT).
3
Cryptocurrencies - Project Kerma
• The referenced transaction f7140...aa196 is invalid (INVALID_ANCESTRY1).
• The output at index 0 in the referenced transaction f7140...aa196 holds less than
5100000000 picaker (INVALID_TX_CONSERVATION).
• Verifying the signature using the public key in output at index 0 in transaction
f7140...aa196 failed (INVALID_TX_SIGNATURE).
3.1.1 Coinbase Transactions
A coinbase transaction is a special form of a transaction and is used by a miner to collect
the block reward. See below section Blocks for more info. If the transaction is a coinbase
transaction, then it must not contain an inputs key but it must contain an integer height key
with the block’s height as the value.
This is an example of a valid coinbase transaction:
Valid coinbase transaction
{
" type " : " transaction " ,
" height " : 1 ,
" outputs " : [
{
"pubkey" : " 3 f0bc71a375b574e4bda3ddf502fe1afd99aa020bf6049adfe525d9ad18ff33f " ,
" value":50000000000000
}
]
}
3.2 Blocks
This represents a block and has the type block. It must contain the following keys:
• txids, which is a list of the transaction identifiers within the block.
• nonce, which is a 32-byte hexified value that can be chosen arbitrarily.
• previd, which is the object identifier of the previous block in the chain. Only the genesis
block is allowed to differ from that by having a previd set to null.
• created, which is an (integer) UNIX timestamp in seconds.
• T, which is a 32-byte hexadecimal integer and is the mining target.
1Since your node will never store invalid objects, upon receiving the transaction, it will attempt to fetch the
referenced transaction from its peer, leaving the object verification pending. When the peer sends the (invalid)
referenced transaction, your node will find out that it is invalid and will release the pending object verification
by rejecting the transaction with an INVALID_ANCESTRY error
4
Cryptocurrencies - Project Kerma
Optionally it can contain a miner key and a note key, which can be any ASCII-printable2
strings up to 128 characters long each.
Here is an example of a valid block:
Valid block
{
"T":"00000000abc00000000000000000000000000000000000000000000000000000" ,
" created":1671148800,
"miner " : " grader " ,
"nonce":"1000000000000000000000000000000000000000000000000000000001aaf999 " ,
" note " : " This block has a coinbase transaction " ,
" previd":"0000000052a0e645eca917ae1c196e0d0a4fb756747f29ef52594d68484bb5e2" ,
" txids " : [ " 6 ebfb4c8e8e9b19dcf54c6ce3e1e143da1f473ea986e70c5cb8899a4671c933a " ] ,
" type " : " block "
}
Block validity mandates that the block satisfies the proof-of-work equation: blockid < T.
The genesis block has a null previd. This is our genesis block:
Genesis block
{
"T":"00000000abc00000000000000000000000000000000000000000000000000000" ,
" created":1671062400,
"miner " : "Marabu" ,
"nonce":"000000000000000000000000000000000000000000000000000000021bea03ed" ,
" note " : " The New York Times 2022−12−13: Sci ent is ts Achieve Nuclear Fusion Breakthrough With Blast of 192 Lasers " ,
" previd " : null ,
" txids " : [ ] ,
" type " : " block "
}
All valid chains must extend genesis. Each block must have a timestamp which is later than
its predecessor but not after the current time.
The transaction identifiers (txids) in a block may (but is not required to) contain one coinbase
transaction. This transaction must be the first in txids. It has exactly one output which
generates 50 ·1012 new picaker and also collects fees from the transactions confirmed in the
block. The value in this output cannot exceed the sum of the new coins plus the fees, but it can
be less than that. The height in the coinbase transaction must match the height of the block
the transaction is contained in. This is so that coinbase transactions with the same public
key in different blocks are distinct. The block height is defined as the distance to the genesis
block: The genesis block has a height of 0, a block that has the genesis block as its parent has
a height of 1 etc. The coinbase transaction cannot be spent in the same block. However, a
transaction can spend from a previous, non-coinbase transaction in the same block. The order
of the identifiers of the confirmed transactions in a block defines the order these transactions
2ASCII-printable characters have hexcodes 0x20 to 0x7e
5
Cryptocurrencies - Project Kerma
are "executed".
All blocks must have a target T of:
00000000abc00000000000000000000000000000000000000000000000000000.
The genesis blockid is:
0000000052a0e645eca917ae1c196e0d0a4fb756747f29ef52594d68484bb5e2.
Check this to ensure your implementation is performing correct JSON canonicalization
4 Block Validation
In this exercise, you will implement block validation for your Kerma node.
1. Create the logic to represent a block, as defined in the protocol description.
2. Check that the block contains all required fields and that they are of the correct format.
3. Ensure that the target is the one required, i.e.
"00000000abc00000000000000000000000000000000000000000000000000000"
4. Check the proof-of-work.
5. Check that for all the txids in the block, you have the corresponding transaction in your
local object database. If not, then send a "getobject" message to your peers in order
to get the transaction and leave the validation of the block pending. Resume validation
once you received all transactions.
6. For each transaction in the block, check that the transaction is valid, and update your
UTXO set based on the transaction. More details on this in Section 5. If any transaction
is invalid, the whole block must be considered invalid.
7. Check for coinbase transactions. There can be at most one coinbase transaction in a
block. If present, then the txid of the coinbase transaction must be at index 0 in txids.
The coinbase transaction cannot be spent in another transaction in the same block (this
is in order to make the law of conservation for the coinbase transaction easier to verify).
8. Validate the coinbase transaction if there is one.
(a) Check that the coinbase transaction has no inputs, exactly one output and a height.
Check that the height and the public key are of the valid format.
(b) Verify the law of conservation for the coinbase transaction. The output of the coin-
base transaction can be at most the sum of transaction fees in the block plus the
block reward. In our protocol, the block reward is a constant 50 ×1012 picaker. The
fee of a transaction is the sum of its input values minus the sum of its output values.
9. When you receive a block object from the network, validate it. If valid, then store the
block in your local database and gossip the block to all of your peers as you did with
transactions in the last task.
2
Cryptocurrencies (WS2024/25) Dr. Zeta Avarikioti, Prof. Matteo Maffei
5 Maintaining UTXO Sets
Overview - UTXO set
The UTXO set ("unspent transaction output set") contains all unspent transaction
outputs and is used to quickly check if a new transaction may use a transaction output
as an input.
The following scenario explains how a UTXO set should be maintained: Assume that
a chain of blocks (g, b0, b1) with g the genesis block is valid. This defines an execution
order of all transactions included in these blocks. Call these transactions (t0, t1).
Assume further:
• t0 is a coinbase transaction and the only transaction in block b0.
• t1 is a transaction spending from the first output of t0 and creating two outputs. It
is contained in b1.
Now assume that a node N regards (g, b0) as the current longest chain, because it has
not yet received block b1.
The UTXO set of N at this point is {(t0, 0)}, with (t0, 0) denoting the output at index 0 of
transaction t0.
Now one of its peers sends N block b1. N fetches the transaction t1 and validates it
"in isolation", i.e. everything you did in the previous task. Additionally, it now has to
check if this transaction may spend from its referenced inputs. It could be the case
that t1 would spend from an output of a transaction which is not confirmed in the
chain or would spend from a transaction output that has already been spent by another
transaction; in both cases the whole block must be considered invalid. t1 spends from
(t0, 0): This is possible, because this particular transaction output exists and is not yet
spent. To determine this, N just checks if this transaction output is in the current UTXO
set. Transaction t1 then gets "executed", which means that N needs to update its UTXO
set: Let u be the current UTXO set, i the set of inputs of t1, and o the set of its outputs.
Then, the updated UTXO state u′is defined as u′= (u \i) ∪o.
The reason for maintaining a UTXO set is because verification of new transactions is as
simple as a set inclusion check - otherwise you might need to traverse the whole chain
to determine if an output is unspent.
In this exercise, you will implement a UTXO set and update it by executing the transactions
of each block that you receive. This task will not yet cover all the features of the UTXO set.
We will revisit this part in future homeworks.
1. For each block in your database, store a UTXO set that will be computed by executing
the transactions in that block. This set is not modified when you receive transactions,
only when they get executed during handling of new block objects.
2. When you receive a new block, you will compute the UTXO set after that block in the
3
Cryptocurrencies (WS2024/25) Dr. Zeta Avarikioti, Prof. Matteo Maffei
following way. To begin with, initialize the UTXO set to the UTXO set after the parent
block (the block corresponding to the previd). Note that the UTXO set after the genesis
block is empty. For each transaction in the block:
(a) Validate the transaction as per your validation logic implemented in Task 2. Addi-
tionally, check that each input of the transaction corresponds to an output that is
present in the UTXO set. This means that the output exists and also that the output
has not been spent yet.
(b) Apply the transaction by removing UTXOs that are spent and adding UTXOs that
are created. Update the UTXO set accordingly.
(c) Repeat steps a-b for the next transaction using the updated UTXO set. This is
because a transaction can spend from an output of a non-coinbase transaction in
the same block"""


from Peer import Peer
from peers import Peers
import constants as const
from message.msgexceptions import *
from jcs import canonicalize

import mempool
import objects
import peers
import create_db

import asyncio
import ipaddress
import json
import random
import re
import sqlite3
import sys

PEERS = Peers()
CONNECTIONS = dict()
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
def add_peer(peer):
    # Do not add banned peer addresses
    if peer.host in const.BANNED_HOSTS:
        return

    # Do not add loopback or multicast addrs
    try:
        ip = ipaddress.ip_address(peer.host)

        if ip.is_loopback or ip.is_multicast:
            return
    except:
        pass

    PEERS.addPeer(peer)


# Add connection if not already open
def add_connection(peer, queue):
    ip, port = peer

    p = Peer(ip, port)
    if p in CONNECTIONS:
        raise Exception("Connection with {} already open!".format(peer))

    CONNECTIONS[p] = queue

# Delete connection
def del_connection(peer):
    ip, port = peer
    p = Peer(ip, port)
    del CONNECTIONS[p]
    PEERS.removePeer(p)
    PEERS.save()

# Make msg objects
def mk_error_msg(error_str, error_name):
    return {"type": "error", "name": error_name, "msg": error_str}

def mk_hello_msg():
    return {"type": "hello", "version": const.VERSION, "agent": const.AGENT}

def mk_getpeers_msg():
    return {"type": "getpeers"}

def mk_peers_msg():
    pl = [f'{peer}' for peer in PEERS.getPeers()]
    if len(pl) > 30:
        pl = random.sample(pl, 30)
    return {"type": "peers", "peers": pl}

def mk_getobject_msg(objid):
    return {"type":"getobject", "objectid":objid}

def mk_object_msg(obj_dict):
    return {"type":"object", "object":obj_dict}

def mk_ihaveobject_msg(objid):
    return {"type":"ihaveobject", "objectid":objid}

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
        msg = json.loads(msg_str)
    except Exception as e:
        raise ErrorInvalidFormat("JSON parse error: {}".format(str(e)))

    if not isinstance(msg, dict):
        raise ErrorInvalidFormat("Received message not a dictionary!")
    if not 'type' in msg:
        raise ErrorInvalidFormat("Key 'type' not set in message!")
    if not isinstance(msg['type'], str):
        raise ErrorInvalidFormat("Key 'type' is not a string!")

    return msg

# Send data over the network as a message
async def write_msg(writer, msg_dict):
    msg_bytes = canonicalize(msg_dict)
    writer.write(msg_bytes)
    writer.write(b'\n')
    await writer.drain()

# Check if message contains no invalid keys,
# raises an ErrorInvalidFormat
def validate_allowed_keys(msg_dict, allowed_keys, msg_type):
    if len(set(msg_dict.keys()) - set(allowed_keys)) != 0:
        raise ErrorInvalidFormat(
            "Message malformed: {} message contains invalid keys!".format(msg_type))


# Validate the hello message
# raises an exception
def validate_hello_msg(msg_dict):
    if msg_dict['type'] != 'hello':
        raise ErrorInvalidHandshake("Message type is not 'hello'!")

    try:
        if 'version' not in msg_dict:
            raise ErrorInvalidFormat(
                "Message malformed: version is missing!")

        version = msg_dict['version']
        if not isinstance(version, str):
            raise ErrorInvalidFormat(
                "Message malformed: version is not a string!")

        if not re.compile('0\.10\.\d').fullmatch(version):
            raise ErrorInvalidFormat(
                "Version invalid")

        validate_allowed_keys(msg_dict, ['type', 'version', 'agent'], 'hello')
    except ErrorInvalidFormat as e:
        raise e

    except Exception as e:
        raise ErrorInvalidFormat("Message malformed: {}".format(str(e)))


# returns true iff host_str is a valid hostname
def validate_hostname(host_str):
    if not re.compile('[a-zA-Z\d\.\-\_]{3,50}').fullmatch(host_str):
        return False
        #raise ErrorInvalidFormat(f"Peer '{host_str}' not valid: Does not match regex")
    
    if not re.compile('.*[a-zA-Z].*').fullmatch(host_str):
        return False
        #raise ErrorInvalidFormat(f"Peer '{host_str}' not valid: Does not contain a letter")

    if not '.' in host_str[1:-1]:
        return False
        # raise ErrorInvalidFormat(f"Peer '{host_str}' not valid: Does not contain a dot")
    
    return True

# returns true iff host_str is a valid ipv4 address
def validate_ipv4addr(host_str):
    if not re.compile('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}').fullmatch(host_str):
        return False
    
    try:
        ip = ipaddress.IPv4Address(host_str)
    except:
        return False

    return True

# returns true iff peer_str is a valid peer address
def validate_peer_str(peer_str):
    peer_parts = peer_str.rsplit(':', 1)
    if len(peer_parts) != 2:
        raise ErrorInvalidFormat("No port given")

    host_str = peer_parts[0]
    port_str = peer_parts[1]

    port = 0
    try:
        port = int(port_str, 10)
    except:
        raise ErrorInvalidFormat("Port not a decimal number")

    if port <= 0:
        raise ErrorInvalidFormat("Port too small")
    
    if port > 65535:
        raise ErrorInvalidFormat("Port too high")

    if (not validate_hostname(host_str)) and (not validate_ipv4addr(host_str)):
        raise ErrorInvalidFormat("Given peer address is neither a hostname nor an ipv4 address")

    return True

# raise an exception if not valid
def validate_peers_msg(msg_dict):
    try:
        if 'peers' not in msg_dict:
            raise ErrorInvalidFormat("Message malformed: peers is missing!")

        peers = msg_dict['peers']
        if not isinstance(peers, list):
            raise ErrorInvalidFormat(
                "Message malformed: peers is not a list!")

        validate_allowed_keys(msg_dict, ['type', 'peers'], 'peers')

        if len(msg_dict['peers']) > 30:
            raise ErrorInvalidFormat('Too many peers in peers msg')

        for p in peers:
            if not isinstance(p, str):
                raise ErrorInvalidFormat(
                    "Message malformed: peer is not a string!")

            validate_peer_str(p)

    except ErrorInvalidFormat as e:
        raise e
    except Exception as e:
        raise ErrorInvalidFormat("Message malformed: {}".format(str(e)))

# raise an exception if not valid
def validate_getpeers_msg(msg_dict):
    if msg_dict['type'] != 'getpeers':
        raise ErrorInvalidFormat("Message type is not 'getpeers'!")

    validate_allowed_keys(msg_dict, ['type'], 'getpeers')

# raise an exception if not valid
def validate_getchaintip_msg(msg_dict):
    pass # TODO

# raise an exception if not valid
def validate_getmempool_msg(msg_dict):
    pass # TODO

# raise an exception if not valid
def validate_error_msg(msg_dict):
    if msg_dict['type'] != 'error':
        raise ErrorInvalidFormat("Message type is not 'error'!") # assert: false

    try:
        if 'msg' not in msg_dict:
            raise ErrorInvalidFormat("Message malformed: msg is missing!")

        msg = msg_dict['msg']
        if not isinstance(msg, str):
            raise ErrorInvalidFormat("Message malformed: msg is not a string!")

        if 'name' not in msg_dict:
            raise ErrorInvalidFormat("Message malformed: name is missing!")

        name = msg_dict['name']
        if not isinstance(name, str):
            raise ErrorInvalidFormat("Message malformed: name is not a string!")

        validate_allowed_keys(msg_dict, ['type', 'msg', 'name'], 'error')

    except ErrorInvalidFormat as e:
        raise e
    except Exception as e:
        raise ErrorInvalidFormat("Message malformed: {}".format(str(e)))

# raise an exception if not valid
def validate_ihaveobject_msg(msg_dict):
    if msg_dict['type'] != 'ihaveobject':
        raise ErrorInvalidFormat("Message type is not 'ihaveobject'!") # assert: false

    try:
        if 'objectid' not in msg_dict:
            raise ErrorInvalidFormat("Message malformed: objectid is missing!")

        objectid = msg_dict['objectid']
        if not isinstance(objectid, str):
            raise ErrorInvalidFormat("Message malformed: objectid is not a string!")

        if not objects.validate_objectid(objectid):
            raise ErrorInvalidFormat("Message malformed: objectid invalid!")

        validate_allowed_keys(msg_dict, ['type','objectid'], 'ihaveobject')

    except ErrorInvalidFormat as e:
        raise e
    except Exception as e:
        raise ErrorInvalidFormat("Message malformed: {}".format(str(e)))

# raise an exception if not valid
def validate_getobject_msg(msg_dict):
    if msg_dict['type'] != 'getobject':
        raise ErrorInvalidFormat("Message type is not 'getobject'!") # assert: false

    try:
        if 'objectid' not in msg_dict:
            raise ErrorInvalidFormat("Message malformed: objectid is missing!")

        objectid = msg_dict['objectid']
        if not isinstance(objectid, str):
            raise ErrorInvalidFormat("Message malformed: objectid is not a string!")

        if not objects.validate_objectid(objectid):
            raise ErrorInvalidFormat("Message malformed: objectid invalid!")

        validate_allowed_keys(msg_dict, ['type','objectid'], 'getobject')

    except ErrorInvalidFormat as e:
        raise e
    except Exception as e:
        raise ErrorInvalidFormat("Message malformed: {}".format(str(e)))

# raise an exception if not valid
def validate_object_msg(msg_dict):
    if msg_dict['type'] != 'object':
        raise ErrorInvalidFormat("Message type is not 'object'!") # assert: false

    try:
        if 'object' not in msg_dict:
            raise ErrorInvalidFormat("Message malformed: object is missing!")

        obj = msg_dict['object']
        objects.validate_object(obj)

        validate_allowed_keys(msg_dict, ['type','object'], 'object')

    except ErrorInvalidFormat as e:
        raise e
    except Exception as e:
        raise ErrorInvalidFormat("Message malformed: {}".format(str(e)))

# raise an exception if not valid
def validate_chaintip_msg(msg_dict):
    pass # todo
    
# raise an exception if not valid
def validate_mempool_msg(msg_dict):
    pass # todo
        
def validate_msg(msg_dict):
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
        raise ErrorInvalidFormat("Message type {} not valid!".format(msg_type))


def handle_peers_msg(msg_dict):
    for p in msg_dict['peers']:
        peer_parts = p.rsplit(':', 1)

        host_str, port_str = peer_parts

        port = int(port_str, 10)

        peer = Peer(host_str, port)
        add_peer(peer)
    PEERS.save()


def handle_error_msg(msg_dict, peer_self):
    print("{}: Received error of type {}: {}".format(peer_self, msg_dict['name'], msg_dict['msg']))


async def handle_ihaveobject_msg(msg_dict, writer):
    objid = msg_dict['objectid']

    con = sqlite3.connect(const.DB_NAME)
    try:
        cur = con.cursor()
        res = cur.execute("SELECT obj FROM objects WHERE oid = ?", (objid,))

        # already have object
        if not res.fetchone() is None:
            return
    finally:
        con.close()

    await write_msg(writer, mk_getobject_msg(objid))


async def handle_getobject_msg(msg_dict, writer):
    objid = msg_dict['objectid']
    obj_tuple = None

    con = sqlite3.connect(const.DB_NAME)
    try:
        cur = con.cursor()
        res = cur.execute("SELECT obj FROM objects WHERE oid = ?", (objid,))

        obj_tuple = res.fetchone()
        # don't have object
        if obj_tuple is None:
            return
    finally:
        con.close()

    obj_dict = objects.expand_object(obj_tuple[0])

    await write_msg(writer, mk_object_msg(obj_dict))

# return a list of transactions that tx_dict references
def gather_previous_txs(db_cur, tx_dict):
    # coinbase transaction
    if 'height' in tx_dict:
        return {}

    # regular transaction
    prev_txs = {}
    for i in tx_dict['inputs']:
        ptxid = i['outpoint']['txid']

        res = db_cur.execute("SELECT obj FROM objects WHERE oid = ?", (ptxid,))
        first_res = res.fetchone()

        if not first_res is None:
            ptx_str = first_res[0]
            ptx_dict = objects.expand_object(ptx_str)

            if ptx_dict['type'] != 'transaction':
                raise ErrorInvalidFormat(f"Transaction attempts to spend from a block")

            prev_txs[ptxid] = ptx_dict

    return prev_txs

# get the block, the current utxo and block height
def get_block_utxo_height(blockid):
    con = sqlite3.connect(const.DB_NAME)
    try:
        cur = con.cursor()

        # Fetch block details
        res = cur.execute("SELECT obj FROM objects WHERE oid = ?", (blockid,))
        block_row = res.fetchone()
        if not block_row:
            raise Exception(f"Previous block {blockid} not found.")

        block = objects.expand_object(block_row[0])

        # Fetch UTXO and height
        res = cur.execute("SELECT utxo, height FROM block_utxo WHERE blockid = ?", (blockid,))
        utxo_row = res.fetchone()
        if not utxo_row:
            raise Exception(f"UTXO and height for block {blockid} not found.")

        utxo = json.loads(utxo_row[0])  # Deserialize UTXO set
        height = utxo_row[1]

        return block, utxo, height
    finally:
        con.close()


# get all transactions as a dict txid -> tx from a list of ids
def get_block_txs(txids):
    pass # TODO

def store_block_utxo_height(block, utxo, height):
    con = sqlite3.connect(const.DB_NAME)
    try:
        cur = con.cursor()

        # Serialize UTXO set
        utxo_json = json.dumps(list(utxo))

        # Store block UTXO and height
        cur.execute(
            "INSERT INTO block_utxo (blockid, utxo, height) VALUES (?, ?, ?)",
            (objects.get_objid(block), utxo_json, height),
        )
        con.commit()
    finally:
        con.close()


# what to do when an object message arrives
async def handle_object_msg(msg_dict, peer_self, writer):
    obj_dict = msg_dict['object']
    objid = objects.get_objid(obj_dict)
    print(f"Received object with id {objid}: {obj_dict}")

    ip_self, port_self = peer_self
    peer_self_obj = Peer(ip_self, port_self)

    con = sqlite3.connect(const.DB_NAME)
    try:
        cur = con.cursor()
        res = cur.execute("SELECT obj FROM objects WHERE oid = ?", (objid,))

        # If the object already exists, skip processing
        if res.fetchone() is not None:
            return

        print(f"Processing new object: {objid}")

        if obj_dict['type'] == 'transaction':
            # Process transactions as before
            prev_txs = gather_previous_txs(cur, obj_dict)
            objects.verify_transaction(obj_dict, prev_txs)

        elif obj_dict['type'] == 'block':
            # Fetch previous block, UTXO set, and height
            prev_block, prev_utxo, prev_height = get_block_utxo_height(obj_dict['previd'])

            # Collect all transactions referenced in the block
            txs = {}
            missing_txids = []
            for txid in obj_dict['txids']:
                tx = objects.get_transaction_from_db(txid)
                if tx:
                    txs[txid] = tx
                else:
                    missing_txids.append(txid)

            # If there are missing transactions, request them from peers and defer validation
            if missing_txids:
                print(f"Missing transactions: {missing_txids}")
                for missing_txid in missing_txids:
                    await write_msg(writer, mk_getobject_msg(missing_txid))
                return  # Defer block validation until missing transactions are received

            # Verify the block
            try:
                updated_utxo, updated_height = objects.verify_block(
                    obj_dict, prev_block, prev_utxo, prev_height, txs
                )
            except Exception as e:
                print(f"Block verification failed for {objid}: {e}")
                raise ErrorInvalidFormat(f"Block verification failed: {e}")

            # If the block is valid, store it and propagate
            print(f"Block {objid} verified successfully.")
            cur.execute("INSERT INTO objects (oid, obj) VALUES (?, ?)", (objid, json.dumps(obj_dict)))
            con.commit()

            # Store updated UTXO and height
            store_block_utxo_height(obj_dict, updated_utxo, updated_height)

        else:
            raise ErrorInvalidFormat(f"Unknown object type: {obj_dict['type']}")

        print(f"Stored object {objid} in database.")

    except NodeException as e:
        con.rollback()
        print(f"Failed to process object {objid}: {e}")
        raise e
    except Exception as e:
        con.rollback()
        raise e
    finally:
        con.close()

    # Propagate the new object to peers
    for k, q in CONNECTIONS.items():
        await q.put(mk_ihaveobject_msg(objid))



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
    # just send whatever another connection requested over the network
    await write_msg(writer, msg_dict)

# how to handle a connection
async def handle_connection(reader, writer):
    read_task = None
    queue_task = None

    peer = None
    queue = asyncio.Queue()
    try:
        peer = writer.get_extra_info('peername')
        if not peer:
            raise Exception("Failed to get peername!")
        
        add_connection(peer, queue)

        print("New connection with {}".format(peer))
    except Exception as e:
        print(str(e))
        try:
            writer.close()
        except:
            pass
        return

    try:
        # Send initial messages
        await write_msg(writer, mk_hello_msg())
        await write_msg(writer, mk_getpeers_msg())
        
        # Complete handshake
        firstmsg_str = await asyncio.wait_for(reader.readline(),
                timeout=const.HELLO_MSG_TIMEOUT)
        firstmsg = parse_msg(firstmsg_str)
        validate_hello_msg(firstmsg)

        msg_str = None
        while True:
            if read_task is None:
                read_task = asyncio.create_task(reader.readline())
            if queue_task is None:
                queue_task = asyncio.create_task(queue.get())

            # wait for network or queue messages
            done, pending = await asyncio.wait([read_task, queue_task],
                    return_when = asyncio.FIRST_COMPLETED)
            if read_task in done:
                msg_str = read_task.result()
                if not msg_str:
                    # client closed the connection
                    print(f"{peer} disconnected.")
                    break
                read_task = None
            # handle queue messages
            if queue_task in done:
                queue_msg = queue_task.result()
                queue_task = None
                await handle_queue_msg(queue_msg, writer)
                queue.task_done()

            # if no message was received over the network continue
            if read_task is not None:
                continue

            try:

                msg = parse_msg(msg_str)
                validate_msg(msg)
                
                print("{}: Received this message: {}".format(peer, msg))

                msg_type = msg['type']
                if msg_type == 'hello':
                    raise ErrorInvalidHandshake("Additional handshake initiated by peer!")
                elif msg_type == 'getpeers':
                    await write_msg(writer, mk_peers_msg())
                elif msg_type == 'peers':
                    handle_peers_msg(msg)
                elif msg_type == 'error':
                    handle_error_msg(msg, peer)
                elif msg_type == 'ihaveobject':
                    await handle_ihaveobject_msg(msg, writer)
                elif msg_type == 'getobject':
                    await handle_getobject_msg(msg, writer)
                elif msg_type == 'object':
                    await handle_object_msg(msg, peer, writer)
                elif msg_type == 'getchaintip':
                    await handle_getchaintip_msg(msg, writer)
                elif msg_type == 'chaintip':
                    await handle_chaintip_msg(msg)
                elif msg_type == 'getmempool':
                    await handle_getmempool_msg(msg, writer)
                elif msg_type == 'mempool':
                    await handle_mempool_msg(msg)
                else:
                    pass # assert: false
            except NonfaultyNodeException as e:
                print("{}: An error occured: {}: {}".format(peer, e.error_name, e.message))
                await write_msg(writer, mk_error_msg(e.message, e.error_name))

    except asyncio.exceptions.TimeoutError:
        print("{}: Timeout".format(peer))
        try:
            await write_msg(writer, mk_error_msg("Timeout in handshake triggered", "INVALID_HANDSHAKE"))
        except:
            pass
    except FaultyNodeException as e:
        PEERS.removePeer(peer)
        PEERS.save()
        print("{}: Detected Faulty Node: {}: {}".format(peer, e.error_name, e.message))
        try:
            await write_msg(writer, mk_error_msg(e.message, e.error_name))
        except:
            pass
    except Exception as e:
        print("{}: An error occured: {}".format(peer, str(e)))
    finally:
        print("Closing connection with {}".format(peer))
        writer.close()
        del_connection(peer)
        if read_task is not None and not read_task.done():
            read_task.cancel()
        if queue_task is not None and not queue_task.done():
            queue_task.cancel()


async def connect_to_node(peer: Peer):
    try:
        reader, writer = await asyncio.open_connection(peer.host, peer.port,
                limit=const.RECV_BUFFER_LIMIT)
    except Exception as e:
        print(f"failed to connect to peer {peer.host}:{peer.port}: {str(e)}")

        # remove this peer from your known peers, unless this is a bootstrap peer
        if not peer.isBootstrap:
            PEERS.removePeer(peer)
            PEERS.save()
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
    for p in const.PRELOADED_PEERS:
        add_peer(p)
        t = asyncio.create_task(connect_to_node(p))
        BACKGROUND_TASKS.add(t)
        t.add_done_callback(BACKGROUND_TASKS.discard)

# connect to some peers
def resupply_connections():
    cons = set(CONNECTIONS.keys())

    if len(cons) >= const.LOW_CONNECTION_THRESHOLD:
        return

    npeers = const.LOW_CONNECTION_THRESHOLD - len(cons)
    available_peers = PEERS.getPeers() - cons

    if len(available_peers) == 0:
        print("Not enough peers available to reconnect.")
        return

    if len(available_peers) < npeers:
        npeers = len(available_peers)

    print("Connecting to {} new peers.".format(npeers))

    chosen_peers = random.sample(tuple(available_peers), npeers)
    for p in chosen_peers:
        t = asyncio.create_task(connect_to_node(p))
        BACKGROUND_TASKS.add(t)
        t.add_done_callback(BACKGROUND_TASKS.discard)


async def init():
    global BLOCK_WAIT_LOCK
    BLOCK_WAIT_LOCK = asyncio.Condition()
    global TX_WAIT_LOCK
    TX_WAIT_LOCK = asyncio.Condition()

    PEERS = Peers() # this automatically loads the peers from file

    bootstrap_task = asyncio.create_task(bootstrap())
    listen_task = asyncio.create_task(listen())

    # Service loop
    while True:
        print("Service loop reporting in.")
        print("Open connections: {}".format(set(CONNECTIONS.keys())))

        # Open more connections if necessary
        resupply_connections()

        await asyncio.sleep(const.SERVICE_LOOP_DELAY)

    await bootstrap_task
    await listen_task


def main():
    # create the database if it does not yet exist
    create_db.createDB()
    asyncio.run(init())


if __name__ == "__main__":
    if len(sys.argv) == 3:
        LISTEN_CFG['address'] = sys.argv[1]
        LISTEN_CFG['port'] = sys.argv[2]

    main()
