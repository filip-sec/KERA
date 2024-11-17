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
the same block

    5.11 Error
If your node receives an invalid message or object, you must send a message with type error.
An error message must contain a standardized key name. Possible values for name are:
• INVALID_FORMAT:
– A message was sent that could not be parsed as valid JSON.
– A message is not a JSON object.
– A required key is missing or an additional key is present.
– An incorrect data type is encountered (e.g., a number was expected in the created
key but a string was sent instead).
– A key that should hold a fixed value contains a different value (e.g., different block
target) or does not meet the required format (e.g., non-printable characters in key
note).
– A block was referenced at a position where a transaction was expected, or vice
versa.
– A non-coinbase transaction has no inputs.
– A transaction has an output that holds a negative amount of coins.
– A peer in a peers message is syntactically invalid.
• INVALID_HANDSHAKE: A (semantic) error occurred related to the handshake, as spec-
ified in section Hello.
• INVALID_TX_CONSERVATION:
– A transaction creates outputs holding more coins than the sum of the inputs.
– A transaction itself double spends, i.e. it uses the same output multiple times as
input.
• INVALID_TX_SIGNATURE: A signature is not valid.
• INVALID_TX_OUTPOINT:
– A transaction in a block spends from the coinbase transaction in the same block.
– A transaction in a block double spends or references a transaction output that is not
in the current chain.
– A transaction references an outpoint (txid, index) but there is no such outpoint in
the transaction with id txid (i.e., index is too high).
• INVALID_BLOCK_POW: A block does not meet the required mining target.
• INVALID_BLOCK_TIMESTAMP: The created key contains a timestamp not strictly greater
than that of the parent block, or is in the future.
• INVALID_BLOCK_COINBASE:
14
Cryptocurrencies - Project Kerma
– The coinbase transaction creates more coins than allowed.
– A coinbase transaction was referenced but is not at the first position.
– More than one coinbase transaction is referenced in a block.
– The height of a coinbase transaction does not match the height of the block that
references it.
• INVALID_GENESIS: A block other than the genesis block with previd set to null was
sent.
• UNKNOWN_OBJECT: An object was requested from a node that does not know about it.
This does not indicate a faulty node.
• UNFINDABLE_OBJECT: The node could not verify an object because it failed to receive
a dependent object after 5s. Note that when this error occurs, it does not necessarily
mean that your communication partner is faulty - therefore you should not close the
connection and remove your communication partner from your known nodes. Send this
error also for every object whose verification you put on hold and must discard for now.
• INVALID_ANCESTRY: If verification of an ancestor of an object failed because it was
found out to be invalid, send this error for every object whose verification you put on
hold and can now be considered invalid


"""


from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from datetime import datetime
from jcs import canonicalize

from message.msgexceptions import *

import copy
import hashlib
import json
import re
import sqlite3

import constants as const

# perform syntactic checks. returns true iff check succeeded
OBJECTID_REGEX = re.compile("^[0-9a-f]{64}$")
def validate_objectid(objid_str):
    if not isinstance(objid_str, str):
        return False
    return OBJECTID_REGEX.match(objid_str)

PUBKEY_REGEX = re.compile("^[0-9a-f]{64}$")
def validate_pubkey(pubkey_str):
    if not isinstance(pubkey_str, str):
        return False
    return PUBKEY_REGEX.match(pubkey_str)

SIGNATURE_REGEX = re.compile("^[0-9a-f]{128}$")
def validate_signature(sig_str):
    if not isinstance(sig_str, str):
        return False
    return SIGNATURE_REGEX.match(sig_str)

NONCE_REGEX = re.compile("^[0-9a-f]{64}$")
def validate_nonce(nonce_str):
    if not isinstance(nonce_str, str):
        return False
    return NONCE_REGEX.match(nonce_str)


TARGET_REGEX = re.compile("^[0-9a-f]{64}$")
def validate_target(target_str):
    if not isinstance(target_str, str):
        return False
    return TARGET_REGEX.match(target_str)

# syntactic checks
def validate_transaction_input(in_dict):
    if not isinstance(in_dict, dict):
        raise ErrorInvalidFormat("Not a dictionary!")

    if 'sig' not in in_dict:
        raise ErrorInvalidFormat("sig not set!")
    if not isinstance(in_dict['sig'], str):
        raise ErrorInvalidFormat("sig not a string!")
    if not validate_signature(in_dict['sig']):
        raise ErrorInvalidFormat("sig not syntactically valid!")

    if 'outpoint' not in in_dict:
        raise ErrorInvalidFormat("outpoint not set!")
    if not isinstance(in_dict['outpoint'], dict):
        raise ErrorInvalidFormat("outpoint not a dictionary!")

    outpoint = in_dict['outpoint']
    if 'txid' not in outpoint:
        raise ErrorInvalidFormat("txid not set!")
    if not isinstance(outpoint['txid'], str):
        raise ErrorInvalidFormat("txid not a string!")
    if not validate_objectid(outpoint['txid']):
        raise ErrorInvalidFormat("txid not a valid objectid!")
    if 'index' not in outpoint:
        raise ErrorInvalidFormat("index not set!")
    if not isinstance(outpoint['index'], int):
        raise ErrorInvalidFormat("index not an integer!")
    if outpoint['index'] < 0:
        raise ErrorInvalidFormat("negative index!")
    if len(set(outpoint.keys()) - set(['txid', 'index'])) != 0:
        raise ErrorInvalidFormat("Additional keys present in outpoint!")

    if len(set(in_dict.keys()) - set(['sig', 'outpoint'])) != 0:
        raise ErrorInvalidFormat("Additional keys present!")

    return True # syntax check done

# syntactic checks
def validate_transaction_output(out_dict):
    if not isinstance(out_dict, dict):
        raise ErrorInvalidFormat("Not a dictionary!")

    if 'pubkey' not in out_dict:
        raise ErrorInvalidFormat("pubkey not set!")
    if not isinstance(out_dict['pubkey'], str):
        raise ErrorInvalidFormat("pubkey not a string!")
    if not validate_pubkey(out_dict['pubkey']):
        raise ErrorInvalidFormat("pubkey not syntactically valid!")

    if 'value' not in out_dict:
        raise ErrorInvalidFormat("value not set!")
    if not isinstance(out_dict['value'], int):
        raise ErrorInvalidFormat("value not an integer!")
    if out_dict['value'] < 0:
        raise ErrorInvalidFormat("negative value!")

    if len(set(out_dict.keys()) - set(['pubkey', 'value'])) != 0:
        raise ErrorInvalidFormat("Additional keys present!")

    return True # syntax check done

# syntactic checks
def validate_transaction(trans_dict):
    if not isinstance(trans_dict, dict):
        raise ErrorInvalidFormat("Transaction object invalid: Not a dictionary!") # assert: false

    if 'type' not in trans_dict:
        raise ErrorInvalidFormat("Transaction object invalid: Type not set") # assert: false
    if not isinstance(trans_dict['type'], str):
        raise ErrorInvalidFormat("Transaction object invalid: Type not a string") # assert: false
    if not trans_dict['type'] == 'transaction':
        raise ErrorInvalidFormat("Transaction object invalid: Type not 'transaction'") # assert: false

    if 'outputs' not in trans_dict:
        raise ErrorInvalidFormat("Transaction object invalid: No outputs key set")
    if not isinstance(trans_dict['outputs'], list):
        raise ErrorInvalidFormat("Transaction object invalid: Outputs key not a list")

    index = 0
    for output in trans_dict['outputs']:
        try:
            validate_transaction_output(output)
        except ErrorInvalidFormat as e:
            raise ErrorInvalidFormat(f"Transaction object invalid: Output at index {index} invalid: {e.message}")
        index += 1

    # check for coinbase transaction
    if 'height' in trans_dict:
        # this is a coinbase transaction
        if not isinstance(trans_dict['height'], int):
            raise ErrorInvalidFormat("Coinbase transaction object invalid: Height not an integer")
        if trans_dict['height'] < 0:
            raise ErrorInvalidFormat("Coinbase transaction object invalid: Negative height")

        if len(trans_dict['outputs']) > 1:
            raise ErrorInvalidFormat("Coinbase transaction object invalid: More than one output set")

        if len(set(trans_dict.keys()) - set(['type', 'height', 'outputs'])) != 0:
            raise ErrorInvalidFormat("Coinbase transaction object invalid: Additional keys present")
        return

    # this is a normal transaction
    if not 'inputs' in trans_dict:
        raise ErrorInvalidFormat("Normal transaction object invalid: Inputs not set")

    if not isinstance(trans_dict['inputs'], list):
        raise ErrorInvalidFormat("Normal transaction object invalid: Inputs not a list")
    for input in trans_dict['inputs']:
        try:
            validate_transaction_input(input)
        except ErrorInvalidFormat as e:
            raise ErrorInvalidFormat(f"Normal transaction object invalid: Input at index {index} invalid: {e.message}")
        index += 1
    if len(trans_dict['inputs']) == 0:
        raise ErrorInvalidFormat(f"Normal transaction object invalid: No input set")

    if len(set(trans_dict.keys()) - set(['type', 'inputs', 'outputs'])) != 0:
        raise ErrorInvalidFormat(f"Normal transaction object invalid: Additional key present")

    return True # syntax check done

# syntactic checks
def validate_block(block_dict):
    if not isinstance(block_dict, dict):
        raise ErrorInvalidFormat("Block object invalid: Not a dictionary!") # assert: false

    if 'type' not in block_dict:
        raise ErrorInvalidFormat("Block object invalid: Type not set") # assert: false
    if not isinstance(block_dict['type'], str):
        raise ErrorInvalidFormat("Block object invalid: Type not a string") # assert: false
    if not block_dict['type'] == 'block':
        raise ErrorInvalidFormat("Block object invalid: Type not 'block'") # assert: false

    if 'txids' not in block_dict:
        raise ErrorInvalidFormat("Block object invalid: No txids key set")
    if not isinstance(block_dict['txids'], list):
        raise ErrorInvalidFormat("Block object invalid: txids key not a list")

    if 'nonce' not in block_dict:
        raise ErrorInvalidFormat("Block object invalid: No nonce key set")
    if not isinstance(block_dict['nonce'], str):
        raise ErrorInvalidFormat("Block object invalid: nonce key not a string")
    if not validate_nonce(block_dict['nonce']):
        raise ErrorInvalidFormat("Block object invalid: nonce key not syntactically valid")

    if 'previd' not in block_dict:
        raise ErrorInvalidFormat("Block object invalid: No previd key set")
    if not isinstance(block_dict['previd'], str):
        raise ErrorInvalidFormat("Block object invalid: previd key not a string")
    if not validate_objectid(block_dict['previd']):
        raise ErrorInvalidFormat("Block object invalid: previd key not syntactically valid")

    if 'created' not in block_dict:
        raise ErrorInvalidFormat("Block object invalid: No created key set")
    if not isinstance(block_dict['created'], int):
        raise ErrorInvalidFormat("Block object invalid: created key not an integer")

    if 'T' not in block_dict:
        raise ErrorInvalidFormat("Block object invalid: No T key set")
    if not isinstance(block_dict['T'], str):
        raise ErrorInvalidFormat("Block object invalid: T key not a string")
    
    if not validate_target(block_dict['T']):
        raise ErrorInvalidFormat("Block object invalid: T key not syntactically valid")
    
    if 'miner' in block_dict:
        if not isinstance(block_dict['miner'], str):
            raise ErrorInvalidFormat("Block object invalid: miner key not a string")
        if len(block_dict['miner']) > 128:
            raise ErrorInvalidFormat("Block object invalid: miner key too long")
        
    if 'note' in block_dict:
        if not isinstance(block_dict['note'], str):
            raise ErrorInvalidFormat("Block object invalid: note key not a string")
        if len(block_dict['note']) > 128:
            raise ErrorInvalidFormat("Block object invalid: note key too long")
        
    
    if len(set(block_dict.keys()) - set(['txids', 'nonce', 'previd', 'created', 'T', 'miner', 'note'])) != 0:
        raise ErrorInvalidFormat("Block object invalid: Additional keys present")
    
    return True # syntax check done


# syntactic checks
def validate_object(obj_dict):
    if not isinstance(obj_dict, dict):
        raise ErrorInvalidFormat("Object invalid: Not a dictionary!")

    if 'type' not in obj_dict:
        raise ErrorInvalidFormat("Object invalid: Type not set!")
    if not isinstance(obj_dict['type'], str):
        raise ErrorInvalidFormat("Object invalid: Type not a string")

    obj_type = obj_dict['type']
    if obj_type == 'transaction':
        return validate_transaction(obj_dict)
    elif obj_type == 'block':
        return validate_block(obj_dict)

    raise ErrorInvalidFormat("Object invalid: Unknown object type")

def expand_object(obj_str):
    return json.loads(obj_str)

def get_objid(obj_dict):
    return hashlib.blake2s(canonicalize(obj_dict)).hexdigest()

# perform semantic checks

# verify the signature sig in tx_dict using pubkey
def verify_tx_signature(tx_dict, sig, pubkey):
    tx_local = copy.deepcopy(tx_dict)

    for i in tx_local['inputs']:
        i['sig'] = None

    pubkey_obj = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pubkey))
    sig_bytes = bytes.fromhex(sig)

    try:
        pubkey_obj.verify(sig_bytes, canonicalize(tx_local))
    except InvalidSignature:
        return False

    return True

class TXVerifyException(Exception):
    pass

# semantic checks
# assert: tx_dict is syntactically valid
def verify_transaction(tx_dict, input_txs):
    # coinbase transaction
    if 'height' in tx_dict:
        return # assume all syntactically valid coinbase transactions are valid

    # regular transaction
    insum = 0 # sum of input values
    in_dict = dict()
    for i in tx_dict['inputs']:
        ptxid = i['outpoint']['txid']
        ptxidx = i['outpoint']['index']

        if ptxid in in_dict:
            if ptxidx in in_dict[ptxid]:
                raise ErrorInvalidTxConservation(f"The same input ({ptxid}, {ptxidx}) was used multiple times in this transaction")
            else:
                in_dict[ptxid].add(ptxidx)
        else:
            in_dict[ptxid] = {ptxidx}

        if ptxid not in input_txs:
            raise ErrorUnknownObject(f"Transaction {ptxid} not known")

        ptx_dict = input_txs[ptxid]

        # just to be sure
        if ptx_dict['type'] != 'transaction':
            raise ErrorInvalidFormat("Previous TX '{}' is not a transaction!".format(ptxid))

        if ptxidx >= len(ptx_dict['outputs']):
            raise ErrorInvalidTxOutpoint("Invalid output index in previous TX '{}'!".format(ptxid))

        output = ptx_dict['outputs'][ptxidx]
        if not verify_tx_signature(tx_dict, i['sig'], output['pubkey']):
            raise ErrorInvalidTxSignature("Invalid signature from previous TX '{}'!".format(ptxid))

        insum = insum + output['value']

    if insum < sum([o['value'] for o in tx_dict['outputs']]):
        raise ErrorInvalidTxConservation("Sum of inputs < sum of outputs!")

class BlockVerifyException(Exception):
    pass

def get_transaction_from_db(txid):
    con = sqlite3.connect(const.DB_NAME)
    try:
        cur = con.cursor()
        res = cur.execute("SELECT obj FROM objects WHERE oid = ?", (txid,))
        row = res.fetchone()
        if row is None:
            return None
        return expand_object(row[0])
    finally:
        con.close()
        

# apply tx to utxo
# returns mining fee
def update_utxo_and_calculate_fee(tx, utxo):
    inputs_value = 0
    outputs_value = 0

    # Process inputs
    for input in tx['inputs']:
        outpoint = (input['outpoint']['txid'], input['outpoint']['index'])
        if outpoint not in utxo:
            raise ErrorInvalidTxOutpoint(f"UTXO for {outpoint} not found!")
        
        input_tx = get_transaction_from_db(outpoint[0])
        if input_tx is None:
            raise ErrorUnknownObject(f"Transaction {outpoint[0]} not found in database")
        
        if outpoint[1] >= len(input_tx['outputs']):
            raise ErrorInvalidTxOutpoint(f"Output index {outpoint[1]} not found in transaction {outpoint[0]}")
        
        output = input_tx['outputs'][outpoint[1]]
        inputs_value += output['value']
        utxo.remove(outpoint)
        
    # Process outputs
    for i, output in enumerate(tx['outputs']):
        if output['value'] < 0:
            raise ErrorInvalidTxConservation(f"Output {i} has negative value!")
        outputs_value += output['value']
        utxo.add((get_objid(tx), i))
        
    return inputs_value - outputs_value


# verify that a block is valid in the current chain state, using known transactions txs
def verify_block(block, prev_block, prev_utxo, prev_height, txs):
    
    # verify the block's target less than the target
    if int(block['T'], 16) >= int(const.TARGET, 16):
        raise ErrorInvalidBlockPOW("Block does not meet the required mining target")
    
    # verify the block's timestamp is greater than the previous block's timestamp
    if block['created'] <= prev_block['created']:
        raise ErrorInvalidBlockTimestamp("Block timestamp not strictly greater than that of the parent block")
    
    first_tx_is_coinbase = False
    
    #check if first txid is a coinbase transaction
    if len(block['txids']) > 0:
        first_tx = get_transaction_from_db(block['txids'][0])
        if first_tx is None:
            raise ErrorUnknownObject(f"Transaction {block['txids'][0]} not found in database")
        if 'height' in first_tx:
            first_tx_is_coinbase = True
            height = first_tx['height']
            if height != prev_height + 1:
                raise ErrorInvalidBlockCoinbase("Coinbase transaction height does not match the height of the block")
        
        
    # now for each transaction except the coinbase in the block execute the transaction
    utxo = copy.deepcopy(prev_utxo)
    fee = 0
    for txid in block['txids']:
        if txid == block['txids'][0] and first_tx_is_coinbase:
            continue
        
        tx = get_transaction_from_db(txid)
        if tx is None:
            raise ErrorUnknownObject(f"Transaction {txid} not found in database")
        
        #if transaction is coinbase raise error
        if 'height' in tx:
            raise ErrorInvalidBlockCoinbase("Coinbase transaction referenced but is not at the first position")
        
        fee += update_utxo_and_calculate_fee(tx, utxo)
        
    #verify coinbase transaction
    if first_tx_is_coinbase:
        max_reward = fee + const.BLOCK_REWARD
        if len(first_tx['outputs']) != 1:
            raise ErrorInvalidBlockCoinbase("Coinbase transaction creates more than one output")
        
        if first_tx['outputs'][0]['value'] > max_reward:
            raise ErrorInvalidBlockCoinbase("Coinbase transaction creates more coins than allowed")
    
    # return the new utxo set and new height
    return utxo, prev_height + 1