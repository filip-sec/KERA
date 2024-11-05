"""
#3 Application Objects
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

Cryptocurrencies - Project Kerma are "executed"

"""



from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from datetime import datetime
from jcs import canonicalize
import object_db

import copy
import hashlib
import json
import re
import sqlite3

import constants as const

# Regex for various formats
OBJECTID_REGEX = re.compile("^[0-9a-f]{64}$")
PUBKEY_REGEX = re.compile("^[0-9a-f]{64}$")
SIGNATURE_REGEX = re.compile("^[0-9a-f]{128}$")
NONCE_REGEX = re.compile("^[0-9a-f]{64}$")
TARGET_REGEX = re.compile("^[0-9a-f]{64}$")

# Syntactic checks
def validate_objectid(objid_str):
    return OBJECTID_REGEX.match(objid_str) is not None

def validate_pubkey(pubkey_str):
    return PUBKEY_REGEX.match(pubkey_str) is not None

def validate_signature(sig_str):
    return SIGNATURE_REGEX.match(sig_str) is not None

def validate_nonce(nonce_str):
    return NONCE_REGEX.match(nonce_str) is not None

def validate_target(target_str):
    return TARGET_REGEX.match(target_str) is not None


# Transaction input and output validation
def validate_transaction_input(in_dict):
    required_keys = {"outpoint", "sig"}
    if not all(key in in_dict for key in required_keys):
        return False

    outpoint = in_dict["outpoint"]
    if "index" not in outpoint or "txid" not in outpoint:
        return False
    if not validate_objectid(outpoint["txid"]):
        return False
    if not isinstance(outpoint["index"], int) or outpoint["index"] < 0:
        return False  # Ensure index is a non-negative integer

    # Validate the signature format
    if not validate_signature(in_dict["sig"]):
        return False

    # Check if referenced transaction exists in the database
    if not object_db.check_object_in_db(outpoint["txid"]):
        raise TXVerifyException("Referenced transaction does not exist in the database")

    return True

def validate_transaction_output(out_dict):
    required_keys = {"pubkey", "value"}
    if not all(key in out_dict for key in required_keys):
        return False
    if not validate_pubkey(out_dict["pubkey"]):
        return False
    if not isinstance(out_dict["value"], int) or out_dict["value"] < 0:
        return False  # Ensure value is a non-negative integer
    return True

# Perform signature verification
def verify_tx_signature(tx_dict, sig, pubkey):
    try:
        # Remove all signatures from inputs for signature verification
        tx_copy = copy.deepcopy(tx_dict)
        for inp in tx_copy["inputs"]:
            inp["sig"] = None

        # Canonicalize the transaction without signatures for verification
        message = canonicalize(tx_copy)
        public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pubkey))
        public_key.verify(bytes.fromhex(sig), message)
        return True
    except InvalidSignature:
        return False

class TXVerifyException(Exception):
    pass

def verify_transaction(tx_dict):
    total_input = 0
    total_output = sum(out["value"] for out in tx_dict["outputs"])

    # Retrieve inputs and their corresponding outputs
    for input_item in tx_dict["inputs"]:
        outpoint = input_item["outpoint"]
        
        # Ensure referenced transaction exists
        if not object_db.check_object_in_db(outpoint["txid"]):
            raise TXVerifyException("Referenced transaction does not exist in the database")
        
        # Query the referenced transaction
        con = sqlite3.connect(const.DB_NAME)
        cur = con.cursor()
        cur.execute("SELECT outputs FROM objects WHERE objectid = ?", (outpoint["txid"],))
        referenced_tx = cur.fetchone()
        con.close()

        if referenced_tx is None:
            raise TXVerifyException("Referenced transaction not found in the database")

        # Ensure referenced transaction has enough outputs
        referenced_outputs = json.loads(referenced_tx[0])
        if outpoint["index"] >= len(referenced_outputs):
            raise TXVerifyException("Invalid outpoint referenced (index out of bounds)")

        # Get the referenced output and validate its value
        ref_output = referenced_outputs[outpoint["index"]]
        total_input += ref_output["value"]

        # Verify signature validity
        if not verify_tx_signature(tx_dict, input_item["sig"], ref_output["pubkey"]):
            raise TXVerifyException("Invalid signature in transaction input")

    # Verify weak law of conservation
    if total_input < total_output:
        raise TXVerifyException("Input value is less than output value (violates conservation)")

    return True

def validate_object(obj_dict):
    if "type" not in obj_dict:
        return False

    if obj_dict["type"] == "transaction":
        return validate_transaction(obj_dict)
    elif obj_dict["type"] == "block":
        return validate_block(obj_dict)

    return False

def validate_transaction(tx_dict):
    if "height" in tx_dict:
        if not isinstance(tx_dict["height"], int) or tx_dict["height"] < 0:
            return False
        
        if "inputs" in tx_dict:
            return False
        
        if "outputs" not in tx_dict or not isinstance(tx_dict["outputs"], list):
            return False
        
        if len(tx_dict["outputs"]) != 1:
            return False
        
        if not validate_transaction_output(tx_dict["outputs"][0]):
            return False
        
        return True
        
    required_keys = {"inputs", "outputs"}
    if not all(key in tx_dict for key in required_keys):
        return False

    if not isinstance(tx_dict["inputs"], list) or not isinstance(tx_dict["outputs"], list):
        return False

    if len(tx_dict["inputs"]) == 0 or len(tx_dict["outputs"]) == 0:
        return False

    for inp in tx_dict["inputs"]:
        if not validate_transaction_input(inp):
            return False

    for out in tx_dict["outputs"]:
        if not validate_transaction_output(out):
            return False

    return True

def validate_block(block_dict):
    required_keys = {"txids", "nonce", "previd", "created", "T"}
    if not all(key in block_dict for key in required_keys):
        return False

    if not isinstance(block_dict["txids"], list):
        return False

    if not validate_nonce(block_dict["nonce"]):
        return False

    if not validate_target(block_dict["T"]):
        return False

    if not validate_objectid(block_dict["previd"]):
        return False

    if not isinstance(block_dict["created"], int) or block_dict["created"] < 0:
        return False
    
    
    # check if miner and note are ascii printable strings
    if "miner" in block_dict:
        if not isinstance(block_dict["miner"], str) or not all(ord(c) >= 0x20 and ord(c) <= 0x7e for c in block_dict["miner"]):
            return False
        
    if "note" in block_dict:
        if not isinstance(block_dict["note"], str) or not all(ord(c) >= 0x20 and ord(c) <= 0x7e for c in block_dict["note"]):
            return False

    return True


# Helper function to get unique object ID for a given object
def get_objid(obj_dict):
    return hashlib.blake2s(canonicalize(obj_dict)).hexdigest()

class BlockVerifyException(Exception):
    pass

# apply tx to utxo
# returns mining fee
def update_utxo_and_calculate_fee(tx, utxo):
    # todo
    return 0

# verify that a block is valid in the current chain state, using known transactions txs
def verify_block(block, prev_block, prev_utxo, prev_height, txs):
    # todo
    return 0