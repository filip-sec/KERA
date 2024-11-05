from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from datetime import datetime
from jcs import canonicalize
import object_db
from message.msgexceptions import *

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
        raise ErrorUnknownObject("Referenced transaction does not exist in the database")

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


def verify_tx_signature(tx_dict, sig_hex, pubkey_hex):
    # Step 1: Make a deep copy of the transaction dictionary to modify for signing
    tx_to_sign = copy.deepcopy(tx_dict)
    
    # Step 2: Replace all `sig` fields with null in the copied transaction
    for inp in tx_to_sign.get("inputs", []):
        inp["sig"] = None
    
    # Step 3: Canonicalize the modified transaction
    # Convert to canonical JSON bytes (assuming a `canonicalize` function is available)
    tx_bytes = canonicalize(tx_to_sign)
    
    print("Canonicalized transaction bytes:", tx_bytes)

    # Step 4: Convert the public key and signature from hex to bytes
    pubkey_bytes = bytes.fromhex(pubkey_hex)
    signature_bytes = bytes.fromhex(sig_hex)

    # Step 5: Deserialize the public key
    public_key = Ed25519PublicKey.from_public_bytes(pubkey_bytes)
    
    # Step 6: Verify the signature using the Ed25519 public key
    try:
        public_key.verify(signature_bytes, tx_bytes)
        print("Signature verified successfully")
        return True
    except InvalidSignature:
        print("Invalid signature")
        return False




def verify_transaction(tx_dict):
    # Check if transaction is a coinbase transaction
    if "height" in tx_dict:
        print("Verifying coinbase transaction")
        
        if not isinstance(tx_dict["height"], int) or tx_dict["height"] < 0:
            raise TXVerifyException("Invalid height in coinbase transaction")
        if "inputs" in tx_dict:
            raise TXVerifyException("Coinbase transaction must not contain inputs")
        if "outputs" not in tx_dict or not isinstance(tx_dict["outputs"], list):
            raise TXVerifyException("Coinbase transaction must contain outputs")
        if len(tx_dict["outputs"]) != 1:
            raise TXVerifyException("Coinbase transaction must contain exactly one output")
        if not validate_transaction_output(tx_dict["outputs"][0]):
            raise TXVerifyException("Invalid output in coinbase transaction")
        return True
    
    print("Verifying transaction")
    
    # Check if transaction contains inputs and outputs
    if "inputs" not in tx_dict or "outputs" not in tx_dict:
        raise TXVerifyException("Transaction must contain inputs and outputs")
    if not isinstance(tx_dict["inputs"], list) or not isinstance(tx_dict["outputs"], list):
        raise TXVerifyException("Inputs and outputs must be lists")
    

    # Check if the sum of input values is less than or equal to the sum of output values
    input_sum = 0
    for inp in tx_dict["inputs"]:        
        # Fetch the referenced transaction from the database
        ref_tx = object_db.get_object(inp["outpoint"]["txid"])
        
        if inp["outpoint"]["index"] >= len(ref_tx["outputs"]):
            raise TXVerifyException("Invalid output index in referenced transaction")
        input_sum += ref_tx["outputs"][inp["outpoint"]["index"]]["value"]
        

    output_sum = sum(out["value"] for out in tx_dict["outputs"])
    
    if input_sum < output_sum:
        raise TXVerifyException("Sum of input values is less than sum of output values")
    
    
    # Verify each input signature
    for inp in tx_dict["inputs"]:
        # Fetch the referenced transaction from the database
        ref_tx = object_db.get_object(inp["outpoint"]["txid"])
        if not verify_tx_signature(tx_dict, inp["sig"], ref_tx["outputs"][inp["outpoint"]["index"]]["pubkey"]):
            raise TXVerifyException("Invalid signature in transaction")
        
    print("Transaction verified successfully")
    return True
    

def validate_object(obj_dict):
    if "type" not in obj_dict:
        raise ErrorInvalidFormat("Object type not specified")

    #validate transaction and verify transaction
    if obj_dict["type"] == "transaction":
        if not validate_transaction(obj_dict):
            raise ErrorInvalidFormat("Invalid transaction format")
        
        print("Validated transaction")
        
        verify_transaction(obj_dict)
        
    elif obj_dict["type"] == "block":
        validate_block(obj_dict)

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