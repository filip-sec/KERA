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
    if block_dict['created'] < 0:
        raise ErrorInvalidFormat("Block object invalid: created key negative")
    if block_dict['created'] > int(datetime.now().timestamp()):
        raise ErrorInvalidFormat("Block object invalid: created key in the future")

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