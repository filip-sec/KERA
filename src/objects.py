from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from datetime import datetime
from jcs import canonicalize

import sqlite3
import copy

from message.msgexceptions import *

import copy
import hashlib
import json
import re
import time

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

HUMAN_READABLE_REGEX = re.compile("^[ -~]*$")
def validate_human_readable(s):
    if not isinstance(s, str):
        return False
    return HUMAN_READABLE_REGEX.match(s)

# note that the target is hardcoded
def validate_target(target_str):
    if not isinstance(target_str, str):
        return False
    return const.BLOCK_TARGET == target_str

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
        raise ErrorInvalidFormat("Block object invalid: Not a dictionary!")

    if 'type' not in block_dict:
        raise ErrorInvalidFormat("Block object invalid: Type not set!")
    if not isinstance(block_dict['type'], str):
        raise ErrorInvalidFormat("Block object invalid: Type not a string!")
    if not block_dict['type'] == 'block':
        raise ErrorInvalidFormat("Block object invalid: Type not 'block'!")

    if int(get_objid(block_dict), 16) >= int(const.BLOCK_TARGET, 16):
        raise ErrorInvalidBlockPOW(f"Block does not satisfy proof-of-work equation (has an objectid of {get_objid(block_dict)})!")

    if 'txids' not in block_dict:
        raise ErrorInvalidFormat("Block object invalid: txids not set!")
    if not isinstance(block_dict['txids'], list):
        raise ErrorInvalidFormat("Block object invalid: txids not a list!")
    if not all(validate_objectid(t) for t in block_dict['txids']):
        raise ErrorInvalidFormat("Block object invalid: txids contain an invalid formatted transaction id!")

    if 'nonce' not in block_dict:
        raise ErrorInvalidFormat("Block object invalid: nonce not set")
    if not isinstance(block_dict['nonce'], str):
        raise ErrorInvalidFormat("Block object invalid: nonce not a string!")
    if not validate_nonce(block_dict['nonce']):
        raise ErrorInvalidFormat("Block object invalid: nonce not of the required format!")

    if 'previd' not in block_dict:
        raise ErrorInvalidFormat("Block object invalid: previd not set!")

    if block_dict['previd'] is None:
        if get_objid(block_dict) != const.GENESIS_BLOCK_ID:
            raise ErrorInvalidGenesis("Block object invalid: previd is null but this is not the genesis block")
        else:
            pass # this is the genesis block
    else:
        if not isinstance(block_dict['previd'], str):
            raise ErrorInvalidFormat("Block object invalid: previd not null and not a string")
        if not validate_objectid(block_dict['previd']):
            raise ErrorInvalidFormat("Block object invalid: previd not of correct format")

    if 'created' not in block_dict:
        raise ErrorInvalidFormat("Block object invalid: created not set!")
    if not isinstance(block_dict['created'], int):
        raise ErrorInvalidFormat("Block object invalid: created not an int!")
    ts = block_dict['created']
    if ts < 0:
        raise ErrorInvalidFormat("Block object invalid: created timestamp smaller than zero")
    try:
        datetime.utcfromtimestamp(ts)
        if ts > time.time():
            raise ErrorInvalidBlockTimestamp("Block object invalid: created timestamp greater than current time")
    except Exception:
        raise ErrorInvalidBlockTimestamp("Block object invalid: created timestamp could not be parsed!")

    if 'T' not in block_dict:
        raise ErrorInvalidFormat("Block object invalid: T not set!")
    if not isinstance(block_dict['T'], str):
        raise ErrorInvalidFormat("Block object invalid: T not a string!")
    if not validate_target(block_dict['T']):
        raise ErrorInvalidFormat("Block object invalid: T not of valid format!")

    if 'miner' in block_dict:
        if not isinstance(block_dict['miner'], str):
            raise ErrorInvalidFormat("Block object invalid: miner not a string!")
        if not validate_human_readable(block_dict['miner']):
            raise ErrorInvalidFormat("Block object invalid: miner field invalid format")

    if 'note' in block_dict:
        if not isinstance(block_dict['note'], str):
            raise ErrorInvalidFormat("Block object invalid: note not a string!")
        if not validate_human_readable(block_dict['note']):
            raise ErrorInvalidFormat("Block object invalid: note field invalid format")

    block_dict_copy = copy.copy(block_dict)
    # remove optional keys...
    if 'miner' in block_dict_copy:
        block_dict_copy.pop('miner')
    if 'note' in block_dict_copy:
        block_dict_copy.pop('note')
    # ... to check for required keys
    if len(set(block_dict_copy.keys()) - set(['type', 'txids', 'nonce', 'previd', 'created', 'T'])) != 0:
        raise ErrorInvalidFormat("Block object invalid: Contains additional keys")

    return True

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

    tx_id = get_objid(tx_dict)

    missing_objects = []

    for i in tx_dict['inputs']:
        ptxid = i['outpoint']['txid']

        if ptxid not in input_txs:
            missing_objects.append(ptxid)

    if len(missing_objects) > 0:
        raise NeedMoreObjects(f"Transaction {tx_id} needs more objects {missing_objects}", missing_objects)

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

def get_block_utxo_height(blockid):
    con = sqlite3.connect(const.DB_NAME)
    try:
        cur = con.cursor()

        # TODO: maybe collapse this into a single joined query

        res = cur.execute("SELECT obj FROM objects WHERE oid = ?", (blockid,))
        block_tuple = res.fetchone()
        if block_tuple is None:
            return (None, None, None)

        block = expand_object(block_tuple[0])

        res = cur.execute("SELECT utxoset FROM utxo WHERE blockid = ?", (blockid,))
        utxo_tuple = res.fetchone()
        if utxo_tuple is None:
            return (block, None, None)

        utxo = expand_object(utxo_tuple[0])

        res = cur.execute("SELECT height FROM heights WHERE blockid = ?", (blockid,))
        height_tuple = res.fetchone()
        if height_tuple is None:
            return (block, utxo, None)

        height = height_tuple[0]

        return (block, utxo, height)

    finally:
        con.close()

# get all transactions as a dict txid -> tx from a list of ids
def get_block_txs(txids):
    txs = dict()

    con = sqlite3.connect(const.DB_NAME)
    try:
        cur = con.cursor()

        for txid in txids:
            res = cur.execute("SELECT obj FROM objects WHERE oid = ?", (txid,))
            tx_tuple = res.fetchone()
            if tx_tuple is not None:
                txs[txid] = expand_object(tx_tuple[0])

        return txs

    finally:
        con.close()


def verify_block(block_dict):
    print(f"Called verify_block for block {block_dict}")
    blockid = get_objid(block_dict)

    prev_utxo = None
    prev_block = None
    prev_height = None

    previd = block_dict['previd']
    prev_block, prev_utxo, prev_height = get_block_utxo_height(previd)

    missing_objects = []
    
    # check if we have all TXs, fetch them if necessary
    txs = get_block_txs(block_dict['txids'])
    missing_objects = set(block_dict['txids']) - set(txs.keys())

    if prev_block is None:
        missing_objects.add(previd)

    print(f'Set of missing objects: {missing_objects}')
    if len(missing_objects) > 0:
        raise NeedMoreObjects(f"Block {blockid} requires objects {missing_objects}", missing_objects)

    new_utxo, height = verify_block_tail(block_dict, prev_block, prev_utxo, prev_height, txs)

    # if everything checks out store the block, its UTXO and its height and
    # broadcast the new block's ID to all connected peers.
    print("Adding new object '{}'".format(blockid))
    return new_utxo, height

# apply tx to utxo
# returns mining fee
def update_utxo_and_calculate_fee(tx, utxo):
    txid = get_objid(tx)

    invalue = 0
    for inp in tx['inputs']:
        in_txid = inp['outpoint']['txid']
        in_idx = "{}".format(inp['outpoint']['index'])

        if in_txid not in utxo:
            raise ErrorInvalidTxOutpoint("Input for TX {} not in UTXO!".format(txid))
        if in_idx not in utxo[in_txid]:
            raise ErrorInvalidTxOutpoint("Input for TX {} not in UTXO!".format(txid))

        invalue = invalue + utxo[in_txid][in_idx]

        del utxo[in_txid][in_idx]
        if len(utxo[in_txid]) == 0:
            del utxo[in_txid]

    outvalue = 0
    for out_idx in range(len(tx['outputs'])):
        out = tx['outputs'][out_idx]

        if txid not in utxo:
            utxo[txid] = dict()

        utxo[txid]["{}".format(out_idx)] = out['value']

        outvalue = outvalue + out['value']

    if outvalue > invalue:
        raise ErrorInvalidTxOutpoint("Outputs for TX {} exceed inputs!".format(txid))

    return invalue - outvalue

def verify_block_tail(block, prev_block, prev_utxo, prev_height, txs):
    if prev_block is None:
        # assert: false (should never happen)
        if get_objid(block) != const.GENESIS_BLOCK_ID:
            raise ErrorInvalidGenesis("Block does not contain link to previous or is fake genesis block!")
        prev_utxo = dict()
        prev_created_ts = 0
        prev_height = -1
    else:
        if prev_block['type'] != 'block':
            raise ErrorInvalidFormat("Previous block is not a block!")
        if prev_utxo is None:
            raise ErrorUnknownObject("No UTXO for previous block found!") # assert: false (should never happen)
        if prev_height is None:
            raise ErrorUnknownObject("No height for previous block found!") # assert: false (should never happen)

        prev_created_ts = prev_block['created']

    # check block timestamp
    if prev_created_ts >= block['created']:
        raise ErrorInvalidBlockTimestamp("Block not created after previous block!")

    if any(tx['type'] != 'transaction' for tx in txs.values()):
        raise ErrorInvalidFormat("Not all transactions are transactions!")

    height = prev_height + 1

    # no transactions, return old UTXO and height
    if len(block['txids']) == 0:
        return prev_utxo, height

    # recheck if we have all transactions
    for txid in block['txids']:
        if txid not in txs:
            raise ErrorUnfindableObject("TX {} missing!".format(txid)) # assert: false (should never happen)

    first_txid = block['txids'][0]
    remaining_txids = block['txids']
    utxo = copy.deepcopy(prev_utxo)

    # do we have a coinbase TX?
    cbtx = None
    cbtxid = None
    if 'height' in txs[first_txid]:
        cbtx = txs[first_txid]
        cbtxid = first_txid
        remaining_txids = block['txids'][1:]

        # add coinbase TX output to UTXO
        utxo[cbtxid] = { '0': cbtx['outputs'][0]['value'] }

        # check coinbase (if included in block) height
        if cbtx['height'] != height:
            raise ErrorInvalidBlockCoinbase("Coinbase TX height invalid!")

    txfees = 0
    for txid in remaining_txids:
        # check for additional coinbase transactions
        if 'height' in txs[txid]:
            raise ErrorInvalidBlockCoinbase("Coinbase TX {} not at index 0!".format(txid))

        tx = txs[txid]

        # check if the coinbase is spent in the same block
        if any(inp['outpoint']['txid'] == cbtxid for inp in tx['inputs']):
            raise ErrorInvalidTxOutpoint("Coinbase TX spent in same block!")

        # check and update UTXO
        fee = update_utxo_and_calculate_fee(tx, utxo)

        txfees = txfees + fee

    # check coinbase output value
    if cbtx is not None:
        if cbtx['outputs'][0]['value'] > const.BLOCK_REWARD + txfees:
            raise ErrorInvalidBlockCoinbase("Coinbase TX output value too big")

    return utxo, height

def store_transaction(obj_dict, cur):
    # assert: obj_dict is a valid transaction
    objid = get_objid(obj_dict)
    obj_str = canonicalize(obj_dict).decode('utf-8')
    cur.execute("INSERT INTO objects VALUES(?, ?)", (objid, obj_str))

# Stores for a block its utxoset and height
def store_block(obj_dict, utxo, height, cur):
    # assert: obj_dict is a valid block
    utxo_str = canonicalize(utxo).decode('utf-8')
    obj_str = canonicalize(obj_dict).decode('utf-8')
    objid = get_objid(obj_dict)

    cur.execute("INSERT INTO objects VALUES(?, ?)", (objid, obj_str))
    cur.execute("INSERT INTO utxo VALUES(?, ?)", (objid, utxo_str))
    cur.execute("INSERT INTO heights VALUES(?, ?)", (objid, height))

def get_object(objid):
    con = sqlite3.connect(const.DB_NAME)
    try:
        cur = con.cursor()

        res = cur.execute("SELECT obj FROM objects WHERE oid = ?", (objid,))
        row = res.fetchone()
        if row is not None:
            return expand_object(row[0])
        else:
            return None
    finally:
        con.close()