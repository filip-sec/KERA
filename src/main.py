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

BLOCK_WAIT_CONDITIONS = {}
BLOCK_DEPENDENCIES = {}

# Tracks reverse dependencies: block -> set of blocks that depend on it
REVERSE_DEPENDENCIES = {}



BLOCK_TO_VALIDATE = dict()
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
    
# Add block dependencies and wait conditions
async def add_block_dependencies(block_id, dependencies):
    if block_id not in BLOCK_DEPENDENCIES:
        BLOCK_DEPENDENCIES[block_id] = set(dependencies)
        BLOCK_WAIT_CONDITIONS[block_id] = asyncio.Condition()
    else:
        BLOCK_DEPENDENCIES[block_id].update(dependencies)
        
    # Update reverse dependencies
    for dep in dependencies:
        if dep not in REVERSE_DEPENDENCIES:
            REVERSE_DEPENDENCIES[dep] = set()
        REVERSE_DEPENDENCIES[dep].add(block_id)


# Notify that a dependency has been resolved
async def notify_dependency_resolved(dependency_id):
    for block_id, dependencies in BLOCK_DEPENDENCIES.items():
        if dependency_id in dependencies:
            dependencies.remove(dependency_id)
            print(f"Removed dependency {dependency_id} from block {block_id}.")
            
            if not dependencies:  # All dependencies resolved
                print(f"All dependencies resolved for block {block_id}.")
                async with BLOCK_WAIT_CONDITIONS[block_id]:
                    BLOCK_WAIT_CONDITIONS[block_id].notify_all()

# Wait for dependencies to be resolved
async def wait_for_dependencies(block_id):
    if block_id not in BLOCK_WAIT_CONDITIONS:
        raise ValueError(f"No condition found for block {block_id}")

    async with BLOCK_WAIT_CONDITIONS[block_id]:
        await BLOCK_WAIT_CONDITIONS[block_id].wait()

# Cleanup block dependencies
def cleanup_block(block_id):
    if block_id in BLOCK_DEPENDENCIES:
        del BLOCK_DEPENDENCIES[block_id]
    if block_id in BLOCK_WAIT_CONDITIONS:
        del BLOCK_WAIT_CONDITIONS[block_id]
        
        
async def propagate_invalid_ancestry(block_id, writer, peer):
    if block_id in REVERSE_DEPENDENCIES:
        dependents = REVERSE_DEPENDENCIES[block_id]
        print(f"Block {block_id} is invalid. Propagating INVALID_ANCESTRY to dependents: {dependents}")
        
        for dependent_block in dependents:
            # Send an error message to notify peers about invalid ancestry
            error_msg = mk_error_msg(f"Block {dependent_block} depends on invalid block {block_id}", "INVALID_ANCESTRY")
            await write_msg(writer, error_msg)
            
            # Recursively propagate invalid ancestry
            await propagate_invalid_ancestry(dependent_block, writer, peer)
            
            # Cleanup tasks and dependencies
            if dependent_block in BLOCK_VERIFY_TASKS:
                del BLOCK_VERIFY_TASKS[dependent_block]
            if dependent_block in BLOCK_DEPENDENCIES:
                del BLOCK_DEPENDENCIES[dependent_block]
            if dependent_block in REVERSE_DEPENDENCIES:
                del REVERSE_DEPENDENCIES[dependent_block]
            if dependent_block in BLOCK_WAIT_CONDITIONS:
                del BLOCK_WAIT_CONDITIONS[dependent_block]
            if dependent_block in BLOCK_TO_VALIDATE:
                del BLOCK_TO_VALIDATE[dependent_block]

        # Remove invalidated block from REVERSE_DEPENDENCIES
        del REVERSE_DEPENDENCIES[block_id]



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

        # Deserialize UTXO set from JSON
        utxo_list = json.loads(utxo_row[0])  # Deserialize JSON string into list of lists
        utxo = set(tuple(item) for item in utxo_list)  # Convert each list to a tuple
        height = utxo_row[1]

        return block, utxo, height
    finally:
        con.close()


# get all transactions as a dict txid -> tx from a list of ids
def get_block_txs(txids):
    pass # TODO

async def store_block_utxo_height(block, utxo, height):
    con = sqlite3.connect(const.DB_NAME)
    
    #print(f"Storing block UTXO and height for {objects.get_objid(block)}")
    #print(f"Block: {block}")
    #print(f"UTXO: {utxo}")
    #print(f"Height: {height}")
    
    try:
        cur = con.cursor()

        # Serialize the UTXO set to JSON
        utxo_list = list(utxo)  # Convert set to a list
        utxo_json = json.dumps(utxo_list)  # Serialize to JSON

        # Store block UTXO and height
        cur.execute(
            "INSERT INTO block_utxo (blockid, utxo, height) VALUES (?, ?, ?)",
            (objects.get_objid(block), utxo_json, height),
        )
        con.commit()
    finally:
        #remove the block from the block to validate
        if objects.get_objid(block) in BLOCK_TO_VALIDATE:
            del BLOCK_TO_VALIDATE[objects.get_objid(block)]
            
        #resolve dependencies
        await notify_dependency_resolved(objects.get_objid(block))
        
        #cleanup block dependencies
        cleanup_block(objects.get_objid(block))
        
        # Remove reverse dependencies as block is now valid
        if objects.get_objid(block) in REVERSE_DEPENDENCIES:
            del REVERSE_DEPENDENCIES[objects.get_objid(block)]
        
        con.close()

# what to do when an object message arrives
async def handle_object_msg(msg_dict, peer_self, writer):
    obj_dict = msg_dict['object']
    objid = objects.get_objid(obj_dict)
    #print(f"Received object with id {objid}: {obj_dict}")

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
            
            if obj_dict['previd'] is None:
                if objects.get_objid(obj_dict) != const.GENESIS_BLOCK_ID:
                    raise ErrorInvalidGenesis("Block does not contain link to previous or is fake genesis block!")
                
            #ADD BLOCK TO VALIDATE
            BLOCK_TO_VALIDATE[objid] = obj_dict
            
            missing_txs = []
            missing_prev_block = False
            txs = []
            
            prev_block_id = obj_dict['previd']
                
            #check if previous block its in the db
            res = cur.execute("SELECT obj FROM objects WHERE oid = ?", (prev_block_id,))
            first_res = res.fetchone()
            if first_res is None:
                missing_prev_block = True
            
            #check if we have all its transactions
            for txid in obj_dict['txids']:
                tx = objects.get_obj_from_db(txid)
                if tx:
                    txs.append(tx)
                else:
                    missing_txs.append(txid)
                    
            if missing_txs or missing_prev_block:
                
                if missing_prev_block:
                    print(f"Block {objid} is missing its previous block {prev_block_id}")
                if missing_txs:
                    print(f"Block {objid} is missing transactions: {missing_txs}")
                
                BLOCK_VERIFY_TASKS[objid] = {
                    "block": obj_dict,
                    "missing_txs": set(missing_txs),
                    "prev_block_id": prev_block_id,
                    "missing_prev_block": missing_prev_block,
                    "writer": writer,
                    "peer": peer_self_obj,
                }
                
                # Request missing dependencies
                if missing_prev_block:
                    await write_msg(writer, mk_getobject_msg(prev_block_id))
                    
                for missing_txid in missing_txs:
                    await write_msg(writer, mk_getobject_msg(missing_txid))
                    
                # Schedule retry after 5 seconds    
                asyncio.create_task(check_block_dependencies_arrival(objid))
                
                return  # Defer validation until retry
            
            # Fetch previous block, UTXO set, and height
            prev_block, prev_utxo, prev_height = get_block_utxo_height(obj_dict['previd'])
                
            # Verify the block
            updated_utxo, updated_height = objects.verify_block(
                    obj_dict, prev_block, prev_utxo, prev_height, txs)

            # Store updated UTXO and height
            await store_block_utxo_height(obj_dict, updated_utxo, updated_height)
            
        else:
            raise ErrorInvalidFormat(f"Unknown object type: {obj_dict['type']}")
        
        print("Adding new object '{}'".format(objid))

        obj_str = objects.canonicalize(obj_dict).decode('utf-8')
        cur.execute("INSERT INTO objects VALUES(?, ?)", (objid, obj_str))
        con.commit()
        
        print(f"Stored object {objid} in database.")

    except NodeException as e:
        con.rollback()
        print(f"Failed to process object {objid}: {e}")
            
        # Notify dependents that this block is invalid
        await propagate_invalid_ancestry(objid, writer, peer_self_obj)
        
        # Cleanup the current block
        if objid in BLOCK_TO_VALIDATE:
            del BLOCK_TO_VALIDATE[objid]
        if objid in BLOCK_VERIFY_TASKS:
            del BLOCK_VERIFY_TASKS[objid]
        if objid in BLOCK_DEPENDENCIES:
            del BLOCK_DEPENDENCIES[objid]
            
        raise e
    except Exception as e:
        con.rollback()
        
        # if block is not valid we need to remove it from the block to validate
        if objid in BLOCK_TO_VALIDATE:
            del BLOCK_TO_VALIDATE[objid]
            
        raise e
    finally:
        con.close()

    # Propagate the new object to peers
    for k, q in CONNECTIONS.items():
        await q.put(mk_ihaveobject_msg(objid))


async def retry_block_validation(block_id):
    print(f"Retrying validation for block {block_id}")
    
    #if block has dependencies, wait for them to be resolved
    if block_id in BLOCK_DEPENDENCIES:
        print(f"Block {block_id} has dependencies: {BLOCK_DEPENDENCIES[block_id]}")
        await wait_for_dependencies(block_id)
    
    print(f"Dependencies resolved for block {block_id}")
    
    #get the block to validate
    block = BLOCK_VERIFY_TASKS[block_id]["block"]
    writer = BLOCK_VERIFY_TASKS[block_id]["writer"]
    peer = BLOCK_VERIFY_TASKS[block_id]["peer"]
    
    # # All dependencies are now validated and we can now validate the block
    try:
        # Fetch previous block, UTXO set, and height
        prev_block, prev_utxo, prev_height = get_block_utxo_height(block['previd'])
        
        txs = []
        for txid in block['txids']:
            tx = objects.get_obj_from_db(txid)
            if tx:
                txs.append(tx)
            else:
                print(f"Transaction {txid} not found in database.") #this should not happen
                
        updated_utxo, updated_height = objects.verify_block(
            block, prev_block, prev_utxo, prev_height, txs
        )
        
        await store_block_utxo_height(block, updated_utxo, updated_height)
        
        print(f"Block {block_id} successfully validated after retry.")
        
        print("Adding new object '{}'".format(block_id))
    
        con = sqlite3.connect(const.DB_NAME)
        cur = con.cursor()
            
        obj_str = objects.canonicalize(block).decode('utf-8')
        cur.execute("INSERT INTO objects VALUES(?, ?)", (block_id, obj_str))
        con.commit()
        
        print(f"Stored object {block_id} in database.")

        # Propagate the new object to peers
        for k, q in CONNECTIONS.items():
            await q.put(mk_ihaveobject_msg(block_id))

    except FaultyNodeException as e:
        
        # Notify dependents that this block is invalid
        await propagate_invalid_ancestry(block_id, writer, peer)
        
        # Cleanup the current block
        if block_id in BLOCK_TO_VALIDATE:
            del BLOCK_TO_VALIDATE[block_id]
        if block_id in BLOCK_VERIFY_TASKS:
            del BLOCK_VERIFY_TASKS[block_id]
        if block_id in BLOCK_DEPENDENCIES:
            del BLOCK_DEPENDENCIES[block_id]
            
        PEERS.removePeer(peer)
        PEERS.save()
        print("{}: Detected Faulty Node: {}: {}".format(peer, e.error_name, e.message))
        try:
            await write_msg(writer, mk_error_msg(e.message, e.error_name))
        except:
            pass
        
        print("Closing connection with {}".format(peer))
        writer.close()
        del_connection((peer.host, peer.port))
    except Exception as e:
        print("{}: An error occured: {}".format(peer, str(e)))
    finally:
        # Remove the block from the pending tasks
        del BLOCK_VERIFY_TASKS[block_id]
    

async def check_block_dependencies_arrival(block_id):
    print(f"Sleeeping for 5 seconds for block {block_id}")

    await asyncio.sleep(5)  # Wait 5 seconds before retrying

    print(f"Checking if block {block_id} dependencies arrived in time.")

    if block_id not in BLOCK_VERIFY_TASKS:
        return  # Block already processed or removed

    task = BLOCK_VERIFY_TASKS[block_id]
    block = task["block"]
    missing_txs = task["missing_txs"]
    prev_block_id = task["prev_block_id"]
    missing_prev_block = task["missing_prev_block"]
    writer = task["writer"]
    peer = task["peer"]

    try:
        unvalidated_dependencies = set()
        
        # Check if the previous block has arrived
        if missing_prev_block:
            prev_block = objects.get_obj_from_db(prev_block_id)
            if not prev_block:
                # If the previous block is not in the `BLOCK_TO_VALIDATE`, raise an error
                if not prev_block_id in BLOCK_TO_VALIDATE:
                    print(f"Retry failed for block {block_id}. Missing previous block: {prev_block_id}")
                    raise ErrorUnfindableObject(f"Block {block_id} still missing previous block: {prev_block_id}")
                else:
                    print(f"Previous block {prev_block_id} is still being validated but has arrived.")
                    unvalidated_dependencies.add(prev_block_id)
            else:
                print(f"Previous block {prev_block_id} has arrived and is valid.")
                
                
        # Check if missing transactions are now available
        still_missing = set()
        for txid in missing_txs:
            tx = objects.get_obj_from_db(txid)
            if not tx:
                still_missing.add(txid)

        if still_missing:
            print(f"Retry failed for block {block_id}. Missing transactions: {still_missing}")
            raise ErrorUnfindableObject(f"Block {block_id} still missing transactions: {still_missing}")

        if unvalidated_dependencies:
            print(f"Block {block_id} still has unvalidated dependencies: {unvalidated_dependencies}")
            await add_block_dependencies(block_id, unvalidated_dependencies)
        
        asyncio.create_task(retry_block_validation(block_id))

    except NonfaultyNodeException as e:
        print(f"{peer}: An error occurred: {e.error_name}: {e.message}")
        #if connection is still open, send error message
        try:
            await write_msg(writer, mk_error_msg(e.message, e.error_name))
        except:
            pass
    except Exception as e:
        print(f"Error in dependency resolution for block {block_id}: {e}")


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
                
                #print("{}: Received this message: {}".format(peer, msg))

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
