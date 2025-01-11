from Peer import Peer
from peers import Peers
from validator import Validator
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

import traceback

VALIDATOR = Validator()
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
CHAINTIP = const.GENESIS_BLOCK_ID
CHAINTIP_HEIGHT = 0

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

async def broadcast_msg(msg):
    for k, q in CONNECTIONS.items():
        await q.put(msg)

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
    return {"type": "chaintip", "blockid": CHAINTIP}

def mk_mempool_msg(txids):
    pass # TODO

def mk_getchaintip_msg():
    return {"type": "getchaintip"}

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
            raise ErrorInvalidFormat("Message malformed: version is missing!")

        version = msg_dict['version']
        if not isinstance(version, str):
            raise ErrorInvalidFormat("Message malformed: version is not a string!")

        if not re.compile('0\.10\.\d').fullmatch(version):
            raise ErrorInvalidFormat("Version invalid")

        validate_allowed_keys(msg_dict, ['type', 'version', 'agent'], 'hello')

        if 'agent' not in msg_dict:
            raise ErrorInvalidFormat("Agent field not set")

        if not objects.validate_human_readable(msg_dict['agent']):
            raise ErrorInvalidFormat("Agent field not of the required format")

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
    if len(msg_dict) != 1:
        raise ErrorInvalidFormat("Invalid getchaintip message")

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

        validate_allowed_keys(msg_dict, ['type','object'], 'object')

        obj = msg_dict['object']
        objects.validate_object(obj)

    except FaultyNodeException as e:
        raise e
    except NonfaultyNodeException as e:
        raise e
    except Exception as e:
        raise ErrorInvalidFormat("Message malformed: {}".format(str(e)))

# raise an exception if not valid
def validate_chaintip_msg(msg_dict):
    if len(msg_dict) != 2:
        raise ErrorInvalidFormat("More than two keys set")
    if not "blockid" in msg_dict:
        raise ErrorInvalidFormat("blockid not set")
    if not isinstance(msg_dict["blockid"], str):
        raise ErrorInvalidFormat("blockid not a string")
    if not objects.validate_objectid(msg_dict["blockid"]):
        raise ErrorInvalidFormat(f"Invalid format of blockid")

    if int(msg_dict["blockid"], 16) >= int(const.BLOCK_TARGET, 16):
        raise ErrorInvalidBlockPOW(f"Proposed chaintip does not satisfy proof-of-work equation (has an objectid of {msg_dict['blockid']})!")

    
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
            await write_msg(writer, mk_error_msg(f"Object {objid} not known", "UNKNOWN_OBJECT"))
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

# what to do when an object message arrives
async def handle_object_msg(msg_dict, queue):
    global CHAINTIP
    global CHAINTIP_HEIGHT
    obj_dict = msg_dict['object']
    objid = objects.get_objid(obj_dict)
    print(f"Received object with id {objid}: {obj_dict}")

    err_str = None
    con = sqlite3.connect(const.DB_NAME)
    try:
        cur = con.cursor()
        res = cur.execute("SELECT obj FROM objects WHERE oid = ?", (objid,))

        # already have object
        if not res.fetchone() is None:
            # object has already been verified as it is in the DB
            return

        print("Received new object '{}'".format(objid))
        # notify validator that we received this object here
        VALIDATOR.received_object(objid)
        if VALIDATOR.is_pending(objid):
            VALIDATOR.add_peer(objid, queue)
            return # no need to rerun verification that is pending yet

        if obj_dict['type'] == 'transaction':
            prev_txs = gather_previous_txs(cur, obj_dict)
            objects.verify_transaction(obj_dict, prev_txs)
            objects.store_transaction(obj_dict, cur)
        elif obj_dict['type'] == 'block':
            new_utxo, height = objects.verify_block(obj_dict)
            objects.store_block(obj_dict, new_utxo, height, cur)

            if height > CHAINTIP_HEIGHT:
                CHAINTIP_HEIGHT = height
                CHAINTIP = objid
        else:
            raise ErrorInvalidFormat("Got an object of unknown type") # assert: false
        # if everything worked, commit this
        con.commit()

        print("Added new object '{}'".format(objid))
        VALIDATOR.new_valid_object(objid)

        # gossip the new object to all connections
        await broadcast_msg(mk_ihaveobject_msg(objid))

    except NeedMoreObjects as e:
        print(f"Need more elements: {e.message}")
        print("Adding this to the validator as a pending task")
        VALIDATOR.verification_pending(obj_dict, queue, e.missingobjids)
        for q in CONNECTIONS.values():
            for missingobjid in e.missingobjids:
                print(f"Requesting {missingobjid} from peer")
                await q.put(mk_getobject_msg(missingobjid))
        print("Returning")
        return # and consume exception
    except NodeException as e: # whatever the reason, just reject this
        con.rollback()
        print("Failed to verify object '{}': {}".format(objid, str(e)))
        raise e # and re-raise this
    except Exception as e:
        print(f"An exception occured: {str(e)}")
        con.rollback()
        raise e
    finally:
        con.close()


# returns the chaintip blockid + height
def get_chaintip_blockid():
    con = sqlite3.connect(const.DB_NAME)
    try:
        cur = con.cursor()

        res = cur.execute("SELECT blockid, height FROM heights ORDER BY height DESC LIMIT 1")
        row = res.fetchone()
        if row is None:
            raise Exception("Assertion error: Not even the genesis block in database")

        return (row[0], row[1])
    except Exception as e:
        # assert: false
        con.rollback()
        raise e
    finally:
        con.close()


async def handle_getchaintip_msg(msg_dict, writer):
    await write_msg(writer, mk_chaintip_msg(CHAINTIP))


async def handle_getmempool_msg(msg_dict, writer):
    pass # TODO


async def handle_chaintip_msg(msg_dict):
    objectid = msg_dict['blockid']

    obj = objects.get_object(objectid)
    if obj == None:
        await broadcast_msg(mk_getobject_msg(objectid))
    else:
        if obj['type'] != 'block':
            raise ErrorInvalidFormat(f"Proposed chaintip {objectid} is not a block")

async def handle_mempool_msg(msg_dict):
    pass # TODO

# Helper function
async def handle_queue_msg(msg_dict, writer):
    #check if this is a special message
    #currently there are only type:'resumeValidation'
    if msg_dict['type'] == 'resumeValidation':
        await handle_object_msg(msg_dict, None)
    else:
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
        await write_msg(writer, mk_getchaintip_msg())
        
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
                    await handle_object_msg(msg, queue)
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
                print("{}: A (nonfaulty) error occured: {}: {}".format(peer, e.error_name, e.message))
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
        print(traceback.format_exc())
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
    CHAINTIP, CHAINTIP_HEIGHT = get_chaintip_blockid()
    asyncio.run(init())


if __name__ == "__main__":
    if len(sys.argv) == 3:
        LISTEN_CFG['address'] = sys.argv[1]
        LISTEN_CFG['port'] = sys.argv[2]

    main()
