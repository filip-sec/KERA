from Peer import Peer
import constants as const
from message.msgexceptions import *
from jcs import canonicalize

import mempool
import objects
import peer_db

import asyncio
import ipaddress
import json
import random
import re
import sqlite3
import sys

PEERS = set()
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
    try:
            if not validate_peer_str(peer):  
                print(f"Invalid peer format: {peer}")
                return
            if peer in PEERS:
                print(f"Peer {peer} is already known.")
            else:
                PEERS.add(peer)
                print(f"New peer {peer} added to the list.")
    except Exception as e:
            print(f"Failed to add peer {peer}: {str(e)}")

# Add connection if not already open
def add_connection(peer, queue):
    if peer not in CONNECTIONS:
        CONNECTIONS[peer] = queue 

# Delete connection
def del_connection(peer):
    if peer in CONNECTIONS:
        del CONNECTIONS[peer]

# Make msg objects
def mk_error_msg(error_str, error_name):
    error_msg = {
        "type": "error",
        "error": error_str,
        "name": error_name
    }
    return json.dumps(error_msg, separators=(',', ':')) + "\n"

def mk_hello_msg():
    hello_msg = {
        "type": "hello",
        "version": "0.10.4",
        "agent": "NewNode"
    }
    return json.dumps(hello_msg, separators=(',', ':')) + "\n"

def mk_getpeers_msg():
    getpeers_msg = {
        "type": "getpeers"
    }
    return json.dumps(getpeers_msg, separators=(',', ':')) + "\n"

def mk_peers_msg():
    # Convert the set of peers to a list and format it appropriately
    peers_list = list(PEERS)  # Assuming PEERS is a set or collection of peers
    peers_msg = {
        "type": "peers",
        "peers": peers_list  # Use the peers_list here
    }
    return json.dumps(peers_msg, separators=(',', ':')) + "\n"

def mk_getobject_msg(objid):
    pass # TODO

def mk_object_msg(obj_dict):
    pass # TODO

def mk_ihaveobject_msg(objid):
    pass # TODO

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
        raise MessageException("Invalid JSON format")

# Send data over the network as a message
async def write_msg(writer, msg_dict):
    msg_str = json.dumps(msg_dict,separators=(',', ':')) + "\n"

    msg_bytes = msg_str.encode('utf-8')

    try:
        writer.write(msg_bytes)
        await writer.drain()
    except Exception as e:
        print(f"Filed to send message: {str(e)}")

# Check if message contains no invalid keys,
# raises a MalformedMsgException
def validate_allowed_keys(msg_dict, allowed_keys, msg_type):
    pass # TODO


# Validate the hello message
# raises an exception
def validate_hello_msg(msg_dict):
    required_keys = ["type", "version", "agent"]
    for key in required_keys:
        if key not in msg_dict:
            raise MessageException("Invalid hello message: missing required key")
        if msg_dict["type"] != "hello":
            raise MessageException("Invalid hello message: wrong type")


# returns true iff host_str is a valid hostname
def validate_hostname(host_str):
    pass # TODO

# returns true iff host_str is a valid ipv4 address
def validate_ipv4addr(host_str):
    pass # TODO

# returns true iff peer_str is a valid peer address
def validate_peer_str(peer_str):
    pass # TODO

# raise an exception if not valid
def validate_peers_msg(msg_dict):
    pass # TODO

# raise an exception if not valid
def validate_getpeers_msg(msg_dict):
    pass # TODO

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
    pass # TODO

# raise an exception if not valid
def validate_getobject_msg(msg_dict):
    pass # TODO

# raise an exception if not valid
def validate_object_msg(msg_dict):
    pass # TODO

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
        pass # TODO


def handle_peers_msg(msg_dict):
    pass # TODO


def handle_error_msg(msg_dict, peer_self):
    pass # TODO


async def handle_ihaveobject_msg(msg_dict, writer):
    pass # TODO


async def handle_getobject_msg(msg_dict, writer):
    pass # TODO

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

# what to do when an object message arrives
async def handle_object_msg(msg_dict, peer_self, writer):
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

        print(f"New connection with {peer}")

        # Send the "hello" message
        await write_msg(writer, mk_hello_msg())
        print(f"Sent 'hello' message to {peer}")

        # Wait to receive the "hello" message from the peer
        msg_str = await asyncio.wait_for(reader.readline(), timeout=20.0)
        msg_dict = parse_msg(msg_str)
        if msg_dict['type'] != 'hello':
            raise MessageException("First message must be 'hello'")
        validate_hello_msg(msg_dict)
        add_connection(peer, queue)
        print(f"Handshake complete with {peer}. Received 'hello'.")

        # Now, after receiving the 'hello' message, send the "getpeers" message
        #await write_msg(writer, mk_getpeers_msg())
        #print(f"Sent 'getpeers' message to {peer}")

    except asyncio.TimeoutError:
        print(f"Timeout waiting for 'hello' message from {peer}. Closing connection.")
        try:
            await write_msg(writer, mk_error_msg("Timeout", "No hello message received in time"))
        except:
            pass
        writer.close()
        return
    except MessageException as e:
        print(f"Error during handshake with {peer}: {str(e)}")
        try:
            await write_msg(writer, mk_error_msg("INVALID_HANDSHAKE", str(e)))
        except:
            pass
        writer.close()
        return
    except Exception as e:
        print(f"Exception: {str(e)}")
        writer.close()
        return

    # Enter the main message loop
    try:
        print(f"Entering message loop with {peer}")
        while True:
            if read_task is None:
                read_task = asyncio.create_task(reader.readline())
            if queue_task is None:
                queue_task = asyncio.create_task(queue.get())

            # Wait for network or queue messages
            done, pending = await asyncio.wait([read_task, queue_task], return_when=asyncio.FIRST_COMPLETED)
            if read_task in done:
                msg_str = read_task.result()
                read_task = None

            if queue_task in done:
                queue_msg = queue_task.result()
                queue_task = None
                await handle_queue_msg(queue_msg, writer)
                queue.task_done()

            # Handle empty message (peer closed connection)
            if msg_str == b'':
                print(f"{peer}: Connection closed by peer.")
                break  # Exit the loop and close the connection

            # Parse and handle the received message
            msg_dict = parse_msg(msg_str)
            
            print(f"Received message from {peer}: {msg_dict}")

            if msg_dict['type'] == 'getpeers':
                print(f"Received 'getpeers' request from {peer}")
                await write_msg(writer, mk_peers_msg())
            elif msg_dict['type'] == 'peers':
                handle_peers_msg(msg_dict)
                print(f"Received peers list from {peer}.")
            elif msg_dict['type'] == 'getchaintip':
                await write_msg(writer, mk_chaintip_msg(get_chaintip_blockid()))
                print(f"Received 'getchaintip' request from {peer}")
            else:
                print(f"Unknown message type received from {peer}: {msg_dict['type']}")
            
    except Exception as e:
        print(f"Exception in message handling: {str(e)}")
    finally:
        print(f"Closing connection with {peer}")
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
    for peer in const.PRELOADED_PEERS:
        await connect_to_node(peer)    

# connect to some peers
async def resupply_connections():
    for peer in const.PRELOADED_PEERS:
        if peer not in CONNECTIONS:  # If no active connection, create one
            print(f"Connecting to peer: {peer}")
            try:
                await asyncio.sleep(5)  # Add delay between connection attempts
                await connect_to_node(peer)
            except Exception as e:
                print(f"Failed to connect to {peer} - {str(e)}")




async def init():
    global BLOCK_WAIT_LOCK
    BLOCK_WAIT_LOCK = asyncio.Condition()
    global TX_WAIT_LOCK
    TX_WAIT_LOCK = asyncio.Condition()

    # Create bootstrap and listen tasks
    bootstrap_task = asyncio.create_task(bootstrap())
    listen_task = asyncio.create_task(listen())

    # Service loop
    while True:
        print("Service loop reporting in.")
        print("Open connections: {}".format(set(CONNECTIONS.keys())))

        # Open more connections if necessary
        #await resupply_connections()  # Ensure that this async function is awaited

        # Delay between service loop iterations
        await asyncio.sleep(const.SERVICE_LOOP_DELAY)

    # Await the completion of bootstrap and listen tasks
    await bootstrap_task
    await listen_task


def main():
    asyncio.run(init())


if __name__ == "__main__":
    if len(sys.argv) == 3:
        LISTEN_CFG['address'] = sys.argv[1]
        LISTEN_CFG['port'] = sys.argv[2]

    main()
