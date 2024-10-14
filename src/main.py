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
        "version": "0.10.0",
        "agent": "Kerma-Core Client 0.10"
    }
    

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

def validate_keys(msg_dict, required_keys, optional_keys, msg_type):
    """
    Validates that a message dictionary contains only allowed keys and includes all required keys.

    Args:
        msg_dict (dict): The message dictionary to validate.
        required_keys (set): A set of keys that are required in the message.
        optional_keys (set): A set of keys that are optional in the message.
        msg_type (str): The type of the message being validated.

    Raises:
        MalformedMsgException: If the message contains an invalid key or is missing a required key.
    """
    allowed_keys = required_keys | optional_keys

    # Check for invalid keys
    for key in msg_dict.keys():
        if key not in allowed_keys:
            raise MalformedMsgException(f"Invalid key '{key}' in '{msg_type}' message.")
    
    # Check for missing required keys
    for key in required_keys:
        if key not in msg_dict.keys():
            raise MalformedMsgException(f"Missing required key '{key}' in '{msg_type}' message.")

# Parse and validate the 'hello' message
def validate_hello_msg(msg_dict):
    """
    Validates the 'hello' message.

    Args:
        msg_dict (dict): The 'hello' message dictionary to validate.

    Raises:
        MalformedMsgException: If the message is malformed.
    """
    required_keys = {"type", "version", "agent"}
    optional_keys = set()  # No optional keys for 'hello' message
    validate_keys(msg_dict, required_keys, optional_keys, "hello")
    
    version = msg_dict.get("version")
    if not version or not version.startswith(const.HELLO_VERSION) or len(version) != 6:
        raise MalformedMsgException("Invalid 'version' in 'hello' message.")

    agent = msg_dict.get("agent")
    if not agent or len(agent) > const.HELLO_AGENT_MAX_LEN or not agent.isascii() or not agent.isprintable():
        raise MalformedMsgException("Invalid 'agent' in 'hello' message.")

    



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

# Handle incoming connections
async def handle_connection(reader, writer):
    buffer = ""  # Buffer to accumulate incomplete messages
    peer = None
    queue = asyncio.Queue()
    received_hello = False  # Track if the hello message has been received

    try:
        peer = writer.get_extra_info('peername')
        if not peer:
            raise Exception("Failed to get peername!")

        print(f"New connection with {peer}")

        # Send your hello message
        await write_msg(writer, mk_hello_msg())
        print(f"Sent 'hello' message to {peer}")
        
        #send getpeers message
        await write_msg(writer, mk_getpeers_msg())
        print(f"Sent 'getpeers' message to {peer}")

        # Set a timeout for receiving the first "hello" message (20 seconds)
        while True:
            try:
                data = await asyncio.wait_for(reader.read(const.RECV_BUFFER_LIMIT), timeout=20.0)
                if not data:  # Peer closed connection
                    print(f"{peer}: Connection closed by peer.")
                    break

                buffer += data.decode('utf-8')
                
                #print(f'Buffer: {buffer}')

                # Process all complete messages (separated by '\n')
                while '\n' in buffer:
                    msg_str, buffer = buffer.split('\n', 1)
                    msg_str = msg_str.strip()

                    if msg_str:  # Ignore empty messages
                        print(f"Received raw message: {msg_str}")
                        try:
                            msg_dict = parse_msg(msg_str)
                            validate_msg(msg_dict)  # Validate using validate_msg function

                            if not received_hello:
                                if msg_dict.get('type') != 'hello':
                                    print(f"First message from {peer} is not 'hello'. Closing connection.")
                                    await write_msg(writer, mk_error_msg("INVALID_HANDSHAKE", "First message is not 'hello'"))
                                    writer.close()
                                    del_connection(peer)
                                    return
                                
                                validate_hello_msg(msg_dict)
                                received_hello = True
                                add_connection(peer, queue)
                                print(f"Handshake complete with {peer}. Received 'hello'.")
                            else:
                                await handle_message(msg_dict, writer, peer)

                        except (MalformedMsgException) as e:
                            error_name = "INVALID_FORMAT"
                            error_message = mk_error_msg(error_name, str(e))
                            await write_msg(writer, error_message)
                            print(f"Error: {str(e)}")
                            return  # Close connection on error
                        
                        except MessageException as e:
                            error_name = "INVALID_HANDSHAKE"
                            error_message = mk_error_msg(error_name, str(e))
                            await write_msg(writer, error_message)
                            print(f"Error: {str(e)}")
                            return # Close connection on error

            except asyncio.TimeoutError:
                if not received_hello:
                    print(f"Timeout waiting for 'hello' message from {peer}.")
                    await write_msg(writer, mk_error_msg("INVALID_HANDSHAKE", "Timeout waiting for 'hello' message"))
                    return # Close connection on error

    finally:
        print(f"Closing connection with {peer}")
        writer.close()
        del_connection(peer)


async def handle_message(msg_dict, writer, peer):
    """Helper function to handle post-handshake messages."""
    msg_type = msg_dict['type']
    if msg_type == 'hello':
        raise MessageException("Received 'hello' message after handshake.")
    if msg_type == 'getpeers':
        print(f"Received 'getpeers' request from {peer}")
        await write_msg(writer, mk_peers_msg())
    elif msg_type == 'peers':
        handle_peers_msg(msg_dict)
        print(f"Received peers list from {peer}.")
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
        await resupply_connections()  # Ensure that this async function is awaited

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
