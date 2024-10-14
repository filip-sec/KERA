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
def add_peer(peer_host, peer_port):
    try:
            if not Peer.validate_peer(peer_host, peer_port):
                print(f"Invalid peer format: {peer_host}:{peer_port}")
                return
            new_peer = Peer(peer_host, peer_port)
            if new_peer in PEERS:
                print(f"Peer {new_peer} is already known.")
            else:
                peer_db.store_peer(new_peer, PEERS)
                PEERS.add(new_peer)
                print(f"New peer {new_peer} added to the list.")
    except Exception as e:
            print(f"Failed to add peer {peer_host}:{peer_port}: {str(e)}")

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
    return {
        "type": "getpeers"
    }

def mk_peers_msg():
    """
    Create a 'peers' message with up to 30 known peers in the format 'host:port'.
    Includes the current node as the first peer if listening.
    """
    # Initialize the list of peers to include in the message
    peers_list = []

    # Add the current node (self) as the first peer if it's listening for connections
    if LISTEN_CFG['address'] and LISTEN_CFG['port']:
        self_peer = f"{LISTEN_CFG['address']}:{LISTEN_CFG['port']}"
        peers_list.append(self_peer)
    
    # Add up to 29 other known peers (to keep total size <= 30)
    known_peers = list(PEERS)  # Get a list from the set of known peers
    random.shuffle(known_peers)  # Randomize the peer order
    
    # Limit to 29 additional peers
    for peer in known_peers[:29]:
        peers_list.append(str(peer))  # Convert the Peer object to string (host:port)

    # Create and return the peers message
    peers_msg = {
        "type": "peers",
        "peers": peers_list
    }

    return peers_msg


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

# Validate the 'peers' message
def validate_peers_msg(msg_dict):
    required_keys = {"type", "peers"}
    optional_keys = set()
    validate_keys(msg_dict, required_keys, optional_keys, "peers")
    
    if msg_dict.get("type") != "peers":
        raise MalformedMsgException("Invalid 'peers' message type.")

    peers_list = msg_dict.get("peers")
    if not isinstance(peers_list, list) or len(peers_list) > 30:
        raise MalformedMsgException("Invalid 'peers' list.")
    
    
    for peer in peers_list:
        peer_host, peer_port = peer.split(':')
        peer_port = int(peer_port)
        
        if not Peer.validate_peer(peer_host, peer_port):
            raise MalformedMsgException(f"Invalid peer format: {peer}")
    


# Validate the 'getpeers' message
def validate_getpeers_msg(msg_dict):
    required_keys = {"type"}
    optional_keys = set()
    validate_keys(msg_dict, required_keys, optional_keys, "getpeers")
    if msg_dict.get("type") != "getpeers":
        raise MalformedMsgException("Invalid 'getpeers' message type.")


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
    peers_list = msg_dict.get("peers")
    
    for peer_str in peers_list:
        try:
            # Extract the host and port
            host, port = peer_str.split(':')
            port = int(port)
            
            # Add valid peers to known peers
            add_peer(host, port)
        except Exception as e:
            print(f"Failed to add peer {peer_str}: {str(e)}")



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
        peer_host, peer_port = peer
        add_peer(peer_host, peer_port)

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
                                
                                received_hello = True
                                add_connection(peer, queue)
                                print(f"Handshake complete with {peer}.")
                            else:
                                await handle_message(msg_dict, writer, peer)

                        except MalformedMsgException as e:
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
    elif msg_type == 'getpeers':
        print(f"Received 'getpeers' request from {peer}")
        # Create and send the peers message
        peers_msg = mk_peers_msg()
        await write_msg(writer, peers_msg)
        print(f"Sent 'peers' message to {peer}")
    elif msg_type == 'peers':
        print(f"Received 'peers' message from {peer}")
        handle_peers_msg(msg_dict)
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
    
    # Load peers from the database
    global PEERS
    PEERS = peer_db.load_peers()
    
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
