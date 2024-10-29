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
PENDING_PEERS = set()
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
        
        # Do not add banned peer addresses
        if new_peer.host in const.BANNED_PEERS:
            print(f"Peer {new_peer} is banned.")
            return
            
        # Do not add loopback or multicast addresses
        try:
            # Try to interpret the host as an IP address
            ip = ipaddress.ip_address(new_peer.host)
            # Check if the IP address is loopback or multicast
            if ip.is_loopback or ip.is_multicast:
                print(f"Peer {new_peer} is a loopback or multicast address.")
                return
        except ValueError:
            # If it's not an IP address, just continue
            pass
            
        if new_peer in PEERS:
            print(f"Peer {new_peer} is already known.")
            return
        else:
            peer_db.store_peer(new_peer, PEERS)
            PEERS.add(new_peer)
            print(f"New peer {new_peer} added to the list.")
    except Exception as e:
            print(f"Failed to add peer {peer_host}:{peer_port}: {str(e)}")

# Add connection if not already open
def add_connection(peer, queue):
    PENDING_PEERS.discard(peer)
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
        "version": const.VERSION,
        "agent": const.AGENT
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
        raise MalformedMsgException("Invalid JSON format")

# Send data over the network as a message
async def write_msg(writer, msg_dict):
    msg_str = json.dumps(msg_dict,separators=(',', ':')) + "\n"

    msg_bytes = msg_str.encode('utf-8')

    try:
        writer.write(msg_bytes)
        await writer.drain()
    except Exception as e:
        print(f"Failed to send message: {str(e)}")

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
    
    # Check for missing type key
    if 'type' not in msg_dict.keys():
        raise MalformedMsgException(f"Missing required key 'type' in message.")
    
    #Check if type is a string
    if not isinstance(msg_dict['type'], str):
        raise MalformedMsgException(f"Invalid 'type' key in message (not a string).")
        
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
        raise MalformedMsgException(f"Unknown message type: {msg_type}")
        


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
                            PENDING_PEERS.discard(peer)
                            return  # Close connection on error
                        
                        except MessageException as e:
                            error_name = "INVALID_HANDSHAKE"
                            error_message = mk_error_msg(error_name, str(e))
                            await write_msg(writer, error_message)
                            print(f"Error: {str(e)}")
                            PENDING_PEERS.discard(peer)
                            return # Close connection on error

            except asyncio.TimeoutError:
                if not received_hello:
                    print(f"Timeout waiting for 'hello' message from {peer}.")
                    await write_msg(writer, mk_error_msg("INVALID_HANDSHAKE", "Timeout waiting for 'hello' message"))
                    PENDING_PEERS.discard(peer)
                    return # Close connection on error
                
            except Exception as e:
                print(f"Connection error with {peer}: {str(e)}")
                PENDING_PEERS.discard(peer)
                return  # Close connection on error

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
    
    ALL_PEERS = PEERS.union(const.PRELOADED_PEERS)
    
    for peer in ALL_PEERS:
        try:
            PENDING_PEERS.add(peer)
            await connect_to_node(peer)
        except Exception as e:
            print(f"Failed to connect to {peer}: {str(e)}")  

# Ensure the node has at least the threshold number of active connections.
def resupply_connections():
    """
    Ensure the node has at least the threshold number of active connections.
    If connections fall below the threshold, attempt to connect to known peers.
    This version is non-async.
    """
    low_connection_threshold = const.LOW_CONNECTION_THRESHOLD  # Threshold from constants
    current_connections = len(CONNECTIONS)

    # Only resupply if below the threshold
    if current_connections >= low_connection_threshold:
        #print(f"Current connections ({current_connections}) meet or exceed the threshold ({low_connection_threshold}). No action needed.")
        return

    # Calculate how many more connections are needed
    needed_connections = low_connection_threshold - current_connections + 10 # Add a buffer of 10 connections
    print(f"Currently have {current_connections} connections, trying to add {needed_connections} more connections.")

    # Randomize the list of known peers and attempt to connect to fill the gap
    known_peers = list(PEERS.union(const.PRELOADED_PEERS))  # Combine known and preloaded peers
    random.shuffle(known_peers)
    
    attempted_connections = 0

    # Start connection attempts to meet the threshold
    for peer in known_peers:
        if peer not in CONNECTIONS and (peer not in PENDING_PEERS):
            print(f"Attempting to connect to peer: {peer}")
            try:
                # Start connection attempt as a background task
                asyncio.create_task(connect_to_node(peer))  # No await, scheduling connection
                attempted_connections += 1
                if attempted_connections >= needed_connections:
                    print(f"Connection threshold reached with {current_connections} connections.")
                    break  # Stop once the threshold is met
            except Exception as e:
                print(f"Failed to connect to {peer}: {str(e)}")

    if current_connections < low_connection_threshold:
        print(f"Warning: Unable to reach connection threshold. Currently at {current_connections} connections.")


async def init():
    global BLOCK_WAIT_LOCK
    BLOCK_WAIT_LOCK = asyncio.Condition()
    global TX_WAIT_LOCK
    TX_WAIT_LOCK = asyncio.Condition()

    # Create bootstrap and listen tasks
    bootstrap_task = asyncio.create_task(bootstrap())
    listen_task = asyncio.create_task(listen())
    
    # sleep to allow the listen task to start
    await asyncio.sleep(2)
    
    
    # Service loop
    while True:
        print("Service loop reporting in.")
        print("Open connections: {}".format(set(CONNECTIONS.keys())))
        
        # Open more connections if necessary
        resupply_connections()

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
