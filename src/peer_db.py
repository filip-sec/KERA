from Peer import Peer
from typing import Iterable, Set
from constants import PEER_DB_FILE

def store_peer(peer: Peer, existing_peers: Iterable[Peer] = set()):
    # Append the new peer to the file if it's not in the existing set
    with open(PEER_DB_FILE, 'a') as f:
        if peer not in existing_peers:
            f.write(f"{peer.host},{peer.port}\n")
            
def load_peers() -> Set[Peer]:
    peers = set()
    try:
        with open(PEER_DB_FILE, 'r') as f:
            f.readline()    #ignore the first line
            for line in f:
                host, port = line.strip().split(",")
                peers.add(Peer(host, int(port)))
    except FileNotFoundError:
        # If the file doesn't exist, return an empty set
        pass
    return peers

def remove_peer(peer: Peer):
    print("Removing peer")
    # Read the existing peers
    existing_peers = load_peers()
    
    peer_to_remove = Peer(peer[0], peer[1])
    
    # Remove the peer from the set
    existing_peers.discard(peer_to_remove)
    
    # Write the remaining peers back to the file
    with open(PEER_DB_FILE, 'w') as f:
        f.write("host,port\n")
        for p in existing_peers:
            f.write(f"{p.host},{p.port}\n")
    