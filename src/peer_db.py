from Peer import Peer
from typing import Iterable, Set

PEER_DB_FILE = "peers.csv"

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