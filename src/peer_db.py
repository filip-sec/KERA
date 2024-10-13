from Peer import Peer
from typing import Iterable, Set

PEER_DB_FILE = "peers.csv"

def store_peer(peer: Peer, existing_peers: Iterable[Peer] = set()):
    # Append the new peer to the file if it's not in the existing set
    with open(PEER_DB_FILE, 'a') as f:
        if peer not in existing_peers:
            f.write(f"{peer.host}:{peer.port}\n")
            
def load_peers() -> Set[Peer]:
    # read from file
    pass