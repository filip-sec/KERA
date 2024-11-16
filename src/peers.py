import os
import json
from Peer import Peer

"""
This stores all peers
"""
class Peers:
    PEER_DB_FILE = "peers.json"

    def __init__(self):
        self.peers = set()
        self.isDirty = False # indicates whether state modified since last write

        # load state from file
        if os.path.isfile(self.PEER_DB_FILE):
            try:
                with open(self.PEER_DB_FILE, 'r') as file:
                    contents = file.read()
                    dec = json.loads(contents)

                    if not isinstance(dec, list):
                        raise Exception()

                    for p in dec:
                        host, port = p.split(':')
                        self.peers.add(Peer(host, int(port)))
            except Exception as e:
                pass

    def addAll(self, peers):
        for peer in peers:
            self.addPeer(peer)

    def addPeer(self, peer: Peer):
        if not peer in self.peers:
            self.peers.add(peer)
            self.isDirty = True

    def removePeer(self, peer: Peer):
        if peer in self.peers:
            self.peers.remove(peer)
            self.isDirty = True

    # saves the current state to file and clear dirty flag
    def save(self):
        if self.isDirty:
            with open(self.PEER_DB_FILE, 'w') as file:
                serialized_peer_list = []
                for peer in self.peers:
                    serialized_peer_list.append(str(peer))
                file.write(json.dumps(serialized_peer_list))
            self.isDirty = False

    def getPeers(self):
        return self.peers