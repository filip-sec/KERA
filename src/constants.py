from Peer import Peer


PORT = 18018
ADDRESS = "0.0.0.0"
SERVICE_LOOP_DELAY = 10
VERSION = '0.10.3'
AGENT = 'Kerma-Core Client Gajdak'
LOW_CONNECTION_THRESHOLD = 10
HELLO_MSG_TIMEOUT = 20.0
DB_NAME = 'db.db'
RECV_BUFFER_LIMIT = 512 * 1024
BLOCK_TARGET = "0000abc000000000000000000000000000000000000000000000000000000000"
OBJECT_FETCH_TIMEOUT = 5
BLOCK_REWARD = 50_000_000_000_000
GENESIS_BLOCK_ID = "00002fa163c7dab0991544424b9fd302bb1782b185e5a3bbdf12afb758e57dee"
GENESIS_BLOCK = {
    "T":"0000abc000000000000000000000000000000000000000000000000000000000",
    "created":1671062400,
    "miner":"Marabu",
    "nonce":"00000000000000000000000000000000000000000000000000000000005bb0f2",
    "note":"The New York Times 2022-12-13: Scientists Achieve Nuclear Fusion Breakthrough With Blast of 192 Lasers",
    "previd": None,
    "txids":[],
    "type":"block"
}


BANNED_HOSTS = [
]

PRELOADED_PEERS = {
    Peer("128.130.122.101", 18018), # lecturers node
    #Peer("127.0.0.1", 18019), # test node 1
    #Peer("127.0.0.1", 18020), # test node 2
}
