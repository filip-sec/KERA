import blockchain_helper as bh
import json
import hashlib
from jcs import canonicalize

#---------------------------------------------------------------

# Valid normal transaction

inputs = [{"txid": "d150fd544d2a7a10c39640a400b8885864f5fd69fc3a91e8be33634f113c94c5", "index": 0}]
outputs = [
    {"pubkey": "3391602a43aeb4ae9140f969240e955bf2b0833f325a1a12726cee5d4cda7ed5", "value": 5},
    {"pubkey": "921c38b1f83f2ca0aae021239aabe22916e512f0800940420bf3ffd10da64575", "value": 5}
]
private_key_pem = """-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEID2+BBzvsXLmG1UUBQydgk3PXL9JcEIV+bKZ3ZUCXbG4
-----END PRIVATE KEY-----"""

transaction, txid = bh.create_transaction(inputs, outputs, private_key_pem)
print("Transaction JSON:")
print(json.dumps(transaction, indent=4))
print(f"Transaction ID: {txid}")

#---------------------------------------------------------------

# # Generate Key Pair
# priv, pub = bh.generate_key_pair()
# print(f"Private Key: {priv}")
# print(f"Public Key: {pub}")

#---------------------------------------------------------------

# Example: Create a coinbase transaction
# miner_pubkey = "da550c7ac3d73fa6b13e8a04b7c5ab59c13119ee2a22a2849164235a008fbfbb" 
# block_height = 1
# reward = 9

# coinbase_tx, coinbase_txid = bh.create_coinbase_transaction(block_height, miner_pubkey, reward)
# print("Coinbase Transaction JSON:")
# print(json.dumps(coinbase_tx, indent=4))
# print(f"Coinbase Transaction ID: {coinbase_txid}")

#---------------------------------------------------------------

# Mine a new block

# transactions_ids = ["e5bd64f287f62906f402b3be796341ace6663b6b8bf0d3b23cb189af5d6b9079",
#                     "8e23b9feed90e78ce693966af36b6650f8225c152c38ad4f2887a1801f99c8f3",
#                     "7fa225a386f6cf99a9e6fa62a88c93aeb7ca6929cfd3fbe3fe7cea87c6d15e05"]
# prev_block_id = "00001521190afa868d961e015c31a23cb31aaf8ec11f6bdc9b6f834ec987f2e9"
# block, block_id = bh.mine_block(prev_block_id, transactions_ids, miner="testerAlice")
# print("Block JSON:")
# print(json.dumps(block, indent=4))
# print(f"Block ID: {block_id}")

#---------------------------------------------------------------