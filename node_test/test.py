import blockchain_helper as bh
import json
import hashlib
from jcs import canonicalize

#---------------------------------------------------------------

# # Valid normal transaction

# inputs = [{"txid": "c966ef7b766a7c355749e13a58f7ac0bad0cef4da646db8aef1ea6f58cee5443", "index": 0}]
# outputs = [
#     {"pubkey": "3391602a43aeb4ae9140f969240e955bf2b0833f325a1a12726cee5d4cda7ed5", "value": 6},
#     {"pubkey": "921c38b1f83f2ca0aae021239aabe22916e512f0800940420bf3ffd10da64575", "value": 5}
# ]
# private_key_pem = """-----BEGIN PRIVATE KEY-----
# MC4CAQAwBQYDK2VwBCIEID2+BBzvsXLmG1UUBQydgk3PXL9JcEIV+bKZ3ZUCXbG4
# -----END PRIVATE KEY-----"""

# transaction, txid = bh.create_transaction(inputs, outputs, private_key_pem)
# print("Transaction JSON:")
# print(json.dumps(transaction, indent=4))
# print(f"Transaction ID: {txid}")

#---------------------------------------------------------------

# # Generate Key Pair
# priv, pub = bh.generate_key_pair()
# print(f"Private Key: {priv}")
# print(f"Public Key: {pub}")

#---------------------------------------------------------------

# # Example: Create a coinbase transaction
# miner_pubkey = "921c38b1f83f2ca0aae021239aabe22916e512f0800940420bf3ffd10da64575" 
# block_height = 2

# coinbase_tx, coinbase_txid = bh.create_coinbase_transaction(block_height, miner_pubkey)
# print("Coinbase Transaction JSON:")
# print(json.dumps(coinbase_tx, indent=4))
# print(f"Coinbase Transaction ID: {coinbase_txid}")

#---------------------------------------------------------------

# Mine a new block

transactions_ids = ["e5bd64f287f62906f402b3be796341ace6663b6b8bf0d3b23cb189af5d6b9079",
                    "c966ef7b766a7c355749e13a58f7ac0bad0cef4da646db8aef1ea6f58cee5443",
                    "f8d92c944e29ce9b36ff6baecf2412219ff7405f4ec7108c0467737d9e82c607"]
prev_block_id = "0713f5d3c0dcea5cac1e31d23651e52f03cf1e6dd58f72532efe9650ec303b32"
block, block_id = bh.mine_block(prev_block_id, transactions_ids, miner="testerTiago")
print("Block JSON:")
print(json.dumps(block, indent=4))
print(f"Block ID: {block_id}")

#---------------------------------------------------------------