import blockchain_helper as bh
import json

#---------------------------------------------------------------

# Valid normal transaction

inputs = [{"txid": "fb70002c26819a156814a48690848498547b3f06f8411feee4cdeb7c772d6c7a", "index": 0}]
outputs = [
    {"pubkey": "3391602a43aeb4ae9140f969240e955bf2b0833f325a1a12726cee5d4cda7ed5", "value": 10},
]
private_key_pem = """-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIG5QVbuOlaT8vofPZI3It+t3FPa6uJbafRBg2V+0J7CQ
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

# # Example: Create a coinbase transaction
# miner_pubkey = "da550c7ac3d73fa6b13e8a04b7c5ab59c13119ee2a22a2849164235a008fbfbb" 
# block_height = 1

# coinbase_tx, coinbase_txid = bh.create_coinbase_transaction(block_height, miner_pubkey)
# print("Coinbase Transaction JSON:")
# print(json.dumps(coinbase_tx, indent=4))
# print(f"Coinbase Transaction ID: {coinbase_txid}")

#---------------------------------------------------------------

