import hashlib
import json
import time
import copy
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from jcs import canonicalize

# Constants
TARGET = "00000000abc00000000000000000000000000000000000000000000000000000"
BLOCK_REWARD = 50000000000000  # 50 KER


def calculate_object_id(obj):
    """
    Calculate the object ID (hash) of a JSON object using Blake2s and canonical JSON format.

    Args:
        obj (dict): The JSON object for which to calculate the ID.

    Returns:
        str: The calculated object ID (64-character hexadecimal string).
    """
    try:
        # Canonicalize the JSON object
        canonical_json = canonicalize(obj)

        # Compute the Blake2s hash
        object_id = hashlib.blake2s(canonical_json).hexdigest()
        return object_id
    except Exception as e:
        print(f"Error calculating object ID: {e}")
        return None


def generate_key_pair():
    """Generates a new Ed25519 key pair."""
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    return private_key_bytes.decode('utf-8'), public_key_bytes.hex()


def create_transaction(inputs, outputs, private_key_pem):
    """Creates a new transaction with inputs, outputs, and signs it."""
    tx = {
        "type": "transaction",
        "inputs": [],
        "outputs": outputs
    }

    # Generate input signatures
    for input_data in inputs:
        tx_input = {
            "outpoint": input_data,
            "sig": None
        }
        tx["inputs"].append(tx_input)

    # Sign the transaction
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode('utf-8'),
        password=None
    )

    # Replace sig fields with null for signing
    tx_to_sign = copy.deepcopy(tx)
    for i in tx_to_sign['inputs']:
        i['sig'] = None
    canonical_tx = canonicalize(tx_to_sign)
    signature = private_key.sign(canonical_tx).hex()

    # Add the signature back to each input
    for tx_input in tx["inputs"]:
        tx_input["sig"] = signature

    # Compute the transaction ID
    txid = calculate_object_id(tx)

    return tx, txid

def create_coinbase_transaction(height, pubkey, reward=50000000000000):
    """
    Generate a coinbase transaction.
    
    Args:
        height (int): The block height (must be non-negative).
        pubkey (str): The miner's public key (hex-encoded).
        reward (int): The block reward (default is 50 * 10^12 picaker).
        
    Returns:
        dict: The coinbase transaction.
        str: The transaction ID (hash).
    """
    if height < 0:
        raise ValueError("Block height must be non-negative.")

    coinbase_tx = {
        "type": "transaction",
        "height": height,
        "outputs": [
            {
                "pubkey": pubkey,
                "value": reward
            }
        ]
    }
    txid = calculate_object_id(coinbase_tx)
    return coinbase_tx, txid



def mine_block(prev_blockid, transactions, miner="tester"):
    """Simulates mining a block."""
    nonce = 0
    timestamp = int(time.time())
    block = {
        "type": "block",
        "txids": [tx["id"] for tx in transactions],
        "nonce": None,
        "previd": prev_blockid,
        "created": timestamp,
        "T": TARGET,
        "miner": miner,
        "note": "Mined block",
    }

    while True:
        block["nonce"] = f"{nonce:064x}"
        block_data = json.dumps(block, separators=(',', ':'))
        blockid = hashlib.blake2s(block_data.encode('utf-8')).hexdigest()

        if blockid < TARGET:
            break

        nonce += 1

    return block, blockid


def main():
    print("Choose an action:")
    print("1. Generate Key Pair")
    print("2. Create Transaction")
    print("3. Mine Block")
    print("4. Calculate Object ID")
    choice = input("Enter choice: ")

    if choice == "1":
        priv, pub = generate_key_pair()
        print(f"Private Key (PEM):\n{priv}")
        print(f"Public Key:\n{pub}")

    elif choice == "2":
        num_inputs = int(input("Number of inputs: "))
        inputs = []
        for _ in range(num_inputs):
            txid = input("Enter previous transaction ID: ")
            index = int(input("Enter output index: "))
            inputs.append({"txid": txid, "index": index})

        num_outputs = int(input("Number of outputs: "))
        outputs = []
        for _ in range(num_outputs):
            pubkey = input("Enter recipient public key: ")
            value = int(input("Enter value: "))
            outputs.append({"pubkey": pubkey, "value": value})

        priv_key_pem = input("Enter your private key (PEM): ")
        tx, txid = create_transaction(inputs, outputs, priv_key_pem)
        print("Transaction JSON:")
        print(json.dumps(tx, indent=4))
        print(f"Transaction ID: {txid}")

    elif choice == "3":
        prev_blockid = input("Enter previous block ID: ")
        num_txs = int(input("Number of transactions in the block: "))
        transactions = []
        for _ in range(num_txs):
            txid = input("Enter transaction ID: ")
            transactions.append({"id": txid})

        miner_name = input("Enter miner name: ")
        block, block_id = mine_block(prev_blockid, transactions, miner_name)
        print("Block JSON:")
        print(json.dumps(block, indent=4))
        print(f"Block ID: {block_id}")

    elif choice == "4":
        obj = input("Enter JSON object as a string: ")
        obj = json.loads(obj)
        obj_id = calculate_object_id(obj)
        print(f"Object ID: {obj_id}")

    else:
        print("Invalid choice.")


if __name__ == "__main__":
    main()
