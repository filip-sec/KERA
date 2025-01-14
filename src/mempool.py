import copy
import sqlite3
from message.msgexceptions import *

import constants as const
import objects

# get expanded object for 
def fetch_object(oid, cur):
    """
    Fetch an expanded object (transaction or block) by its ID.
    :param oid: Object ID.
    :param cur: SQLite cursor.
    :return: Expanded object dictionary or None.
    """
    # Query the database for the object by its ID
    res = cur.execute("SELECT obj FROM objects WHERE oid = ?", (oid,))
    row = res.fetchone()

    # If no object is found, return None
    if row is None:
        return None

    # Expand and return the object
    return objects.expand_object(row[0])


# get utxo for block
def fetch_utxo(bid, cur):
    """
    Fetch the UTXO set for a given block ID.
    :param bid: Block ID.
    :param cur: SQLite cursor.
    :return: UTXO set dictionary.
    """
    # Query the database for the UTXO set associated with the block ID
    res = cur.execute("SELECT utxoset FROM utxo WHERE blockid = ?", (bid,))
    row = res.fetchone()

    # If no UTXO set is found, return an empty dictionary
    if row is None:
        return {}

    # Expand and return the UTXO set
    return objects.expand_object(row[0])

def get_all_txids_in_blocks(blocks):
    """
    Retrieve all transaction IDs (txids) from a list of blocks.
    :param blocks: A list of block IDs.
    :return: A list of transaction IDs contained in the given blocks.
    """
    txids = []
    con = sqlite3.connect(const.DB_NAME)
    try:
        cur = con.cursor()

        for block in blocks:
            # Fetch the block object from the database
            res = cur.execute("SELECT obj FROM objects WHERE oid = ?", (block,))
            row = res.fetchone()

            if not row:
                print(f"Block {block} not found in the database; skipping.")
                continue

            # Expand the block object to access its transactions
            block_obj = objects.expand_object(row[0])

            if block_obj['type'] != 'block':
                print(f"Object {block} is not a block; skipping.")
                continue

            # Append all txids from the block's transactions
            txids.extend(block_obj['txids'])

        return txids

    except Exception as e:
        print(f"Error retrieving txids from blocks: {str(e)}")
        raise e
    finally:
        con.close()


def get_lca_and_intermediate_blocks(old_tip: str, new_tip: str):
    """
    Finds the Latest Common Ancestor (LCA) and the intermediate blocks for both old and new chains.
    :param old_tip: Block ID of the old chain tip.
    :param new_tip: Block ID of the new chain tip.
    :return: A tuple (lca, old_blocks, new_blocks).
             lca: The block ID of the LCA.
             old_blocks: A list of block IDs from the LCA to the old chain tip (exclusive).
             new_blocks: A list of block IDs from the LCA to the new chain tip (exclusive).
    """
    con = sqlite3.connect(const.DB_NAME)
    try:
        cur = con.cursor()

        def trace_back_to_genesis(tip):
            """Trace back the chain from the given tip to the Genesis block."""
            chain = []
            current_block = tip
            while current_block:
                chain.append(current_block)
                current_block_dict = fetch_object(current_block, cur)
                res = cur.execute("SELECT obj FROM objects WHERE oid = ?", (current_block,))
                row = res.fetchone()
                current_block = objects.expand_object(row[0])["previd"]
            return chain

        # Trace both chains back to the Genesis block
        old_chain = trace_back_to_genesis(old_tip)
        new_chain = trace_back_to_genesis(new_tip)

        # Reverse the chains to start from Genesis
        old_chain.reverse()
        new_chain.reverse()

        # Find the LCA
        lca = None
        for b1, b2 in zip(old_chain, new_chain):
            if b1 == b2:
                lca = b1
            else:
                break

        # Identify blocks from the LCA to the tips
        old_blocks = old_chain[old_chain.index(lca) + 1:] if lca else []
        new_blocks = new_chain[new_chain.index(lca) + 1:] if lca else []
        
        print (f"LCA: {lca}")
        print (f"Old blocks: {old_blocks}")
        print (f"New blocks: {new_blocks}")

        return lca, old_blocks, new_blocks

    finally:
        con.close()



def rebase_mempool(old_tip, new_tip, mptxids):
    """
    Rebase the mempool when the chain changes.
    :param old_tip: Block ID of the old chain tip.
    :param new_tip: Block ID of the new chain tip.
    :param mptxids: List of transaction IDs currently in the mempool.
    :return: A tuple (new_mempool_txs, updated_utxo).
    """
    con = sqlite3.connect(const.DB_NAME)
    try:
        cur = con.cursor()

        # Step 1: Find LCA and intermediate blocks
        lca, old_blocks, new_blocks = get_lca_and_intermediate_blocks(old_tip, new_tip)

        # Step 2: Fetch UTXO state at the LCA
        utxo = fetch_utxo(lca, cur)
        
        print(f"UTXO at LCA: {utxo}")
        
        # go to database and get the utxo for the newtip
        utxo = fetch_utxo(new_tip, cur)
        
        print(f"UTXO after applying transactions from new blocks: {utxo}")
        
        # Step 4: Rebuild the mempool
        new_mempool_txs = []

        # Add transactions from old chain's blocks to the new mempool
        for block in old_blocks:
            block_txs = get_all_txids_in_blocks([block])
            for txid in block_txs:
                tx = fetch_object(txid, cur)
                if tx:
                    try:
                        # Verify transaction inputs and values
                        if not verify_transaction_inputs_and_values(tx, utxo):
                            print(f"Transaction {txid} from old blocks is invalid with the current UTXO set.")
                            continue
                        objects.update_utxo_and_calculate_fee(tx, utxo)
                        new_mempool_txs.append(txid)
                    except Exception as e:
                        print(f"Transaction {txid} from old blocks discarded: {str(e)}")
                        
        print(f'UTXO after applying transactions from old blocks: {utxo}')
        print(f'New mempool txs: {new_mempool_txs}')

        # Add transactions from the old mempool to the new mempool
        for txid in mptxids:
            tx = fetch_object(txid, cur)
            if tx:
                try:
                    # Verify transaction inputs and values
                    if not verify_transaction_inputs_and_values(tx, utxo):
                        print(f"Transaction {txid} is invalid with the current UTXO set.")
                        continue
                    print(f"Transaction {txid} from old mempool is valid")
                    objects.update_utxo_and_calculate_fee(tx, utxo)
                    new_mempool_txs.append(txid)
                except Exception as e:
                    print(f"Transaction {txid} from old mempool discarded")
                    
        print(f'UTXO after applying transactions from old mempool: {utxo}')
        print(f'New mempool txs: {new_mempool_txs}')

        print(f"Mempool rebased to new chain tip {new_tip}. Valid transactions: {len(new_mempool_txs)}")
        return new_mempool_txs, utxo

    except Exception as e:
        print(f"Failed to rebase mempool: {str(e)}")
        raise e
    finally:
        con.close()
        
def verify_transaction_inputs_and_values(tx, utxo_set):
    """
    Verifies if the inputs and values of the transaction are valid according to the current UTXO set.
    :param tx: The transaction to verify.
    :param utxo_set: The UTXO set to check against.
    :return: True if all inputs and values are valid, False otherwise.
    """
    try:
        # Coinbase transactions should not be passed to this function
        if "height" in tx:
            raise Exception("Coinbase transactions should not be verified here.")

        # Sum of inputs and outputs
        input_sum = 0
        output_sum = 0

        # Check each input
        for input_data in tx["inputs"]:
            outpoint = input_data["outpoint"]
            txid = outpoint["txid"]
            index = str(outpoint["index"])

            # Verify the outpoint exists in the UTXO set
            if txid not in utxo_set or index not in utxo_set[txid]:
                raise Exception(f"Input outpoint {txid}:{index} does not exist in UTXO set.")

            # Fetch the input's value
            input_value = utxo_set[txid][index]
            input_sum += input_value

        # Sum the outputs
        for output_data in tx["outputs"]:
            value = output_data["value"]

            # Ensure output value is positive
            if value <= 0:
                raise Exception("Output value must be positive.")

            output_sum += value

        # Check that input_sum >= output_sum
        if input_sum < output_sum:
            raise Exception("Input sum is less than output sum.")

        # If everything is valid, return True
        return True

    except Exception as e:
        print(f"Transaction validation error: {e}")
        return False

    



class Mempool:
    def __init__(self, bbid: str, butxo: dict):
        self.base_block_id = bbid
        self.utxo = butxo
        self.txs = []

    def try_add_tx(self, tx: dict) -> bool:
        """
        Try to add a transaction to the mempool.
        :param tx: Transaction dictionary.
        :return: True if the transaction was added, False otherwise.
        """
        txid = objects.get_objid(tx)  # Generate transaction ID

        # Check if the transaction is already in the mempool
        if txid in self.txs:
            print(f"Transaction {txid} is already in the mempool.")
            return False
        
        # Reject coinbase transactions
        if "height" in tx:
            print(f"Transaction {txid} is a coinbase transaction and cannot be added to the mempool.")
            return False

        try:
            print(f'UTXO: {self.utxo}')
            
            # Verify transaction inputs and values
            if not verify_transaction_inputs_and_values(tx, self.utxo):
                print(f"Transaction {txid} is invalid with the current UTXO set.")
                return False

            # Update the mempool's UTXO set to include this transaction
            objects.update_utxo_and_calculate_fee(tx, self.utxo)

            # Add transaction to the mempool
            self.txs.append(txid)
            print(f"Transaction {txid} added to the mempool.")
            return True

        except Exception as e:
            print(f"Transaction {txid} failed to verify: {str(e)}")
            return False

