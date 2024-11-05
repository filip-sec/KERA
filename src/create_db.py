import hashlib
import sqlite3
import constants as const
import json
from jcs import canonicalize

# Function to create the database and objects table
def main():
    con = sqlite3.connect(const.DB_NAME)
    try:
        cur = con.cursor()

        # Create objects table to store JSON objects with their unique ids
        cur.execute('''
            CREATE TABLE IF NOT EXISTS objects (
                objectid TEXT PRIMARY KEY,
                object_data TEXT NOT NULL
            )
        ''')
        print("Database and table created successfully.")

        # Preload genesis block if not already in the database
        preload_genesis_block(cur)

        con.commit()
    except Exception as e:
        con.rollback()
        print(f"Database setup failed: {str(e)}")
    finally:
        con.close()

# Function to preload genesis block
def preload_genesis_block(cur):
    # Convert genesis block to canonical JSON format and get object ID
    genesis_block_json = json.dumps(const.GENESIS_BLOCK)
    genesis_id = get_objid(const.GENESIS_BLOCK)

    # Check if genesis block already exists in the database
    cur.execute("SELECT * FROM objects WHERE objectid = ?", (genesis_id,))
    if cur.fetchone() is None:
        cur.execute("INSERT INTO objects (objectid, object_data) VALUES (?, ?)", (genesis_id, genesis_block_json))
        print("Genesis block loaded into database.")
    else:
        print("Genesis block already exists in database.")

# Helper function to get unique object ID for a given object
def get_objid(obj_dict):
    return hashlib.blake2s(canonicalize(obj_dict)).hexdigest()

if __name__ == "__main__":
    main()
