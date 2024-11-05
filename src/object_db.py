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

def check_object_in_db(objid):
    """Check if an object with a given objectid exists in the database."""
    con = sqlite3.connect(const.DB_NAME)
    try:
        cur = con.cursor()
        cur.execute("SELECT COUNT(1) FROM objects WHERE objectid = ?", (objid,))
        exists = cur.fetchone()[0] > 0
    except Exception as e:
        print(f"Error checking object in DB: {e}")
        return False
    finally:
        con.close()
    return exists

def get_object(objid):
    """Retrieve an object from the database given its objectid."""
    con = sqlite3.connect(const.DB_NAME)
    try:
        cur = con.cursor()
        cur.execute("SELECT object_data FROM objects WHERE objectid = ?", (objid,))
        obj_data = cur.fetchone()[0]
    except Exception as e:
        print(f"Error retrieving object from DB: {e}")
        return None
    finally:
        con.close()
    return json.loads(obj_data)

def store_object(obj_dict):
    """Store an object in the database."""
    con = sqlite3.connect(const.DB_NAME)
    try:
        cur = con.cursor()
        obj_id = get_objid(obj_dict)
        obj_json = json.dumps(obj_dict)
        cur.execute("INSERT INTO objects (objectid, object_data) VALUES (?, ?)", (obj_id, obj_json))
        con.commit()
    except Exception as e:
        con.rollback()
        print(f"Error storing object in DB: {e}")
    finally:
        con.close()

if __name__ == "__main__":
    main()
