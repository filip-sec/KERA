import sqlite3
import objects
import constants as const
import os
import json


def dropDB():
    if os.path.exists(const.DB_NAME):
        os.unlink(const.DB_NAME)


def createDB():
    print("Creating database now")
    con = sqlite3.connect(const.DB_NAME)
    try:
        cur = con.cursor()

        # Table for storing objects (transactions and blocks)
        cur.execute(
            "CREATE TABLE IF NOT EXISTS objects(oid VARCHAR(64) PRIMARY KEY, obj TEXT NOT NULL)"
        )

        # Table for storing UTXO sets and block heights
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS block_utxo(
                blockid VARCHAR(64) PRIMARY KEY,
                utxo TEXT NOT NULL,
                height INTEGER NOT NULL
            )
            """
        )

        # Preload genesis block
        res = cur.execute(
            "SELECT obj FROM objects WHERE oid = ?", (const.GENESIS_BLOCK_ID,)
        )
        if res.fetchone() is None:
            gen_id = objects.get_objid(const.GENESIS_BLOCK)
            if gen_id != const.GENESIS_BLOCK_ID:
                raise Exception("Invalid genesis block!")

            # Store genesis block in the objects table
            gen_str = objects.canonicalize(const.GENESIS_BLOCK).decode("utf-8")
            cur.execute("INSERT INTO objects VALUES(?, ?)", (gen_id, gen_str))

            # Store an empty UTXO set for the genesis block
            cur.execute(
                "INSERT INTO block_utxo (blockid, utxo, height) VALUES (?, ?, ?)",
                (gen_id, json.dumps({}), 0),
            )
        con.commit()

    except Exception as e:
        con.rollback()
        print(str(e))
    finally:
        con.close()


if __name__ == "__main__":
    createDB()
