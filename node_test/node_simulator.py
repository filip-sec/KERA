import asyncio
import json
import logging

HOST = '0.0.0.0'  # Listen on all interfaces
PORT = 18019  # Port to listen on

# Set up logging
logging.basicConfig(level=logging.INFO)

async def read_messages(reader,writer):
    while True:
        data = await reader.read(1024)  # Read up to 100 bytes
        if not data:
            logging.info("Connection closed by client.")
            
            # Close the TCP port
            writer.close()
            await writer.wait_closed()
            
            break

        # The incoming data might contain multiple messages
        messages = data.decode('utf-8').split("\n")
        for message in messages:
            if message.strip():  # Ignore empty lines
                logging.info(f"\n\nReceived message: {message}\n\n")
                # Process the received message as JSON
                try:
                    msg_dict = json.loads(message)
                    #logging.info(f"Parsed JSON: {msg_dict}")
                except json.JSONDecodeError:
                    logging.error("Received an invalid JSON message.")

async def async_input(prompt: str) -> str:
    """Asynchronous wrapper for input using a thread to avoid blocking the event loop."""
    return await asyncio.to_thread(input, prompt)

async def send_messages(writer):
    while True:
        print("Choose a response to send back:")
        print("1: Hello response")
        print("2: Get peers response")
        print("3: Peers response")
        print("4: GetObject message")
        print("5: IHaveObject message")
        print("6: Object message")
        
        # Use async_input to avoid blocking the event loop
        choice = await async_input("Enter number: ")

        if choice == "1":
            response = {
                "type": "hello",
                "version": "0.10.0",
                "agent": "Kerma Agent 47"
            }
        elif choice == "2":
            response = {
                "type": "getpeers",
            }
        elif choice == "3":
            response = {
                "type": "peers",
                "peers": [
                    "192.169.5.3:18018",
                    "192.168.1.5:18018"
                ]
            }
        elif choice == "4":
            response = {
                "type": "getobject",
                "objectid": "d46d09138f0251edc32e28f1a744cb0b7286850e4c9c777d7e3c6e459b289347"  # Example object ID
            }
        elif choice == "5":
            response = {
                "type": "ihaveobject",
                "objectid": "0000000052a0e645eca917ae1c196e0d0a4fb756747f29ef52594d68484bb333"  # Example object ID
            }
        elif choice == "6":
            response = {
                "type": "object",
                "object":{ 
                    "height": 0, 
                    "outputs": [{
                            "pubkey": "85acb336a150b16a9c6c8c27a4e9c479d9f99060a7945df0bb1b53365e98969b",
                            "value": 50000000000000
                    }],
                    "type": "transaction" 
                },
            }
        elif choice == "7":
            #895ca2bea390b7508f780c7174900a631e73905dcdc6c07a6b61ede2ebd4033f
            response = {
                "type": "object",
                "object": {
                    "inputs": [
                        {
                            "outpoint": {
                                "index": 0,
                                "txid": "d56d09138f0251edc32e28f1a744cb0b7286850e4c9c777d7e3c6e459b289347"
                            },
                            "sig": "6204bbab1b736ce2133c4ea43aff3767c49c881ac80b57ba38a3bab980466644cdbacc86b1f4357cfe45e6374b963f5455f26df0a86338310df33e50c15d7f04"
                        }
                    ],
                    "outputs": [
                        {
                            "pubkey": "b539258e808b3e3354b9776d1ff4146b52282e864f56224e7e33e7932ec72985",
                            "value": 10
                        },
                        {
                            "pubkey": "8dbcd2401c89c04d6e53c81c90aa0b551cc8fc47c0469217c8f5cfbae1e911f9",
                            "value": 49999999999990
                        }
                    ],
                    "type": "transaction"
                },
            }
        else:
            print("Invalid choice.")
            continue

        # Send the response to the server
        writer.write((json.dumps(response) + "\n").encode('utf-8'))
        await writer.drain()
        print(f"Sent response: {json.dumps(response)}")

async def handle_client(reader, writer):
    # Run both reading and sending tasks in parallel
    read_task = asyncio.create_task(read_messages(reader,writer))
    send_task = asyncio.create_task(send_messages(writer))

    # Wait for both tasks to finish (they will run indefinitely until the connection closes)
    await asyncio.gather(read_task, send_task)

    logging.info("Closing the connection.")
    writer.close()
    await writer.wait_closed()

async def main():
    server = await asyncio.start_server(handle_client, HOST, PORT)
    logging.info(f'Serving on {HOST}:{PORT}')

    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info("Server shutting down.")
