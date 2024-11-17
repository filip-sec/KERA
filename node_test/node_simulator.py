import asyncio
import json
import logging

HOST = '0.0.0.0'  # Listen on all interfaces
PORT = 18019  # Port to listen on

# Set up logging
logging.basicConfig(level=logging.INFO)

async def read_messages(reader, writer):
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
                    # logging.info(f"Parsed JSON: {msg_dict}")
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
            #fb70002c26819a156814a48690848498547b3f06f8411feee4cdeb7c772d6c7a
            response = {
                "type": "object",
                "object": {
                    "type": "transaction",
                    "height": 1,
                    "outputs": [
                        {
                                "pubkey": "da550c7ac3d73fa6b13e8a04b7c5ab59c13119ee2a22a2849164235a008fbfbb",
                                "value": 50000000000000
                            }
                        ]
                    },
            }
        elif choice == "7":
            #c966ef7b766a7c355749e13a58f7ac0bad0cef4da646db8aef1ea6f58cee5443
            response = {"object":
                {
                    "type": "transaction",
                    "inputs": [
                        {
                            "outpoint": {
                                "txid": "fb70002c26819a156814a48690848498547b3f06f8411feee4cdeb7c772d6c7a",
                                "index": 0
                            },
                            "sig": "830af0137d79f095555d4f3c86df285a7a651edb196d326cbad5662e04122e7de00e5ecd22e99b3df12fa2ad4adeea514d48e77defd244daf8375e9e91e30001"
                        }
                    ],
                    "outputs": [
                        {
                            "pubkey": "3391602a43aeb4ae9140f969240e955bf2b0833f325a1a12726cee5d4cda7ed5",
                            "value": 10
                        }
                    ]
                }
                ,"type":"object"}
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
