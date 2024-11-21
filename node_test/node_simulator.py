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
            # tiago - coinbase transaction
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
            #tiago pays 10 to john
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
        elif choice == "8":
            #f8d92c944e29ce9b36ff6baecf2412219ff7405f4ec7108c0467737d9e82c607
            #john pays 5 to alice and 5 to john himself
            response = {
                "type": "object",
                "object":
                        {
                            "type": "transaction",
                            "inputs": [
                                {
                                    "outpoint": {
                                        "txid": "c966ef7b766a7c355749e13a58f7ac0bad0cef4da646db8aef1ea6f58cee5443",
                                        "index": 0
                                    },
                                    "sig": "b58c30f891f0b6116bd0d2ad240cbb1b370ec571aa9bc565e4fe0ec8a734787b74d844fd84a0f5d3e47773b3cf8ca3fe82005c56f18ce9bb00c7f5798c694c0a"
                                }
                            ],
                            "outputs": [
                                {
                                    "pubkey": "3391602a43aeb4ae9140f969240e955bf2b0833f325a1a12726cee5d4cda7ed5",
                                    "value": 5
                                },
                                {
                                    "pubkey": "921c38b1f83f2ca0aae021239aabe22916e512f0800940420bf3ffd10da64575",
                                    "value": 5
                                }
                            ]
                        }
            }
        elif choice == "9":
            #0713f5d3c0dcea5cac1e31d23651e52f03cf1e6dd58f72532efe9650ec303b32
            # block with height 1
            response = {
                "type": "object",
                                "object": {
                    "type": "block",
                    "txids": [
                        "fb70002c26819a156814a48690848498547b3f06f8411feee4cdeb7c772d6c7a"
                    ],
                    "nonce": "0000000000000000000000000000000000000000000000000000000000000015",
                    "previd": "0000000052a0e645eca917ae1c196e0d0a4fb756747f29ef52594d68484bb5e2",
                    "created": 1732035349,
                    "T": "0a00000000000000000000000000000000000000000000000000000000000000",
                    "miner": "tester",
                    "note": "Mined block"
                }}
        elif choice == "10":
            #0afb603c5e9bf99d0d3b8bc8fc6686e4d6d175fbebcd7783fe774aebc1f9152b
            # alice - coinbase transaction
                response = {
                    "type": "object",
                    "object": {
    "type": "transaction",
    "height": 2,
    "outputs": [
        {
            "pubkey": "921c38b1f83f2ca0aae021239aabe22916e512f0800940420bf3ffd10da64575",
            "value": 99999999999990
        }
    ]
}
                    }
        elif choice == "11":
            #088c43e9b9eae4190ef3544586d6810232408c08700c15fffd014365476b475d
            #block with height 2
            response = {
                "type": "object",
                "object": {
    "type": "block",
    "txids": [
        "0afb603c5e9bf99d0d3b8bc8fc6686e4d6d175fbebcd7783fe774aebc1f9152b",
        "c966ef7b766a7c355749e13a58f7ac0bad0cef4da646db8aef1ea6f58cee5443",
        "f8d92c944e29ce9b36ff6baecf2412219ff7405f4ec7108c0467737d9e82c607"
    ],
    "nonce": "000000000000000000000000000000000000000000000000000000000000000a",
    "previd": "0713f5d3c0dcea5cac1e31d23651e52f03cf1e6dd58f72532efe9650ec303b32",
    "created": 1732215878,
    "T": "0a00000000000000000000000000000000000000000000000000000000000000",
    "miner": "testerTiago",
    "note": "Mined block"
}
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
