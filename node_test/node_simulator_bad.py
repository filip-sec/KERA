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
            #19d988f2ff8a3c6db6ad5b365ea2ac7faafb356229265c5c7ef678e58e824f6b
            # tiago - coinbase transaction
            response = {
                "type": "object",
                "object": {
    "type": "transaction",
    "height": 1,
    "outputs": [
        {
            "pubkey": "da550c7ac3d73fa6b13e8a04b7c5ab59c13119ee2a22a2849164235a008fbfbb",
            "value": 150000000000000
        }
    ]
},
            }
        elif choice == "7":
            #8e23b9feed90e78ce693966af36b6650f8225c152c38ad4f2887a1801f99c8f3
            #tiago pays 10 to john
            response = {"object":
                {
    "type": "transaction",
    "inputs": [
        {
            "outpoint": {
                "txid": "19d988f2ff8a3c6db6ad5b365ea2ac7faafb356229265c5c7ef678e58e824f6b",
                "index": 0
            },
            "sig": "c6dc7a40d1ee437ece20a6a86f8256f36e64ec9e8a4306d868136a8b59a1c6dd4d11f2abd03810491c63f0c6bf1e11f18f0b8a21b21e998b2bd5d0f414c5340f"
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
            #7fa225a386f6cf99a9e6fa62a88c93aeb7ca6929cfd3fbe3fe7cea87c6d15e05
            #john pays 5 to alice and 5 to john himself
            response = {
                "type": "object",
                "object":
                        {
    "type": "transaction",
    "inputs": [
        {
            "outpoint": {
                "txid": "8e23b9feed90e78ce693966af36b6650f8225c152c38ad4f2887a1801f99c8f3",
                "index": 0
            },
            "sig": "dd638470a03ee2b0098737ee092a9d2ff098e514fad8f8951656d5c3bf4dce8a44463333956fd10e5bebed4ae2b8297f1bf734a0baebfd3357342e6c431eea05"
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
            #00001521190afa868d961e015c31a23cb31aaf8ec11f6bdc9b6f834ec987f2e9
            # block with height 1
            response = {
                "type": "object",
                "object":
                    {
    "type": "block",
    "txids": [
        "19d988f2ff8a3c6db6ad5b365ea2ac7faafb356229265c5c7ef678e58e824f6b"
    ],
    "nonce": "000000000000000000000000000000000000000000000000000000000003f38a",
    "previd": "00002fa163c7dab0991544424b9fd302bb1782b185e5a3bbdf12afb758e57dee",
    "created": 1734456168,
    "T": "0000abc000000000000000000000000000000000000000000000000000000000",
    "miner": "testerTiago",
    "note": "Mined block"
}
                }
        elif choice == "10":
            #e5bd64f287f62906f402b3be796341ace6663b6b8bf0d3b23cb189af5d6b9079
            # alice - coinbase transaction
                response = {
                    "type": "object",
                    "object":
                    {
                        "type": "transaction",
                        "height": 2,
                        "outputs": [
                            {
                                "pubkey": "921c38b1f83f2ca0aae021239aabe22916e512f0800940420bf3ffd10da64575",
                                "value": 50000000000000
                            }
                        ]
                    }
                    }
        elif choice == "11":
            #0000a9029b058af2c3c25fd643f309770ff427555522e140a5f5784cfcffbeee
            #block with height 2
            response = {
                "type": "object",
                "object":
                    {
    "type": "block",
    "txids": [
        "e5bd64f287f62906f402b3be796341ace6663b6b8bf0d3b23cb189af5d6b9079",
        "8e23b9feed90e78ce693966af36b6650f8225c152c38ad4f2887a1801f99c8f3",
        "7fa225a386f6cf99a9e6fa62a88c93aeb7ca6929cfd3fbe3fe7cea87c6d15e05"
    ],
    "nonce": "000000000000000000000000000000000000000000000000000000000002cc4f",
    "previd": "00001521190afa868d961e015c31a23cb31aaf8ec11f6bdc9b6f834ec987f2e9",
    "created": 1734456288,
    "T": "0000abc000000000000000000000000000000000000000000000000000000000",
    "miner": "testerAlice",
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
