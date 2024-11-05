import asyncio
import json
import logging

HOST = '0.0.0.0'  # Listen on all interfaces
PORT = 18019  # Port to listen on

# Set up logging
logging.basicConfig(level=logging.INFO)

async def read_messages(reader,writer):
    while True:
        data = await reader.read(100)  # Read up to 100 bytes
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
                "objectid": "0000000052a0e645eca917ae1c196e0d0a4fb756747f29ef52594d68484bb5e2"  # Example object ID
            }
        elif choice == "5":
            response = {
                "type": "ihaveobject",
                "objectid": "0000000052a0e645eca917ae1c196e0d0a4fb756747f29ef52594d68484bb5e2"  # Example object ID
            }
        elif choice == "6":
            response = {
                "type": "object",
                "object": {
                    "T": "00000000abc00000000000000000000000000000000000000000000000000000",  # Example ID
                    "created": 1671062400,  # Example timestamp
                    "miner": "Marabu",  # Example miner name
                    "nonce": "000000000000000000000000000000000000000000000000000000021bea03ed",  # Example nonce
                    "note": "The New York Times 2022−12−13: Scientists Achieve Nuclear Fusion Breakthrough With Blast of 192 Lasers",  # Example note
                    "previd": None,  # Example previous object ID (None for genesis)
                    "txids": [],  # Example transaction IDs (empty for now)
                    "type": "block"  # Specify type as block or transaction as needed
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
