import asyncio
import json
import logging

HOST = '0.0.0.0'  # Listen on all interfaces
PORT = 18019  # Port to listen on

# Set up logging
logging.basicConfig(level=logging.INFO)

async def read_messages(reader):
    while True:
        data = await reader.read(100)  # Read up to 100 bytes
        if not data:
            logging.info("Connection closed by client.")
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
        
        # Use async_input to avoid blocking the event loop
        choice = await async_input("Enter 1 or 2: ")

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
        else:
            print("Invalid choice. Please enter 1 or 2.")
            continue

        response_json = json.dumps(response) + "\n"  # Add newline for completeness

        # Split the response in half to simulate a partial response
        #part1 = response_json[:len(response_json)//2]
        #writer.write(part1.encode('utf-8'))
        #await writer.drain()
        
        # Simulate a delay
        #await asyncio.sleep(5)
        
        #part2 = response_json[len(response_json)//2:]
        #writer.write(part2.encode('utf-8'))
        #await writer.drain()
    
        
        # Send response back to the client
        writer.write(response_json.encode('utf-8'))
        await writer.drain()  # Ensure the data is sent
        logging.info(f"Sent response: {response_json.strip()}")

async def handle_client(reader, writer):
    # Run both reading and sending tasks in parallel
    read_task = asyncio.create_task(read_messages(reader))
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
