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

        message = data.decode('utf-8')
        logging.info(f"Received message: {message}")

        # Process the received message as JSON
        try:
            msg_dict = json.loads(message)
            logging.info(f"Parsed JSON: {msg_dict}")
        except json.JSONDecodeError:
            logging.error("Received an invalid JSON message.")

async def send_messages(writer):
    while True:
        print("Choose a response to send back:")
        print("1: Hello response")
        print("2: Get peers response")
        choice = input("Enter 1 or 2: ")

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

        # Send response back to the client
        writer.write(response_json.encode('utf-8'))
        await writer.drain()  # Ensure the data is sent
        #logging.info(f"Sent response: {response_json.strip()}")

async def handle_client(reader, writer):
    read_task = asyncio.create_task(read_messages(reader))
    send_task = asyncio.create_task(send_messages(writer))

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