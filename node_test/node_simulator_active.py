import asyncio
import json
import logging

SERVER_HOST = 'localhost'  # The address of your server node
SERVER_PORT = 18018  # Port where the server is listening

# Set up logging
logging.basicConfig(level=logging.INFO)

async def read_messages(reader):
    while True:
        data = await reader.read(100)  # Read up to 100 bytes
        if not data:
            logging.info("Connection closed by server.")
            break

        # The incoming data might contain multiple messages
        messages = data.decode('utf-8').split("\n")
        for message in messages:
            if message.strip():  # Ignore empty lines
                logging.info(f"Received message: {message}")
                try:
                    msg_dict = json.loads(message)
                    handle_incoming_message(msg_dict)
                except json.JSONDecodeError:
                    logging.error("Received an invalid JSON message.")

def handle_incoming_message(msg_dict):
    # Handle different message types as needed
    if msg_dict['type'] == 'hello':
        logging.info(f"Received 'hello' message: {msg_dict}")
    elif msg_dict['type'] == 'peers':
        logging.info(f"Received 'peers' message: {msg_dict}")
    else:
        logging.info(f"Unknown message type received: {msg_dict['type']}")

async def send_message(writer, msg_type):
    if msg_type == "hello":
        message = {
            "type": "hello",
            "version": "0.10.0",
            "agent": "Kerma Agent 47"
        }
    elif msg_type == "getpeers":
        message = {
            "type": "getpeers"
        }
    elif msg_type == "getchaintip":
        message = {
            "type": "getchaintip"
        }
    else:
        logging.error("Invalid message type.")
        return

    message_json = json.dumps(message) + "\n"  # Add newline for completeness
    writer.write(message_json.encode('utf-8'))
    await writer.drain()  # Ensure the data is sent
    logging.info(f"Sent message: {message}")

async def main():
    # Create a connection to the server
    reader, writer = await asyncio.open_connection(SERVER_HOST, SERVER_PORT)

    logging.info(f'Connected to server at {SERVER_HOST}:{SERVER_PORT}')

    # Send the initial hello message
    await send_message(writer, "hello")

    # Run reading messages in the background
    read_task = asyncio.create_task(read_messages(reader))

    # Menu loop
    try:
        while True:
            print("\nChoose a message to send:")
            print("1: Send Hello")
            print("2: Send Get Peers")
            print("3: Send Get Chain Tip")
            print("4: Exit")

            choice = input("Enter your choice (1-4): ")

            if choice == "1":
                await send_message(writer, "hello")
            elif choice == "2":
                await send_message(writer, "getpeers")
            elif choice == "3":
                await send_message(writer, "getchaintip")
            elif choice == "4":
                logging.info("Exiting...")
                break
            else:
                logging.error("Invalid choice. Please enter a number between 1 and 4.")

    except Exception as e:
        logging.error(f"An error occurred: {e}")
    finally:
        logging.info("Closing the connection.")
        writer.close()
        await writer.wait_closed()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info("Client shutting down.")
