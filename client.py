
import json
import socket
import struct
import threading

from crypto_utils import (
    load_or_create_key,
    encrypt_message,
    decrypt_message,
)

HOST = "127.0.0.1"
PORT = 5000
MAX_PACKET_SIZE = 1_000_000

key = load_or_create_key()


def receive_exactly(sock, size):
    data = bytearray()

    while len(data) < size:
        chunk = sock.recv(size - len(data))

        if not chunk:
            return None

        data.extend(chunk)

    return bytes(data)


def receive_packet(sock):
    header = receive_exactly(sock, 4)

    if header is None:
        return None

    length = struct.unpack("!I", header)[0]

    if length < 1 or length > MAX_PACKET_SIZE:
        raise ValueError("Invalid packet size.")

    packet = receive_exactly(sock, length)

    if packet is None:
        return None

    kind = packet[:1]
    payload = packet[1:]

    if kind not in (b"J", b"E"):
        raise ValueError("Unknown packet type.")

    return kind, payload


def send_packet(sock, kind, payload):
    packet = kind + payload
    sock.sendall(struct.pack("!I", len(packet)) + packet)


def send_json(sock, data):
    payload = json.dumps(data).encode("utf-8")
    send_packet(sock, b"J", payload)


def receive_messages(client):
    try:
        while True:
            packet = receive_packet(client)

            if packet is None:
                print("\n[!] Disconnected from server.")
                break

            kind, payload = packet

            if kind == b"J":
                data = json.loads(payload.decode("utf-8"))

                if data.get("type") == "system":
                    print(f"\n[*] {data['message']}")

                print("You: ", end="", flush=True)

            elif kind == b"E":
                plaintext = decrypt_message(payload, key)
                data = json.loads(plaintext)

                username = data.get("username", "Unknown")
                message = data.get("message", "")

                print(f"\n{username}: {message}")
                print("You: ", end="", flush=True)

    except (
        OSError,
        ValueError,
        json.JSONDecodeError,
        UnicodeDecodeError,
    ) as error:
        print(f"\n[!] Receive error: {error}")

    finally:
        try:
            client.close()
        except OSError:
            pass


def main():
    username = input(
        "Choose a username (3-20 characters, letters/numbers/_/-): "
    ).strip()

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        client.connect((HOST, PORT))

        send_json(
            client,
            {
                "type": "login",
                "username": username,
            },
        )

        response = receive_packet(client)

        if response is None or response[0] != b"J":
            print("[!] No valid response from server.")
            return

        data = json.loads(response[1].decode("utf-8"))

        if data.get("type") == "error":
            print(f"[!] {data['message']}")
            return

        if data.get("type") != "welcome":
            print("[!] Login failed.")
            return

        username = data["username"]

        print(f"[+] Welcome, {username}!")
        print("Type /quit to exit.\n")

        receiver = threading.Thread(
            target=receive_messages,
            args=(client,),
            daemon=True,
        )
        receiver.start()

        while True:
            message = input("You: ")

            if message.strip().lower() == "/quit":
                break

            if not message.strip():
                continue

            encrypted_payload = encrypt_message(
                json.dumps(
                    {
                        "username": username,
                        "message": message,
                    },
                    ensure_ascii=False,
                ),
                key,
            )

            send_packet(client, b"E", encrypted_payload)

    except ConnectionRefusedError:
        print("[!] Server is not running. Start server.py first.")

    except (OSError, ValueError) as error:
        print(f"[!] Client error: {error}")

    finally:
        try:
            client.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

        client.close()
        print("[*] Client closed.")


if __name__ == "__main__":
    main()
