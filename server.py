
import json
import re
import socket
import struct
import threading

HOST = "127.0.0.1"
PORT = 5000
MAX_PACKET_SIZE = 1_000_000

clients = {}
clients_lock = threading.Lock()


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


def broadcast_json(data, exclude=None):
    payload = json.dumps(data).encode("utf-8")

    with clients_lock:
        recipients = [
            client for client in clients
            if client is not exclude
        ]

    for client in recipients:
        try:
            send_packet(client, b"J", payload)
        except OSError:
            try:
                client.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                client.close()
            except OSError:
                pass


def broadcast_encrypted(packet, sender):
    with clients_lock:
        recipients = [
            client for client in clients
            if client is not sender
        ]

    for client in recipients:
        try:
            send_packet(client, b"E", packet)
        except OSError:
            try:
                client.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                client.close()
            except OSError:
                pass


def valid_username(username):
    return (
        isinstance(username, str)
        and re.fullmatch(r"[A-Za-z0-9_-]{3,20}", username)
        is not None
    )


def handle_client(client, address):
    username = None

    try:
        first_packet = receive_packet(client)

        if first_packet is None or first_packet[0] != b"J":
            return

        request = json.loads(first_packet[1].decode("utf-8"))
        username = request.get("username")

        if not valid_username(username):
            send_json(
                client,
                {
                    "type": "error",
                    "message": (
                        "Username must be 3-20 characters: "
                        "letters, numbers, _ or -."
                    ),
                },
            )
            return

        with clients_lock:
            name_taken = any(
                name.casefold() == username.casefold()
                for name in clients.values()
            )

            if not name_taken:
                clients[client] = username

        if name_taken:
            send_json(
                client,
                {
                    "type": "error",
                    "message": "This username is already in use.",
                },
            )
            return

        send_json(
            client,
            {
                "type": "welcome",
                "username": username,
            },
        )

        print(f"[+] {username} connected from {address}")

        broadcast_json(
            {
                "type": "system",
                "message": f"{username} joined the chat.",
            },
            exclude=client,
        )

        while True:
            packet = receive_packet(client)

            if packet is None:
                break

            kind, payload = packet

            # Only encrypted chat messages are accepted after login.
            if kind != b"E":
                raise ValueError("Unexpected packet type.")

            print(
                f"[Encrypted data] {username}: "
                f"{len(payload)} bytes received"
            )

            # The server forwards ciphertext without decrypting it.
            broadcast_encrypted(payload, client)

    except (
        OSError,
        ValueError,
        json.JSONDecodeError,
        UnicodeDecodeError,
        AttributeError,
    ) as error:
        print(f"[!] Client error from {address}: {error}")

    finally:
        was_logged_in = False

        with clients_lock:
            if client in clients:
                del clients[client]
                was_logged_in = True

        try:
            client.close()
        except OSError:
            pass

        if was_logged_in:
            print(f"[-] {username} disconnected")

            broadcast_json(
                {
                    "type": "system",
                    "message": f"{username} left the chat.",
                }
            )


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server.bind((HOST, PORT))
        server.listen()

        print(f"[*] Encrypted chat server: {HOST}:{PORT}")
        print("[*] Waiting for clients...")

        while True:
            client, address = server.accept()

            thread = threading.Thread(
                target=handle_client,
                args=(client, address),
                daemon=True,
            )
            thread.start()

    except KeyboardInterrupt:
        print("\n[*] Server shutting down.")

    finally:
        with clients_lock:
            active_clients = list(clients)
            clients.clear()

        for client in active_clients:
            try:
                client.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                client.close()
            except OSError:
                pass

        server.close()


if __name__ == "__main__":
    main()
