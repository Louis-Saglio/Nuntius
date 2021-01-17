import socket
import threading
from queue import SimpleQueue
from typing import Iterable

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPrivateKey

from crypto import generate_key_pair, load_public_key
from helpers import Sender, BUFFER_SIZE, ResponseCode

# todo : stop using global variables

public_key_by_username: dict[bytes, tuple[RSAPublicKey, bytes]] = {}
rooms_messages: dict[frozenset[bytes], dict[bytes, SimpleQueue[tuple[bytes, bytes]]]] = {}


def listen(ip: str, port: int):
    private_key, serial_private_key, public_key, serial_public_key = generate_key_pair(4096, verbose=True)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind((ip, port))
        server.listen(5)
        print(f"listening on {ip}:{port}")
        while True:
            connexion_to_client, (ip, port) = server.accept()
            threading.Thread(
                target=handle_client,
                args=(connexion_to_client, private_key, serial_public_key),
                name=f"{ip}:{port} handler",
            ).start()


def handle_client(connexion_to_client: socket.socket, private_key: RSAPrivateKey, serial_public_key: bytes):
    username, client_public_key = authenticate(connexion_to_client, serial_public_key)
    sender = Sender(connexion_to_client, client_public_key, private_key)
    recipients = sender.recv(send_ar=False).split(b",")
    recipients_set = set(recipients)
    existing_users = set(public_key_by_username.keys())
    if not recipients_set.issubset(existing_users):
        sender.send(b",".join(recipients_set.difference(existing_users)))
    else:
        sender.send(ResponseCode.ROOM_CREATED)
        for recipient in recipients:
            sender.send(public_key_by_username[recipient][1], encrypt=False)
        recipients = frozenset(recipients + [username])
        if recipients not in rooms_messages:
            rooms_messages[recipients] = {recipient: SimpleQueue() for recipient in recipients}
        threads = [
            threading.Thread(
                target=broadcast_client_messages,
                args=[sender, rooms_messages[recipients].values(), username],
                name=f"messages of {username.decode()} broadcaster",
            ),
            threading.Thread(
                target=send_messages_to_client,
                args=[sender, rooms_messages[recipients][username]],
                name=f"to {username.decode()} message sender",
            ),
        ]
        [thread.start() for thread in threads]
        [thread.join() for thread in threads]


def authenticate(connexion_to_client: socket.socket, serial_public_key) -> tuple[bytes, RSAPublicKey]:
    response = b""
    while response != serial_public_key:
        message = connexion_to_client.recv(BUFFER_SIZE)
        if message.count(b"\n") == 0:
            username = message
            if username in public_key_by_username:
                response = serial_public_key
            else:
                response = ResponseCode.USERNAME_DOES_NOT_EXIST
        else:
            if message not in public_key_by_username:
                username, *user_public_key_rows = message.split(b"\n")
                serial_user_public_key = b"\n".join(user_public_key_rows)
                user_public_key = load_public_key(serial_user_public_key)
                public_key_by_username[username] = (user_public_key, serial_user_public_key)
                response = serial_public_key
            else:
                response = ResponseCode.USERNAME_ALREADY_EXISTS
        connexion_to_client.sendall(response)
    # noinspection PyUnboundLocalVariable
    return username, user_public_key


def broadcast_client_messages(sender: Sender, queues: Iterable[SimpleQueue[tuple[bytes, bytes]]], username: bytes):
    # todo : hash messages
    while True:
        for queue in queues:
            message = sender.recv(decrypt=False)
            queue.put((username, message))


def send_messages_to_client(sender: Sender, queue: SimpleQueue[tuple[bytes, bytes]]):
    while True:
        username, message = queue.get()
        sender.send(username)
        sender.send(message, encrypt=False)


if __name__ == "__main__":
    listen("127.0.0.1", 8887)
