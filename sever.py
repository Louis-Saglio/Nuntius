import socket
import threading
from collections import deque

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from crypto import generate_key_pair, encrypt, decrypt, load_public_key
from helpers import Sender, BUFFER_SIZE

private_key, serial_private_key, public_key, serial_public_key = generate_key_pair()

public_key_by_username: dict[bytes, tuple[RSAPublicKey, bytes]] = {}
rooms_messages: dict[frozenset[bytes], dict[bytes, bytes]] = {}


class ResponseCode:
    USERNAME_DOES_NOT_EXIST = b"0"
    USERNAME_ALREADY_EXISTS = b"1"
    ROOM_CREATED = b"2"


def listen(ip: str, port: int):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind((ip, port))
        server.listen(5)
        while True:
            connexion_to_client, (ip, port) = server.accept()
            threading.Thread(target=handle_client, args=(connexion_to_client,), name=f"{ip}:{port}").start()


def handle_client(connexion_to_client: socket.socket):
    username, client_public_key = authenticate(connexion_to_client)
    sender = Sender(client_public_key, private_key, connexion_to_client)
    recipients = sender.recv().split(b",")
    recipients_set = set(recipients)
    existing_users = set(public_key_by_username.keys())
    if not recipients_set.issubset(existing_users):
        sender.send(b','.join(recipients_set.difference(existing_users)))
    else:
        sender.send(ResponseCode.ROOM_CREATED)
        for recipient in recipients:
            sender.send(public_key_by_username[recipient][1])
        recipients = frozenset(recipients + [username])
        if recipients not in rooms_messages:
            rooms_messages[recipients] = {recipient: deque() for recipient in recipients}
        threads = [
            threading.Thread(
                target=broadcast_client_messages, args=[connexion_to_client, rooms_messages[recipients], username]
            ),
            threading.Thread(
                target=send_messages_to_client,
                args=[connexion_to_client, rooms_messages[recipients][username], client_public_key],
            ),
        ]
        [thread.start() for thread in threads]
        [thread.join() for thread in threads]


def authenticate(connexion_to_client: socket.socket) -> tuple[bytes, RSAPublicKey]:
    response = b""
    while response != serial_public_key:
        message = connexion_to_client.recv(BUFFER_SIZE)
        print("authenticate :", message)
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
                # todo : encrypt
                response = serial_public_key
            else:
                response = ResponseCode.USERNAME_ALREADY_EXISTS
        connexion_to_client.sendall(response)
    # noinspection PyUnboundLocalVariable
    return username, user_public_key


def broadcast_client_messages(connexion_to_client: socket.socket, queues: list[deque[bytes]], username: bytes):
    # todo : hash messages
    while True:
        for queue in queues:
            message = connexion_to_client.recv(BUFFER_SIZE)
            queue.append(encrypt(public_key_by_username[username][0], b"\n".join((username, message))))


def send_messages_to_client(connexion_to_client: socket.socket, queue: deque[bytes]):
    while True:
        message = queue.pop()
        connexion_to_client.sendall(message)


if __name__ == "__main__":
    listen("127.0.0.1", 8889)
