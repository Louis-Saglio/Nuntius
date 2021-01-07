import random
import socket
import string
import threading
from enum import Enum

threads = []
users: dict[bytes, bytes] = {}
tokens: dict[bytes, bytes] = {}


class Action(Enum):
    SIGNUP = b'0'
    SIGNIN = b'1'


class ErrorCode(Enum):
    AUTHENTICATION_FAILED = b'0'


def listen(ip: str, port: int):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind((ip, port))
        server.listen(5)
        while True:
            connexion_to_client, (ip, port) = server.accept()
            thread = threading.Thread(target=handle_client, args=(connexion_to_client,), name=f'{ip}:{port}')
            threads.append(thread)
            thread.start()


def handle_client(connexion_to_client: socket.socket):
    # todo : hash messages
    # todo : encrypt all messages
    authenticate(connexion_to_client)
    connexion_to_client.close()


def authenticate(connexion_to_client: socket.socket):
    response = b''
    while response == ErrorCode.AUTHENTICATION_FAILED:
        message = connexion_to_client.recv(1024)
        print(message)
        action, username, password = message.split(b',')
        if action == Action.SIGNUP:
            if username not in users:
                users[username] = password
        if users.get(username) == password:
            token = ''.join(random.choices(string.ascii_letters, k=64)).encode()
            tokens[token] = username
            response = token
        else:
            response = ErrorCode.AUTHENTICATION_FAILED
        connexion_to_client.sendall(response)
