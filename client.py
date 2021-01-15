import socket
import threading
import time

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from crypto import generate_key_pair, load_public_key, encrypt, decrypt
from helpers import Sender
from sever import ResponseCode, BUFFER_SIZE

private_key, serial_private_key, public_key, serial_public_key = generate_key_pair(4096, verbose=True)


class AuthenticationError(Exception):
    pass


class Signal:
    KEEP_RUNNING = True


def authenticate(connexion_to_server: socket.socket) -> RSAPublicKey:
    username = input("username ?> ")
    payload = b"\n".join([username.encode(), serial_public_key])
    connexion_to_server.sendall(payload)
    response = connexion_to_server.recv(BUFFER_SIZE)
    if response == ResponseCode.USERNAME_ALREADY_EXISTS:
        raise AuthenticationError(f"The username {username} is already taken")
    elif response == ResponseCode.USERNAME_DOES_NOT_EXIST:
        raise AuthenticationError("This username does not exist. Add your public key to the payload to create it.")
    else:
        return load_public_key(response)


def send_messages(connexion_to_server: socket.socket, recipients: dict[bytes, RSAPublicKey]):
    while Signal.KEEP_RUNNING:
        message = input("Say something >>> ").encode()
        for recipient, key in recipients.items():
            connexion_to_server.sendall(encrypt(key, message))


def listen_messages(sender: Sender):
    while Signal.KEEP_RUNNING:
        username = sender.recv()
        sender.send(ResponseCode.RECEIVED)
        message = sender.recv().decode()
        sender.send(ResponseCode.RECEIVED)
        print(f"{username} said : {message}")


def main(ip, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
        sender = Sender(client, decrypting_key=private_key)
        client.connect((ip, port))
        try:
            server_public_key = authenticate(client)
        except AuthenticationError as e:
            print(e)
        else:
            sender.encrypting_key = server_public_key
            recipients = []
            while True:
                recipient = input("Input a recipient name (type exit when you are done) >>> ")
                if recipient == "exit":
                    break
                recipients.append(recipient)
            sender.send(",".join(recipients).encode())
            response = sender.recv()
            sender.send(ResponseCode.RECEIVED)
            if response != ResponseCode.ROOM_CREATED:
                print(f"These users {response.decode().split(',')} don't exist")
                # todo : inform server
            else:
                recipients_public_keys = {}
                for recipient in recipients:
                    recipients_public_keys[recipient] = load_public_key(sender.recv(decrypt=False))
                    sender.send(ResponseCode.RECEIVED)
                threads = [
                    threading.Thread(target=send_messages, args=[client, recipients_public_keys]),
                    threading.Thread(target=listen_messages, args=[sender]),
                ]
                [thread.start() for thread in threads]
                while True:
                    try:
                        time.sleep(1)
                    except KeyboardInterrupt:
                        Signal.KEEP_RUNNING = False
                        [thread.join() for thread in threads]


if __name__ == "__main__":
    main("127.0.0.1", 8889)
