import socket

from crypto import encrypt as encrypt_, decrypt as decrypt_


BUFFER_SIZE = 2 ** 15


class Sender:
    def __init__(self, connexion: socket.socket, encrypting_key=None, decrypting_key=None):
        self.encrypting_key = encrypting_key
        self.decrypting_key = decrypting_key
        self.connexion = connexion

    def send(self, message, encrypt=None):
        print("sending :", message)
        if encrypt is None:
            encrypt = self.encrypting_key is not None
        if encrypt:
            if not self.encrypting_key:
                raise RuntimeError("Cannot encrypt without an encrypting key")
            message = encrypt_(self.encrypting_key, message)
        self.connexion.sendall(message)

    def recv(self, decrypt=None) -> bytes:
        # todo : wait for AR
        if decrypt is None:
            decrypt = self.decrypting_key is not None
        message = self.connexion.recv(BUFFER_SIZE)
        print("receiving :", message)
        if decrypt:
            if not self.decrypting_key:
                raise RuntimeError("Cannot decrypt without an decrypting key")
            message = decrypt_(self.decrypting_key, message)
        print("decrypted :", message)
        return message
