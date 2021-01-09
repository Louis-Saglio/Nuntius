from crypto import encrypt, decrypt


BUFFER_SIZE = 2 ** 15


class Sender:
    def __init__(self, client_public_key, server_private_key, connexion):
        self.client_public_key = client_public_key
        self.server_private_key = server_private_key
        self.connexion = connexion

    def send(self, message):
        self.connexion.sendall(encrypt(self.client_public_key, message))

    def recv(self) -> bytes:
        return decrypt(self.server_private_key, self.connexion.recv(BUFFER_SIZE))
