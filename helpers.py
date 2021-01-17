import socket
import threading

from crypto import encrypt as encrypt_, decrypt as decrypt_


BUFFER_SIZE = 2 ** 15


class Sender:
    def __init__(self, connexion: socket.socket, encrypting_key=None, decrypting_key=None):
        self.encrypting_key = encrypting_key
        self.decrypting_key = decrypting_key
        self.connexion = connexion

    def send(self, message, wait_for_ar=True, decrypt_ar=None, encrypt=None, encrypting_key=None):
        print(f"{threading.current_thread().name} : sending : {message}")
        encrypting_key = encrypting_key or self.encrypting_key
        if encrypt is None:
            encrypt = encrypting_key is not None
        if encrypt:
            if not encrypting_key:
                raise RuntimeError("Cannot encrypt without an encrypting key")
            message = encrypt_(encrypting_key, message)
        self.connexion.sendall(message)
        if wait_for_ar:
            ar = self.recv(send_ar=False, decrypt=decrypt_ar)
            assert ar == ResponseCode.RECEIVED, f"Bad response code, expected {ResponseCode.RECEIVED}, got {ar}"

    def recv(self, send_ar=True, encrypt_ar=None, decrypt=None, decrypting_key=None) -> bytes:
        # todo : handle errors
        decrypting_key = decrypting_key or self.decrypting_key
        if decrypt is None:
            decrypt = decrypting_key is not None
        message = self.connexion.recv(BUFFER_SIZE)
        print(f"{threading.current_thread().name} : receiving : ", end='')
        if decrypt:
            if not decrypting_key:
                raise RuntimeError("Cannot decrypt without an decrypting key")
            try:
                message = decrypt_(decrypting_key, message)
            except ValueError:
                message = f'Error, could not decrypt : {message}'.encode()
        print(message)
        if send_ar:
            self.send(ResponseCode.RECEIVED, wait_for_ar=False, encrypt=encrypt_ar)
        return message


class ResponseCode:
    USERNAME_DOES_NOT_EXIST = b"0"
    USERNAME_ALREADY_EXISTS = b"1"
    ROOM_CREATED = b"2"
    RECEIVED = b"3"
