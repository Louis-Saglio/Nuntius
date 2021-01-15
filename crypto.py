from typing import Union

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding


class TextTooLongException(ValueError):
    pass


padding = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)


def decrypt(key: rsa.RSAPrivateKey, cypher_text: bytes) -> bytes:
    return key.decrypt(cypher_text, padding)


def encrypt(key: Union[rsa.RSAPrivateKey, rsa.RSAPublicKey], plaintext: bytes) -> bytes:
    max_message_size = get_max_message_size(key.key_size)
    plaintext_size = len(plaintext)
    if plaintext_size > max_message_size:
        raise TextTooLongException(f"Max size : {max_message_size}, got {plaintext_size}")
    return key.encrypt(plaintext, padding)


def load_public_key(serial_public_key: bytes) -> rsa.RSAPublicKey:
    return serialization.load_pem_public_key(serial_public_key, default_backend())


def generate_key_pair(size=2048, verbose=False) -> tuple[rsa.RSAPrivateKey, bytes, rsa.RSAPublicKey, bytes]:
    if verbose:
        print("generating key pair...")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=size, backend=default_backend())
    # noinspection PyTypeChecker
    serial_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_key = private_key.public_key()
    # noinspection PyTypeChecker
    serial_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    if verbose:
        print("key pair generated")
    return private_key, serial_private_key, public_key, serial_public_key


def get_max_message_size(key_size: int) -> int:
    assert key_size >= 1024
    for i in range(100):
        if 2 ** i == key_size:
            break
        elif 2 ** i > key_size:
            raise ValueError(f"{key_size} is not a power of two")
    initial_key_size = 1024
    initial_message_size = 62
    while True:
        if initial_key_size == key_size:
            return initial_message_size
        else:
            initial_key_size *= 2
            initial_message_size = initial_message_size * 2 + 66
