from typing import Union

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding


padding = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)


def decrypt(key: Union[rsa.RSAPrivateKey, rsa.RSAPublicKey], cypher_text: bytes) -> bytes:
    return key.decrypt(cypher_text, padding)


def encrypt(key: Union[rsa.RSAPrivateKey, rsa.RSAPublicKey], plaintext: bytes) -> bytes:
    return key.encrypt(plaintext, padding)


def load_public_key(serial_public_key: bytes) -> rsa.RSAPublicKey:
    return serialization.load_pem_public_key(serial_public_key, default_backend())


def generate_key_pair() -> tuple[rsa.RSAPrivateKey, bytes, rsa.RSAPublicKey, bytes]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
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
    return private_key, serial_private_key, public_key, serial_public_key
