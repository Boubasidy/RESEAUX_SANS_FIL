import base64
import hashlib
import hmac
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from config import BLOCK_SIZE, MESSAGE_PREFIX, KEYUPDATE_PREFIX


def pad(data):
    padding = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([padding]) * padding


def unpad(data):
    if not data:
        return data
    padding = data[-1]
    if padding < 1 or padding > BLOCK_SIZE:
        raise ValueError('bad padding')
    return data[:-padding]


def hmac_sha1(key, message):
    return hmac.new(key, message, hashlib.sha1).digest()


def equal_bytes(a, b):
    return hmac.compare_digest(a, b)


def encrypt_aes_cbc(key, plaintext):
    nonce = os.urandom(BLOCK_SIZE)
    cipher = Cipher(algorithms.AES(key), modes.CBC(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(pad(plaintext)) + encryptor.finalize()
    return nonce + ciphertext


def decrypt_aes_cbc(key, data):
    nonce = data[:BLOCK_SIZE]
    ciphertext = data[BLOCK_SIZE:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(nonce), backend=default_backend())
    decryptor = cipher.decryptor()
    return unpad(decryptor.update(ciphertext) + decryptor.finalize())


def pack_message(node_id, plaintext, aes_key, hmac_key):
    encrypted = encrypt_aes_cbc(aes_key, plaintext)
    mac_data = MESSAGE_PREFIX + b'|' + node_id.encode() + b'|' + encrypted
    mac = hmac_sha1(hmac_key, mac_data)
    packet = node_id.encode() + b'|' + encrypted + b'|' + mac
    return base64.b64encode(packet).decode()


def unpack_message(packet, aes_key, hmac_key):
    try:
        raw = base64.b64decode(packet)
        node_id_bytes, rest = raw.split(b'|', 1)
        node_id = node_id_bytes.decode()
        encrypted, mac = rest.rsplit(b'|', 1)
        mac_data = MESSAGE_PREFIX + b'|' + node_id_bytes + b'|' + encrypted
        expected = hmac_sha1(hmac_key, mac_data)
        if not equal_bytes(mac, expected):
            return False, node_id, b''
        plaintext = decrypt_aes_cbc(aes_key, encrypted)
        return True, node_id, plaintext
    except Exception:
        return False, '', b''


def build_key_update(new_aes_key, new_hmac_key, current_hmac_key):
    nonce = os.urandom(8)
    command = KEYUPDATE_PREFIX + b'|' + nonce + b'|' + new_aes_key.hex().encode() + b'|' + new_hmac_key.hex().encode()
    mac = hmac_sha1(current_hmac_key, command)
    return command + b'|' + mac.hex().encode()


def verify_key_update(command_packet, current_hmac_key):
    try:
        command, mac = command_packet.rsplit(b'|', 1)
        expected = hmac_sha1(current_hmac_key, command)
        if not equal_bytes(mac, expected):
            return False, b'', b''
        parts = command.split(b'|')
        if len(parts) != 4 or parts[0] != KEYUPDATE_PREFIX:
            return False, b'', b''
        return True, bytes.fromhex(parts[2].decode()), bytes.fromhex(parts[3].decode())
    except Exception:
        return False, b'', b''