#!/usr/bin/env python3

import argparse
import base64
import hashlib
import hmac
import json
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import paho.mqtt.client as mqtt


BLOCK_SIZE = 16
MESSAGE_PREFIX = b'INSARISF1'
KEYUPDATE_PREFIX = b'KEYUPDATE'
DEFAULT_BROKER = 'p-fb.net'
DEFAULT_PORT = 1883
DEFAULT_USER = 'insa'
DEFAULT_PASSWORD = 'insa'
DEFAULT_DATA_TOPIC = 'insa/lora/data'
DEFAULT_COMMAND_TOPIC = 'insa/lora/command/passerelle'
DEFAULT_AES_KEY = b'0123456789abcdef'
DEFAULT_HMAC_KEY = b'abcd'


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


def make_mqtt_client(args):
    try:
        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id='linux-lora-client')
    except AttributeError:
        client = mqtt.Client(client_id='linux-lora-client')
    client.username_pw_set(args.mqtt_user, args.mqtt_password)
    client.connect(args.broker, args.port, 60)
    return client


def on_message(client, userdata, message, args):
    valid, node_id, plaintext = unpack_message(message.payload, args.aes_key, args.hmac_key)

    if valid:
        data = plaintext.decode()
        print('[OK] {} {}'.format(node_id, data))
    else:
        print('[BAD] message rejected')


def listen(args):
    client = make_mqtt_client(args)
    client.subscribe(args.data_topic)
    client.on_message = lambda client, userdata, message: on_message(client, userdata, message, args)
    print('Listening on {} topic {}'.format(args.broker, args.data_topic))
    client.loop_forever()


def update_keys(args):
    command = build_key_update(args.new_aes_key, args.new_hmac_key, args.current_hmac_key)
    client = make_mqtt_client(args)
    info = client.publish(args.command_topic, command)
    info.wait_for_publish()
    client.disconnect()
    print('Published secure key update on {}'.format(args.command_topic))


def parse_bytes(value):
    return value.encode()


def build_arg_parser():
    parser = argparse.ArgumentParser(description='Client Linux MQTT/LoRa sécurisé')
    parser.add_argument('--broker', default=DEFAULT_BROKER)
    parser.add_argument('--port', type=int, default=DEFAULT_PORT)
    parser.add_argument('--mqtt-user', default=DEFAULT_USER)
    parser.add_argument('--mqtt-password', default=DEFAULT_PASSWORD)
    parser.add_argument('--data-topic', default=DEFAULT_DATA_TOPIC)
    parser.add_argument('--command-topic', default=DEFAULT_COMMAND_TOPIC)
    parser.add_argument('--aes-key', type=parse_bytes, default=DEFAULT_AES_KEY)
    parser.add_argument('--hmac-key', type=parse_bytes, default=DEFAULT_HMAC_KEY)

    subparsers = parser.add_subparsers(dest='command', required=True)

    listen_parser = subparsers.add_parser('listen', help='écouter et vérifier les messages LoRa publiés en MQTT')
    listen_parser.set_defaults(func=listen)

    update_parser = subparsers.add_parser('update-keys', help='mettre à jour les clés de la passerelle et du capteur')
    update_parser.add_argument('--new-aes-key', type=parse_bytes, default=b'0123456789abcdef')
    update_parser.add_argument('--new-hmac-key', type=parse_bytes, default=b'abcd')
    update_parser.add_argument('--current-hmac-key', type=parse_bytes, default=DEFAULT_HMAC_KEY)
    update_parser.set_defaults(func=update_keys)

    return parser


def main():
    parser = build_arg_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == '__main__':
    main()
