#!/usr/bin/env python3

import argparse
import paho.mqtt.client as mqtt

from config import (
    DEFAULT_BROKER, DEFAULT_PORT, DEFAULT_USER, DEFAULT_PASSWORD,
    DEFAULT_DATA_TOPIC, DEFAULT_COMMAND_TOPIC, DEFAULT_AES_KEY, DEFAULT_HMAC_KEY
)
from security import unpack_message
from shell import MqttShell, print_async


def make_mqtt_client(args):
    try:
        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION1, client_id='linux-lora-client')
    except AttributeError:
        client = mqtt.Client(client_id='linux-lora-client')
    client.username_pw_set(args.mqtt_user, args.mqtt_password)
    client.connect(args.broker, args.port, 60)
    return client


def on_message(client, userdata, message, args, shell=None):
    try:
        raw_payload = message.payload.decode()
    except Exception:
        raw_payload = message.payload.hex()
    
    out = f'\n[MQTT raw] {raw_payload}'

    valid, node_id, plaintext = unpack_message(message.payload, args.aes_key, args.hmac_key)

    if valid:
        data = plaintext.decode()
        out += f'\n[OK] {node_id} {data}'
    else:
        out += f'\n[BAD] message rejected\nraw: {raw_payload}'
        
    if shell:
        print_async(out, shell)
    else:
        print(out)


def parse_bytes(value):
    return value.encode()


def main():
    parser = argparse.ArgumentParser(description='Client Linux MQTT/LoRa sécurisé interactif')
    parser.add_argument('--broker', default=DEFAULT_BROKER)
    parser.add_argument('--port', type=int, default=DEFAULT_PORT)
    parser.add_argument('--mqtt-user', default=DEFAULT_USER)
    parser.add_argument('--mqtt-password', default=DEFAULT_PASSWORD)
    parser.add_argument('--data-topic', default=DEFAULT_DATA_TOPIC)
    parser.add_argument('--command-topic', default=DEFAULT_COMMAND_TOPIC)
    parser.add_argument('--aes-key', type=parse_bytes, default=DEFAULT_AES_KEY)
    parser.add_argument('--hmac-key', type=parse_bytes, default=DEFAULT_HMAC_KEY)

    args = parser.parse_args()

    client = make_mqtt_client(args)
    shell = MqttShell(args, client)
    
    client.on_message = lambda client, userdata, message: on_message(client, userdata, message, args, shell)
    
    # Démarrer la boucle MQTT en arrière-plan
    client.loop_start()

    try:
        shell.cmdloop()
    except KeyboardInterrupt:
        print("\nInterruption clavier...")
    finally:
        client.loop_stop()
        client.disconnect()


if __name__ == '__main__':
    main()