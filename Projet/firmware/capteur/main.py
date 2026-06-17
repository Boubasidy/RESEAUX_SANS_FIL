from machine import Pin, SoftSPI
from time import sleep
import machine
import ujson

from config import *
from security import *
from sx127x import SX127x
from oled import *


def init_lora():
    device_spi = SoftSPI(
        baudrate=10000000,
        polarity=0,
        phase=0,
        bits=8,
        firstbit=SoftSPI.MSB,
        sck=Pin(device_config['sck'], Pin.OUT, Pin.PULL_DOWN),
        mosi=Pin(device_config['mosi'], Pin.OUT, Pin.PULL_UP),
        miso=Pin(device_config['miso'], Pin.IN, Pin.PULL_UP)
    )
    return SX127x(
        device_spi,
        pins=device_config,
        parameters=lora_parameters
    )


def build_payload(counter):
    value = 20.0 + counter * 0.5
    return ujson.dumps({
        'node': NODE_ID,
        'type': 'sensor',
        'counter': counter,
        'temperature': value,
        'battery': 90 - counter
    })


def listen_key_update(lora, oled, screen):
    global AES_KEY
    global HMAC_KEY

    lora.receive()
    sleep(1)

    if not lora.received_packet():
        return False

    packet = lora.read_payload()
    ok, new_aes_key, new_hmac_key = verify_key_update(packet, HMAC_KEY)

    if ok:
        AES_KEY = new_aes_key
        HMAC_KEY = new_hmac_key
        screen[0] = 'KEYS OK'
        screen[1] = NODE_ID
        screen[2] = 'updated'
        write_screen(oled, screen)
        return True

    screen[0] = 'KEYS BAD'
    screen[1] = NODE_ID
    write_screen(oled, screen)
    return False


def run():
    global AES_KEY
    global HMAC_KEY

    lora = init_lora()
    oled, screen = init_oled()
    counter = 0

    screen[0] = 'LoRa capteur'
    screen[1] = NODE_ID
    screen[2] = 'AES+HMAC'
    write_screen(oled, screen)

    while True:
        counter += 1
        payload = build_payload(counter)
        packet = pack_message(NODE_ID, payload.encode(), AES_KEY, HMAC_KEY)

        lora.println(packet)

        screen[0] = 'TX {}'.format(NODE_ID)
        screen[1] = packet[:21]
        screen[2] = 'counter {}'.format(counter)
        write_screen(oled, screen)

        listen_key_update(lora, oled, screen)
        sleep(5)


if __name__ == '__main__':
    run()
