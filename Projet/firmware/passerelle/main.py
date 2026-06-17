from machine import Pin, SoftSPI
from time import sleep
import machine
import network
import ubinascii
import ujson

from config import *
from security import *
from sx127x import SX127x
from oled import *
from umqttsimple import MQTTClient


mqtt_client = None


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


def connect_wifi():
    wlan = network.WLAN(network.STA_IF)
    wlan.active(True)

    if wlan.isconnected():
        print('WiFi connected')
        print(wlan.ifconfig())
        return True

    print('Connecting WiFi {}'.format(WIFI_SSID))
    wlan.connect(WIFI_SSID, WIFI_PASSWORD)

    for _ in range(30):
        if wlan.isconnected():
            print('WiFi connected')
            print(wlan.ifconfig())
            return True
        sleep(1)

    print('WiFi connection failed')
    return False


def connect_mqtt():
    global mqtt_client

    client_id = ubinascii.hexlify(machine.unique_id())
    mqtt_client = MQTTClient(
        client_id=client_id,
        server=MQTT_SERVER,
        port=MQTT_PORT,
        user=MQTT_USER,
        password=MQTT_PASSWORD
    )
    mqtt_client.set_callback(on_mqtt_message)
    mqtt_client.connect()
    mqtt_client.subscribe(MQTT_COMMAND_TOPIC)
    print('Connected to MQTT {}'.format(MQTT_SERVER))
    return mqtt_client


def publish_status(topic, event, ok, detail=''):
    payload = ujson.dumps({
        'node': NODE_ID,
        'event': event,
        'ok': ok,
        'detail': detail
    })
    mqtt_client.publish(topic, payload)


def set_screen(lines):
    if 'screen' not in globals() or 'oled' not in globals():
        return
    for index, line in enumerate(lines):
        screen[index] = line
    write_screen(oled, screen)


def send_key_update(command_packet):
    lora.println(command_packet.decode())


def on_mqtt_message(topic, msg):
    global AES_KEY
    global HMAC_KEY

    if topic != MQTT_COMMAND_TOPIC:
        return

    ok, new_aes_key, new_hmac_key = verify_key_update(msg, HMAC_KEY)

    if ok:
        AES_KEY = new_aes_key
        HMAC_KEY = new_hmac_key
        publish_status(MQTT_DATA_TOPIC, 'keys_updated', True)
        if 'lora' in globals():
            send_key_update(msg)
        set_screen(['KEYS OK', NODE_ID, 'updated'])
    else:
        publish_status(MQTT_DATA_TOPIC, 'keys_rejected', False)
        set_screen(['KEYS BAD', NODE_ID])


def publish_lora_message(node_id, plaintext, rssi, snr, secure):
    payload = ujson.dumps({
        'node': node_id,
        'data': plaintext.decode(),
        'rssi': rssi,
        'snr': snr,
        'secure': secure
    })
    mqtt_client.publish(MQTT_DATA_TOPIC, payload)


def run():
    global lora
    global oled
    global screen

    if not connect_wifi():
        return

    connect_mqtt()

    lora = init_lora()
    oled, screen = init_oled()

    screen[0] = 'Passerelle'
    screen[1] = NODE_ID
    screen[2] = 'MQTT + LoRa'
    write_screen(oled, screen)

    while True:
        try:
            mqtt_client.check_msg()
        except OSError:
            connect_mqtt()

        if lora.received_packet():
            packet = lora.read_payload()
            rssi = lora.packet_rssi()
            snr = lora.packet_snr()
            ok, node_id, plaintext = unpack_message(packet, AES_KEY, HMAC_KEY)

            if ok:
                publish_lora_message(node_id, plaintext, rssi, snr, True)
                screen[0] = 'RX {}'.format(node_id)
                screen[1] = plaintext.decode()[:16]
                screen[2] = 'RSSI {}'.format(rssi)
                screen[3] = 'SNR {}'.format(snr)
                screen[4] = 'OK'
            else:
                publish_lora_message(node_id, packet, rssi, snr, False)
                screen[0] = 'RX BAD'
                screen[1] = packet.decode()[:16]
                screen[2] = 'RSSI {}'.format(rssi)
                screen[3] = 'SNR {}'.format(snr)
                screen[4] = 'HMAC'

            write_screen(oled, screen)

        sleep(0.2)


if __name__ == '__main__':
    run()
