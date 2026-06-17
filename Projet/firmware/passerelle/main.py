import os
os.chdir("/passerelle")
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
no_check_mode = False


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
    # Initialisation du modem
    modem = SX127x(
        device_spi,
        pins=device_config,
        parameters=lora_parameters
    )
    # Force le modem en mode écoute LoRa dès le démarrage
    modem.receive()
    return modem


def connect_wifi():
    wlan = network.WLAN(network.STA_IF)
    
    # Nettoyage préventif de l'état interne de la puce Wi-Fi
    if wlan.active():
        wlan.active(False)
        sleep(0.5) 
    
    wlan.active(True)
    sleep(0.5) 

    if wlan.isconnected():
        print('WiFi connected')
        print(wlan.ifconfig())
        return True

    print('Connecting WiFi {}'.format(WIFI_SSID))
    
    try:
        wlan.connect(WIFI_SSID, WIFI_PASSWORD)
    except OSError as e:
        print("WiFi HW Error: {}. Retrying...".format(e))
        machine.reset() 

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
    lora.println(command_packet)
    lora.receive()


def on_mqtt_message(topic, msg):
    global AES_KEY
    global HMAC_KEY
    global no_check_mode

    # 1. On force le topic reçu à devenir une chaîne de caractères (str)
    actual_topic = topic.decode() if type(topic) == bytes else topic
    
    # 2. On force AUSSI le topic de configuration à devenir une chaîne (str)
    config_topic = MQTT_COMMAND_TOPIC.decode() if type(MQTT_COMMAND_TOPIC) == bytes else MQTT_COMMAND_TOPIC

    # 3. La comparaison se fait maintenant entre deux 'str' parfaits !
    if actual_topic != config_topic:
        return

    # Vérification de commande NOCHECK
    if msg.startswith(NOCHECK_PREFIX):
        ok, state = verify_nocheck_command(msg, HMAC_KEY)
        if ok:
            no_check_mode = state
            print("[MQTT] Mode no-check mis a jour:", no_check_mode)
            set_screen(['NO CHECK', 'ON' if state else 'OFF'])
            mqtt_client.publish(MQTT_DATA_TOPIC, b"nocheck_updated")
        else:
            print("[MQTT] Mode no-check refuse: HMAC invalide")
        return

    print("[MQTT] Ordre de Key Update reçu.")
    ok, new_aes_key, new_hmac_key = verify_key_update(msg, HMAC_KEY)

    if ok:
        AES_KEY = new_aes_key
        HMAC_KEY = new_hmac_key
        mqtt_client.publish(MQTT_DATA_TOPIC, b"keys_updated")
        if 'lora' in globals():
            send_key_update(msg)
            lora.receive()
        set_screen(['KEYS OK', NODE_ID, 'updated'])
        print("[REKEY] Cles mises a jour avec succes et relayees.")
    else:
        mqtt_client.publish(MQTT_DATA_TOPIC, b"keys_rejected")
        set_screen(['KEYS BAD', NODE_ID])
        
        print("[REKEY] Echec : HMAC invalide.")

def publish_lora_message(node_id, plaintext, rssi, snr, secure):
    # Si le message n'a pas pu être déchiffré (secure=False), plaintext est un objet bytes brut.
    # On le décode proprement ou on l'affiche sous forme safe pour éviter les crashs JSON.
    try:
        data_str = plaintext.decode() if type(plaintext) == bytes else str(plaintext)
    except Exception:
        data_str = str(plaintext)

    payload = ujson.dumps({
        'node': node_id,
        'data': data_str,
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
            packet = lora.read_payload() # C'est la chaîne Base64 du capteur
            rssi = lora.packet_rssi()
            snr = lora.packet_snr()
            mqtt_client.publish(MQTT_DATA_TOPIC, packet)
            
            if no_check_mode:
                screen[0] = 'RX RAW'
                screen[1] = packet[:16].decode() if type(packet) == bytes else packet[:16]
                screen[2] = 'RSSI {}'.format(rssi)
                screen[3] = 'SNR {}'.format(snr)
                screen[4] = 'NO-CHK'
            else:
                ok, node_id, plaintext = unpack_message(packet, AES_KEY, HMAC_KEY)
                if ok:
                    screen[0] = 'RX {}'.format(node_id)
                    screen[1] = plaintext.decode()[:16]
                    screen[2] = 'RSSI {}'.format(rssi)
                    screen[3] = 'SNR {}'.format(snr)
                    screen[4] = 'OK'
                else:
                    screen[0] = 'RX BAD'
                    screen[4] = 'HMAC ERR'
            write_screen(oled, screen)

            # CORRECTION C : Très important, on relance l'écoute du module LoRa
            lora.receive()

        sleep(0.1)


if __name__ == '__main__':
    run()


