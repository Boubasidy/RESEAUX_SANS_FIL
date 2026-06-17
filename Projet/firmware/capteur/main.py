import os
import sys
os.chdir("/capteur")
from machine import Pin, SoftSPI
from time import sleep, ticks_ms, ticks_diff
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
        'battery': max(0, 90 - counter)
    })


def listen_key_update(lora, oled, screen, timeout_ms=2000):
    global AES_KEY
    global HMAC_KEY

    # Passage explicite en mode réception active
    lora.receive()
    
    start_time = ticks_ms()
    packet_detected = False

    # Attente active non-bloquante du paquet (évite le sleep brut)
    while ticks_diff(ticks_ms(), start_time) < timeout_ms:
        if lora.received_packet():
            print("Msg recu")
            packet_detected = True
            break
        sleep(0.05)

    if not packet_detected:
        # Forcer le retour au mode veille/standard pour pouvoir émettre au prochain coup
        lora.sleep() 
        return False

    # Lecture du paquet de mise à jour des clés
    packet = lora.read_payload()
    
    # Sécurité : vérification de la signature HMAC du paquet d'update
    ok, new_aes_key, new_hmac_key = verify_key_update(packet, HMAC_KEY)

    if ok:
        AES_KEY = new_aes_key
        HMAC_KEY = new_hmac_key
        
        # Optionnel mais recommandé : Sauvegarder les clés en mémoire flash (config.json) 
        # pour éviter de les perdre lors d'un reboot de l'ESP32.
        
        screen[0] = 'KEYS OK'
        screen[1] = NODE_ID
        screen[2] = 'updated'
        write_screen(oled, screen)
        lora.sleep()
        return True
    
    # Si un paquet est reçu mais invalide (mauvais HMAC, attaque par rejeu...)
    screen[0] = 'KEYS BAD'
    screen[1] = NODE_ID
    screen[2] = 'Rejected!'
    write_screen(oled, screen)
    lora.sleep()
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
    sleep(2)

    while True:
        counter += 1
        payload = build_payload(counter)
        
        # Chiffrement AES-CBC + Signature HMAC-SHA1 + Encodage Base64
        packet = pack_message(NODE_ID, payload.encode(), AES_KEY, HMAC_KEY)

        # Envoi de la trame Base64 via LoRa
        lora.println(packet)
        print("[TX] Paquet envoyé : {}".format(packet[:30] + "..."))

        # Mise à jour de l'affichage OLED
        screen[0] = 'TX {}'.format(NODE_ID)
        screen[1] = packet[:16] # Affiche les 16 premiers caractères du Base64
        screen[2] = 'counter {}'.format(counter)
        write_screen(oled, screen)

        # Fenêtre d'écoute des clés (2 secondes d'ouverture)
        print("Enter listening")
        listen_key_update(lora, oled, screen, timeout_ms=5000)
        
        # Intervalle de repos avant la prochaine mesure (5 secondes)
        sleep(1)


if __name__ == '__main__':
    run()
