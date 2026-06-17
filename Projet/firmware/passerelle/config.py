from machine import Pin, SoftSPI

WIFI_SSID = 'INSA_RiSF'
WIFI_PASSWORD = 'insa032023'

MQTT_SERVER = 'p-fb.net'
MQTT_PORT = 1883
MQTT_USER = 'insa'
MQTT_PASSWORD = 'insa'
MQTT_DATA_TOPIC = b'echange'
MQTT_COMMAND_TOPIC = b'echange/command/passerelle'

NODE_ID = 'passerelle1'
AES_KEY = b'0123456789abcdef'
HMAC_KEY = b'abcd'

device_config = {
    'miso': 19,
    'mosi': 27,
    'ss': 18,
    'sck': 5,
    'dio_0': 26,
    'reset': 14,
    'led': 25,
}

lora_parameters = {
    'frequency': 868E6,
    'tx_power_level': 2,
    'signal_bandwidth': 125E3,
    'spreading_factor': 11,
    'coding_rate': 5,
    'preamble_length': 8,
    'implicit_header': True,
    'sync_word': 0x12,
    'enable_CRC': True,
    'invert_IQ': False,
}
