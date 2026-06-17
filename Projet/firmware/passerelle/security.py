import uhashlib
import ubinascii

try:
    from ucryptolib import aes
except ImportError:
    aes = None

try:
    import uos
except ImportError:
    uos = None

SHA1 = uhashlib.sha1
AES_CBC = 2
BLOCK_SIZE = 16
MESSAGE_PREFIX = b'INSARISF1'
KEYUPDATE_PREFIX = b'KEYUPDATE'


def random_bytes(size):
    if uos:
        return uos.urandom(size)
    return b'\0' * size


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
    SHA1_BLOCK_SIZE = 64
    key_block = key + (b'\0' * (SHA1_BLOCK_SIZE - len(key)))
    key_inner = bytes((x ^ 0x36) for x in key_block)
    key_outer = bytes((x ^ 0x5C) for x in key_block)
    return SHA1(key_outer + SHA1(key_inner + message).digest()).digest()


def equal_bytes(a, b):
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0


def encrypt_aes_cbc(key, plaintext):
    nonce = random_bytes(BLOCK_SIZE)
    cipher = aes(key, AES_CBC, nonce)
    ciphertext = cipher.encrypt(pad(plaintext))
    return nonce + ciphertext


def decrypt_aes_cbc(key, data):
    nonce = data[:BLOCK_SIZE]
    ciphertext = data[BLOCK_SIZE:]
    try:
        # Mode 3 est souvent AES_DECRYPT_CBC dans ucryptolib
        cipher = aes(key, 3, nonce) 
    except ValueError:
        # Si votre firmware utilise le mode 2 pour les deux actions
        cipher = aes(key, AES_CBC, nonce)        
    return unpad(cipher.decrypt(ciphertext))


def b64encode(data):
    return ubinascii.b2a_base64(data).strip().decode()


def b64decode(data):
    return ubinascii.a2b_base64(data)


def pack_message(node_id, plaintext, aes_key, hmac_key):
    encrypted = encrypt_aes_cbc(aes_key, plaintext)
    mac_data = MESSAGE_PREFIX + b'|' + node_id.encode() + b'|' + encrypted
    mac = hmac_sha1(hmac_key, mac_data)
    packet = node_id.encode() + b'|' + encrypted + b'|' + mac
    return b64encode(packet)


def unpack_message(packet, aes_key, hmac_key):
    try:
        raw = b64decode(packet)
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
    nonce = random_bytes(8)
    command = KEYUPDATE_PREFIX + b'|' + nonce + b'|' + ubinascii.hexlify(new_aes_key) + b'|' + ubinascii.hexlify(new_hmac_key)
    mac = hmac_sha1(current_hmac_key, command)
    return command + b'|' + ubinascii.hexlify(mac)


def verify_key_update(command_packet, current_hmac_key):
    try:
        # Séparation de la commande et du HMAC textuel hex
        command, mac_hex = command_packet.rsplit(b'|', 1)
        
        # 1. Calcul du HMAC attendu (octets bruts)
        expected = hmac_sha1(current_hmac_key, command)
        
        # 2. CORRECTION : unhexlify convertit le texte HEX en octets bruts sous MicroPython
        received_bytes = ubinascii.unhexlify(mac_hex)
        
        # 3. Comparaison en temps constant
        if not equal_bytes(received_bytes, expected):
            print("HMAC Mismatch!")
            return False, b'', b''
            
        parts = command.split(b'|')
        if len(parts) != 4 or parts[0] != KEYUPDATE_PREFIX:
            return False, b'', b''
            
        # 4. Conversion également des clés reçues (qui sont en HEX)
        return True, ubinascii.unhexlify(parts[2]), ubinascii.unhexlify(parts[3])
    except Exception as e:
        print("Error in verify:", e)
        return False, b'', b''
