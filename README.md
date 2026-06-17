# Infrastructure de capteurs : MQTT + LoRa sécurisé

Ce projet contient une passerelle MQTT/LoRa avec chiffrement AES-CBC, authentification et intégrité HMAC-SHA1.

## Architecture

- ESP32 capteur :
  - génère une mesure toutes les 5 secondes ;
  - chiffre la donnée en AES-CBC ;
  - ajoute un HMAC-SHA1 ;
  - transmet le paquet par LoRa.

- ESP32 passerelle :
  - reçoit les messages LoRa ;
  - vérifie le HMAC ;
  - déchiffre AES-CBC ;
  - publie le résultat vers le broker MQTT `p-fb.net:1883`.

- Client Linux :
  - s’abonne au topic MQTT ;
  - vérifie l’authentification et l’intégrité ;
  - déchiffre les messages ;
  - peut mettre à jour les clés de manière sécurisée.

## Fichiers MicroPython

À copier à la racine de chaque ESP32.

### Capteur

Copier tous les fichiers de :

```text
firmware/capteur/
```

sur le premier ESP32.

### Passerelle

Copier tous les fichiers de :

```text
firmware/passerelle/
```

sur le second ESP32.

Les deux ESP32 doivent avoir les mêmes paramètres dans `config.py` :

```python
AES_KEY = b'0123456789abcdef'
HMAC_KEY = b'abcd'
```

Ils doivent aussi avoir les mêmes paramètres LoRa :

```python
'frequency': 868E6,
'spreading_factor': 11,
'coding_rate': 5,
'sync_word': 0x12,
'enable_CRC': True,
```

## Installation du client Linux

Depuis le dossier `projet/` :

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
```

## Test 1 : vérifier le broker MQTT

Dans un premier shell :

```bash
mosquitto_sub -h p-fb.net -u insa -P insa -t insa/lora/data
```

Dans un second shell :

```bash
mosquitto_pub -h p-fb.net -u insa -P insa -t insa/lora/data -m "coucou"
```

Le premier shell doit afficher :

```text
coucou
```

## Test 2 : lancer le client Linux sécurisé

```bash
python3 linux/mqtt_client.py listen \
  --broker p-fb.net \
  --mqtt-user insa \
  --mqtt-password insa \
  --data-topic insa/lora/data \
  --aes-key 0123456789abcdef \
  --hmac-key abcd
```

Sortie attendue lorsqu’un message valide arrive :

```text
[OK] capteur1 {"node":"capteur1","type":"sensor","counter":1,...}
```

Sortie attendue si le HMAC est invalide ou si la clé est mauvaise :

```text
[BAD] message rejected
```

## Test 3 : lancer les deux ESP32

1. Flasher le premier ESP32 avec les fichiers de `firmware/capteur/`.
2. Flasher le second ESP32 avec les fichiers de `firmware/passerelle/`.
3. Connecter la passerelle au Wi-Fi configuré dans `config.py`.
4. Lancer le client Linux avec la commande `listen`.
5. Attendre les messages LoRa.

La passerelle publie des messages JSON contenant :

```json
{
  "node": "capteur1",
  "data": "...",
  "rssi": -80,
  "snr": 8.5,
  "secure": true
}
```

Le RSSI et le SNR sont aussi affichés sur l’OLED de la passerelle.

## Test 4 : vérifier l’intégrité

Pour vérifier que le HMAC fonctionne :

1. Lancer le client Linux avec une mauvaise clé HMAC :

```bash
python3 linux/mqtt_client.py listen \
  --broker p-fb.net \
  --mqtt-user insa \
  --mqtt-password insa \
  --data-topic insa/lora/data \
  --aes-key 0123456789abcdef \
  --hmac-key mauvaisecle
```

2. Attendre un message du capteur.
3. Le client doit afficher :

```text
[BAD] message rejected
```

Cela montre qu’un message modifié ou signé avec une mauvaise clé est rejeté.

## Mise à jour sécurisée des clés

Le protocole de mise à jour utilise un HMAC avec la clé actuelle.

Depuis le PC, avec les clés actuelles :

```bash
python3 linux/mqtt_client.py update-keys \
  --broker p-fb.net \
  --mqtt-user insa \
  --mqtt-password insa \
  --command-topic insa/lora/command/passerelle \
  --current-hmac-key abcd \
  --new-aes-key nouvellecle16octets \
  --new-hmac-key nouvellecle
```

Après une mise à jour réussie :

- la passerelle met à jour ses clés ;
- elle renvoie la commande au capteur par LoRa ;
- le capteur met à jour ses clés ;
- le client Linux doit ensuite être relancé avec les nouvelles clés.

Exemple :

```bash
python3 linux/mqtt_client.py listen \
  --broker p-fb.net \
  --mqtt-user insa \
  --mqtt-password insa \
  --data-topic insa/lora/data \
  --aes-key nouvellecle16octets \
  --hmac-key nouvellecle
```

La nouvelle clé AES doit faire exactement 16 octets.

## Dépannage

Si aucun message n’arrive :

- vérifier que les deux ESP32 utilisent la même fréquence LoRa ;
- vérifier que le spreading factor, le coding rate et le sync word sont identiques ;
- vérifier que les clés AES/HMAC sont identiques sur le capteur, la passerelle et le client Linux ;
- vérifier que la passerelle est bien connectée au Wi-Fi ;
- vérifier que le broker MQTT accepte bien les identifiants `insa / insa` ;
- vérifier que le topic MQTT utilisé est bien `insa/lora/data`.

Si les messages sont rejetés :

- vérifier que la clé HMAC est la même partout ;
- vérifier que la clé AES est la même partout ;
- relancer une mise à jour sécurisée des clés avec `update-keys`.
