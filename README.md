# Infrastructure de capteurs : MQTT + LoRa Bidirectionnel Sécurisé

Ce projet contient une passerelle MQTT/LoRa avec chiffrement AES-CBC, authentification et intégrité HMAC-SHA1. Il intègre un système complet de communication bidirectionnelle permettant le **renouvellement dynamique des clés cryptographiques (OTA Rekeying)** et la gestion à distance depuis un client Linux interactif.

## Architecture

* **ESP32 Capteur :**

  * génère une mesure toutes les 5 secondes ;

  * chiffre la donnée en AES-CBC ;

  * ajoute une signature HMAC-SHA1 pour l'intégrité ;

  * transmet le paquet par LoRa ;

  * **ouvre une fenêtre d'écoute LoRa de 6 secondes** après chaque envoi pour recevoir d'éventuelles commandes (nouveauté).

* **ESP32 Passerelle :**

  * reçoit les messages LoRa des capteurs ;

  * vérifie le HMAC et déchiffre l'AES-CBC (sauf si le mode `NOCHECK` est activé) ;

  * publie le résultat vers le broker MQTT ;

  * **écoute les commandes MQTT de l'administrateur** pour relayer des requêtes (ex: mise à jour de clés) vers les capteurs via LoRa.

* **Client Linux (Interactif) :**

  * interface shell (invite de commande `(mqtt)`) ;

  * s’abonne au topic MQTT pour décoder la télémétrie en direct ;

  * **permet l'envoi de commandes administratives** : rotation de clés (rekeying), désactivation temporaire de la sécurité (`NOCHECK`), ou publication de messages de test.

## Fichiers MicroPython

À copier à la racine de chaque ESP32 (via un outil comme Thonny ou ampy).

### 1. Capteur

Copier tous les fichiers du dossier `Projet/firmware/capteur/` sur le premier ESP32.

### 2. Passerelle

Copier tous les fichiers du dossier `Projet/firmware/passerelle/` sur le second ESP32. Configurez obligatoirement le point d'accès Wi-Fi dans le fichier `config.py` de la passerelle :

```python
WIFI_SSID = 'Votre_SSID'
WIFI_PASSWORD = 'Votre_Mot_de_passe'
```

### Paramètres communs (clés initiales)

Les deux ESP32 et le client Linux utilisent initialement les clés définies dans leurs fichiers `config.py` respectifs :

```python
AES_KEY = b'0123456789abcdef'
HMAC_KEY = b'abcd'
```

## Installation du client d'administration Linux

Le nouveau client Linux se trouve dans le dossier `Projet/mqtt_client/`. Depuis le dossier racine du projet :

```bash
# Création et activation de l'environnement virtuel
python3 -m venv .venv
source .venv/bin/activate

# Installation des dépendances (Paho MQTT, Cryptography, etc.)
python3 -m pip install -r Projet/requirements.txt
```

## Utilisation et Tests

Le client Linux agit désormais comme un interpréteur de commandes interactif.

### Lancer le client

```bash
python3 Projet/mqtt_client/main.py
```

*Le terminal affichera une invite de commande `(mqtt)> `.*

### Liste des commandes disponibles dans le shell

Tapez `help` dans l'invite pour voir toutes les commandes.

* `listen` : Démarre l'écoute des messages chiffrés sur le réseau.

* `stop_listen` : Arrête l'écoute.

* `status` : Affiche l'état du broker, des clés en cours d'utilisation et si l'écoute est active.

* `update_keys <nouvelle_cle_aes> <nouvelle_cle_hmac>` : Lance une rotation des clés sur le réseau.

* `nocheck <on|off>` : Active/désactive la vérification de sécurité sur la passerelle.

* `publish <node_id> <message>` : Simule l'envoi d'un message capteur pour tester la passerelle.

* `exit` ou `quit` : Ferme l'application.

## Scénarios de tests

### Test 1 : Lancement standard de l'infrastructure

1. Allumez la passerelle, l'écran OLED indique son IP et sa connexion au broker.

2. Allumez le capteur.

3. Dans le client Linux, tapez :

   ```text
   (mqtt) listen
   ```

4. Vous devriez voir arriver les paquets décodés en temps réel :

   ```json
   [OK] capteur1 {"node":"capteur1","type":"sensor","counter":1,"temperature":20.5,"battery":89}
   ```

### Test 2 : Rotation de clés à distance (OTA Rekeying)

Cette opération modifie les clés à la volée de manière synchronisée entre le PC, la passerelle, et le capteur en utilisant un HMAC de la clé actuelle pour authentifier la demande.

1. Lancer l'écoute dans le client : `listen`

2. Déclencher la mise à jour (la clé AES **doit** faire 16 caractères) :

   ```text
   (mqtt) update_keys 1234567890123456 supersecret
   ```

3. **Le système gère la transaction complète** :

   * Le Linux envoie l'ordre à la Passerelle.

   * La Passerelle met à jour ses clés et relaie l'ordre par LoRa au capteur.

   * Le Capteur vérifie la demande, met à jour ses clés (OLED: `KEYS OK`), et renvoie un acquittement.

   * Le Client Linux reçoit l'acquittement et valide l'opération finale en affichant :
     `[CONFIRMED] Mise à jour des clés validée par le capteur.`

### Mécanisme de sécurité : Rollback Automatique

Pour éviter qu'une mise à jour de clés ne corrompe le réseau de manière irréversible (par exemple si la passerelle applique les nouvelles clés mais que le capteur ne les reçoit pas ou les refuse), un mécanisme de **Rollback Automatique** est intégré au client Linux :

1. **Compte à rebours :** Lors de l'envoi de la commande `update_keys`, le client Linux initie un compte à rebours (timeout).

2. **Détection d'échec (NACK ou Timeout) :** Si le client reçoit un rejet explicite (`keys_rejected` / `KEYS_FAILED`) signalant que le capteur a refusé la signature de la trame (NACK), **OU** s'il ne reçoit aucune confirmation avant l'expiration du délai (perte radio), la transaction est immédiatement abortée.

3. **Restauration distante (Rollback) :** Le client Linux forge alors automatiquement une commande de "retour en arrière" (restauration des anciennes clés). Puisque la passerelle utilise déjà les *nouvelles* clés, cette commande de restauration est impérativement signée avec la *nouvelle* clé HMAC.

4. **Resynchronisation :** La passerelle accepte l'ordre, repasse sur ses anciennes clés, et le réseau retrouve son état de fonctionnement d'origine. Les clés du client Linux sont également restaurées localement.

### Test 3 : Mode `NOCHECK` (Débogage)

Si un capteur a un HMAC invalide ou n'a pas les bonnes clés, son message est rejeté silencieusement. Pour voir le trafic brut LoRa reçu par la passerelle :

1. Dans le client Linux, tapez :

   ```text
   (mqtt) nocheck on
   ```

2. La passerelle (qui affiche `NO-CHK` sur son OLED) va cesser de déchiffrer et transférer la chaîne Base64 intégrale sur le serveur MQTT.

3. Le client Linux récupère les données brutes :

   ```json
   [MQTT raw] {"node": "capteur1", "data": "SU5TQ...", "rssi": -45, "snr": 9.5, "secure": false}
   ```

4. Remettez la sécurité en route avec : `nocheck off`.

## Dépannage

* **Aucun message n'arrive au Linux :**

  * Vérifiez la connexion Wi-Fi de la passerelle via le moniteur série.

  * Vérifiez que la passerelle et le capteur partagent bien le même `sync_word` et `spreading_factor` dans `config.py`.

* **Messages rejetés (HMAC invalide / Décryptage impossible) :**

  * Il y a une désynchronisation des clés.

  * Si le PC est à jour mais le capteur a refusé les clés, vérifiez sur l'OLED du capteur s'il est affiché `KEYS BAD`. Dans ce cas, redémarrez les ESP32 pour recharger les clés d'usine du fichier de config et redémarrez le client Linux.

* **La mise à jour des clés reste bloquée en "[BAD_KEYS] (Old Keys Valid)" :**

  * Le message n'a pas atteint le capteur dans sa fenêtre d'écoute de 6 secondes, ou le capteur a refusé la trame (NACK). Le Linux a automatiquement déclenché le Rollback décrit ci-dessus. Attendez l'annulation complète, puis réessayez.