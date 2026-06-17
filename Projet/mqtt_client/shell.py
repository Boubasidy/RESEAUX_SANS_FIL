import cmd
import sys
import readline

from security import build_key_update, pack_message, build_nocheck_command


def print_async(text, shell):
    """Affiche du texte en arrière-plan de manière propre en gérant le prompt."""
    # Effacer la ligne courante
    sys.stdout.write('\r\x1b[K')
    sys.stdout.flush()
    # Afficher le texte
    print(text)
    # Ré-afficher le prompt et le buffer actuel de readline
    sys.stdout.write(shell.prompt + readline.get_line_buffer())
    sys.stdout.flush()


class MqttShell(cmd.Cmd):
    intro = "Client MQTT/LoRa sécurisé interactif.\nTapez 'help' ou '?' pour lister les commandes."
    prompt = "(mqtt) "

    def __init__(self, args, client):
        super().__init__()
        self.args = args
        self.client = client
        self.listening = False

    def do_listen(self, arg):
        """Démarrer l'écoute des messages: listen"""
        if not self.listening:
            self.client.subscribe(self.args.data_topic)
            self.listening = True
            print(f"Connecté à {self.args.broker}:{self.args.port}, en écoute sur le topic {self.args.data_topic}")
        else:
            print("Déjà en écoute.")

    def do_stop_listen(self, arg):
        """Arrêter l'écoute des messages: stop_listen"""
        if self.listening:
            self.client.unsubscribe(self.args.data_topic)
            self.listening = False
            print("Écoute arrêtée.")
        else:
            print("Pas en écoute.")

    def do_update_keys(self, arg):
        """Mettre à jour les clés: update_keys <new_aes_key> <new_hmac_key>"""
        args_list = arg.split()
        if len(args_list) != 2:
            print("Usage: update_keys <new_aes_key> <new_hmac_key>")
            return
        
        new_aes_key = args_list[0].encode()
        new_hmac_key = args_list[1].encode()
        
        command = build_key_update(new_aes_key, new_hmac_key, self.args.hmac_key)
        info = self.client.publish(self.args.command_topic, command)
        info.wait_for_publish()
        print(f"Commande de mise à jour des clés publiée sur {self.args.command_topic}")
        
        # Passer en mode PENDING_UPDATE
        self.args.pending_update = True
        self.args.fallback_keys = (self.args.aes_key, self.args.hmac_key)
        self.args.active_keys = (new_aes_key, new_hmac_key)
        self.args.message_count = 0
        
        self.args.aes_key = new_aes_key
        self.args.hmac_key = new_hmac_key
        print("En attente de confirmation du capteur (mode double-décodage activé).")

    def do_publish(self, arg):
        """Publier un message de test: publish <node_id> <message>"""
        args_list = arg.split(maxsplit=1)
        if len(args_list) < 2:
            print("Usage: publish <node_id> <message>")
            return
            
        node_id = args_list[0]
        message = args_list[1]
        
        packet = pack_message(node_id, message.encode(), self.args.aes_key, self.args.hmac_key)
        info = self.client.publish(self.args.data_topic, packet)
        info.wait_for_publish()
        print(f"Message de test sécurisé publié sur {self.args.data_topic}")

    def do_nocheck(self, arg):
        """Activer/désactiver le mode no-check sur la passerelle: nocheck <on|off>"""
        arg = arg.strip().lower()
        if arg not in ('on', 'off'):
            print("Usage: nocheck <on|off>")
            return
            
        state = (arg == 'on')
        command = build_nocheck_command(state, self.args.hmac_key)
        info = self.client.publish(self.args.command_topic, command)
        info.wait_for_publish()
        print(f"Commande no-check={arg} publiée sur {self.args.command_topic}")

    def do_status(self, arg):
        """Afficher le statut actuel: status"""
        print(f"Broker: {self.args.broker}:{self.args.port}")
        print(f"En écoute: {'Oui' if self.listening else 'Non'} (Topic: {self.args.data_topic})")
        print(f"Clé AES actuelle: {self.args.aes_key.decode()}")
        print(f"Clé HMAC actuelle: {self.args.hmac_key.decode()}")

    def do_quit(self, arg):
        """Quitter l'application: quit"""
        print("Fermeture...")
        return True
    
    def do_exit(self, arg):
        """Quitter l'application: exit"""
        return self.do_quit(arg)