import time
from scapy.all import srp, Ether, ARP, conf
from datetime import datetime
import json
from google.cloud import pubsub_v1
import logging


conf.verb = 0

def obtener_dispositivos_activos(red):
    """Devuelve un diccionario con las direcciones MAC e IP de los dispositivos activos."""
    dispositivos_activos = {}
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=red), timeout=2, retry=2)
    for snd, rcv in ans:
        dispositivos_activos[rcv[ARP].psrc] = rcv[Ether].src
    return dispositivos_activos

def monitorear_red(red):
    dispositivos_conocidos = {}
    try:
        while True:
            timestamp = datetime.now().isoformat()
            dispositivos_actuales = obtener_dispositivos_activos(red)
            nuevos_dispositivos = {ip: mac for ip, mac in dispositivos_actuales.items() if ip not in dispositivos_conocidos}
            dispositivos_desconectados = {ip: mac for ip, mac in dispositivos_conocidos.items() if ip not in dispositivos_actuales}
            
            for ip, mac in nuevos_dispositivos.items():
                evento_nuevos = {                    
                    "TIME": timestamp,
                    "IP": ip,
                    "MAC": mac
                }
                print(json.dumps(evento_nuevos, indent=4))
                      
            
            dispositivos_conocidos = dispositivos_actuales
            time.sleep(10)  # Pausa antes del siguiente escaneo
    except KeyboardInterrupt:
        print("Monitoreo detenido.")


class PubSubMessages:

    """ Publish Messages in our PubSub Topic """

    def _init_(self, project_id: str, topic_name: str):
        self.publisher = pubsub_v1.PublisherClient()
        self.project_id = project_id
        self.topic_name = topic_name

    def publishMessages(self, message: str):
        json_str = json.dumps(message)
        topic_path = self.publisher.topic_path(self.project_id, self.topic_name)
        self.publisher.publish(topic_path, json_str.encode("utf-8"))
        logging.info("A New person has been monitored. Id: %s", message['persona_id'])

    def _exit_(self):
        self.publisher.transport.close()
        logging.info("PubSub Client closed.")



monitorear_red('172.28.40.1/25')
