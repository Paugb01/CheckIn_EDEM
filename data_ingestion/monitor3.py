import time
import json
import logging
from datetime import datetime
from scapy.all import srp, Ether, ARP, conf
from google.cloud import pubsub_v1

# Configure logging
logging.basicConfig(level=logging.INFO)

# Scapy configuration to mute verbose output
conf.verb = 0

class PubSubMessages:
    """Publish messages to a Pub/Sub topic."""

    def __init__(self, project_id: str, topic_name: str):
        self.publisher = pubsub_v1.PublisherClient()
        self.project_id = project_id
        self.topic_name = topic_name

    def publishMessages(self, message: dict):
        json_str = json.dumps(message)
        topic_path = self.publisher.topic_path(self.project_id, self.topic_name)
        future = self.publisher.publish(topic_path, json_str.encode('utf-8'))
        future.result()  # Ensure the message is sent before proceeding
        logging.info("Message published to %s: %s", self.topic_name, json_str)

    def __del__(self):
        self.publisher.transport.close()
        logging.info("PubSub client closed.")

def obtener_dispositivos_activos(red):
    """Returns a dictionary with MAC and IP addresses of active devices."""
    dispositivos_activos = {}
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=red), timeout=2, retry=2)
    for snd, rcv in ans:
        dispositivos_activos[rcv[ARP].psrc] = rcv[Ether].src
    return dispositivos_activos

def monitorear_red(red, pubsub_client):
    """Monitor network for active devices and publish changes to Pub/Sub."""
    dispositivos_conocidos = {}
    try:
        while True:
            timestamp = datetime.now().isoformat()
            dispositivos_actuales = obtener_dispositivos_activos(red)
            nuevos_dispositivos = {ip: mac for ip, mac in dispositivos_actuales.items() if ip not in dispositivos_conocidos}
            
            for ip, mac in dispositivos_actuales.items():
                evento = {
                    "TIME": timestamp,
                    "IP": ip,
                    "MAC": mac
                }
                print(json.dumps(evento, indent=4))
                pubsub_client.publishMessages(evento)
            
            dispositivos_conocidos = dispositivos_actuales
            time.sleep(10)  # Pause before the next scan
    except KeyboardInterrupt:
        print("Monitoring stopped.")

if __name__ == "__main__":
    project_id = 'gft-edem-hackathon'
    topic_name = 'mac_receiver'

    # Initialize PubSubMessages with the Google Cloud project and topic name
    pubsub_client = PubSubMessages(project_id, topic_name)

    # Start monitoring the network specified
    monitorear_red('172.28.40.1/25', pubsub_client)