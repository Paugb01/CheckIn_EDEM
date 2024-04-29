from google.cloud import pubsub_v1
import time
from datetime import datetime
import json
from scapy.all import srp, Ether, ARP, conf

conf.verb = 0

publisher = pubsub_v1.PublisherClient()
topic_path = publisher.topic_path('gft-edem-hackathon', 'mac_receiver')

def obtener_dispositivos_activos(red):
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
            
            for ip, mac in nuevos_dispositivos.items():
                evento_nuevos = {
                    "TIME": timestamp,
                    "IP": ip,
                    "MAC": mac
                }
                data = json.dumps(evento_nuevos)
                # Publica el mensaje en Pub/Sub
                publisher.publish(topic_path, data.encode('utf-8'))
            
            dispositivos_conocidos = dispositivos_actuales
            time.sleep(10)
    except KeyboardInterrupt:
        print("Monitoreo detenido.")


monitorear_red('172.28.40.1/25')
