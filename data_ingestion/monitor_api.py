import time
import json
import logging
from datetime import datetime
from scapy.all import srp, Ether, ARP, conf
import requests

# Configure logging
logging.basicConfig(level=logging.INFO)

# Scapy configuration to mute verbose output
conf.verb = 0

def send_data_to_api(data, api_endpoint):
    """Send data to the specified API endpoint."""
    try:
        response = requests.post(api_endpoint, json=data)
        response.raise_for_status()  # Raise an exception for non-2xx status codes
        logging.info("Data sent to API successfully: %s", data)
    except requests.exceptions.RequestException as e:
        logging.error("Error sending data to API: %s", e)

def obtener_dispositivos_activos(red):
    """Returns a dictionary with MAC and IP addresses of active devices."""
    dispositivos_activos = {}
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=red), timeout=2, retry=2)
    for snd, rcv in ans:
        dispositivos_activos[rcv[ARP].psrc] = rcv[Ether].src
    return dispositivos_activos

def monitorear_red(red, api_endpoint):
    """Monitor network for active devices and send changes to API."""
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
                send_data_to_api(evento, api_endpoint)
            
            dispositivos_conocidos = dispositivos_actuales
            time.sleep(300)  # Pause before the next scan
    except KeyboardInterrupt:
        print("Monitoring stopped.")

if __name__ == "__main__":
    api_endpoint = 'https://api-mac-checker-vqe6hjqvra-ew.a.run.app/messages'
    # Start monitoring the network specified
    monitorear_red('172.28.40.1/25', api_endpoint)
