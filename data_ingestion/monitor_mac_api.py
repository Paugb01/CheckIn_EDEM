import time
import json
import logging
from datetime import datetime
from scapy.all import srp, Ether, ARP, conf
import requests  # Import requests library

# Configure logging
logging.basicConfig(level=logging.INFO)

# Scapy configuration to mute verbose output
conf.verb = 0

def send_to_api(endpoint, message):
    """Send messages to a specified API endpoint."""
    response = requests.post(endpoint, json=message)
    if response.status_code == 200:
        logging.info("Message sent to API: %s", json.dumps(message))
    else:
        logging.error("Failed to send message: %s. Response: %s", json.dumps(message), response.text)

def obtener_dispositivos_activos(red):
    """Returns a dictionary with MAC and IP addresses of active devices."""
    dispositivos_activos = {}
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=red), timeout=2, retry=2)
    for snd, rcv in ans:
        dispositivos_activos[rcv[ARP].psrc] = rcv[Ether].src
    return dispositivos_activos

def monitorear_red(red, api_url):
    """Monitor network for active devices and send changes to an API."""
    dispositivos_conocidos = {}
    try:
        while True:
            timestamp = datetime.now().isoformat()
            dispositivos_actuales = obtener_dispositivos_activos(red)
            
            for ip, mac in dispositivos_actuales.items():
                if ip not in dispositivos_conocidos:
                    evento = {
                        "TIME": timestamp,
                        "IP": ip,
                        "MAC": mac
                    }
                    print(json.dumps(evento, indent=4))
                    send_to_api(api_url, evento)
            
            dispositivos_conocidos = dispositivos_actuales
            time.sleep(300)  # Pause before the next scan
    except KeyboardInterrupt:
        print("Monitoring stopped.")

if __name__ == "__main__":
    api_url = "https://api-mac-checker-vqe6hjqvra-ew.a.run.app/messages"
    # Start monitoring the network specified
    monitorear_red('172.28.40.1/25', api_url)
