import time
import json
import logging
from datetime import datetime
from scapy.all import sniff, Ether, DNS, DNSQR, IP, UDP
import requests

# Configure logging
logging.basicConfig(level=logging.INFO)

class APIMessages:
    def __init__(self, api_endpoint: str):
        self.api_endpoint = api_endpoint

    def send_message(self, message: dict):
        timestamp = message['TIME']
        json_data = json.dumps(message)
        headers = {'Content-Type': 'application/json'}
        try:
            response = requests.post(self.api_endpoint, headers=headers, data=json_data)
            if response.status_code == 200:
                logging.info("Message sent to API endpoint at %s: %s", self.api_endpoint, json_data)
            else:
                logging.error("Failed to send message to API endpoint. Status code: %d", response.status_code)
        except Exception as e:
            logging.error("Error sending message to API endpoint: %s", str(e))

def handle_dns_packet(packet, api_client):
    """Process DNS packets and send relevant information to API."""
    if packet.haslayer(DNS) and packet.haslayer(DNSQR) and packet.haslayer(Ether):
        timestamp = datetime.now().isoformat()
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        mac_src = packet[Ether].src
        mac_dst = packet[Ether].dst
        dns_query = packet[DNSQR].qname.decode()

        event = {
            "TIME": timestamp,
            "IP_SRC": ip_src,
            "IP_DST": ip_dst,
            "MAC_SRC": mac_src,
            "MAC_DST": mac_dst,
            "DNS_QUERY": dns_query
        }

        api_client.send_message(event)

def monitor_network(api_client, interface='eth0'):
    """Monitor network for DNS queries and send changes to API."""
    sniff(filter="udp port 53", iface=interface, store=False, prn=lambda x: handle_dns_packet(x, api_client))

if __name__ == "__main__":
    api_endpoint = 'https://api-mac-checker-traffic-vqe6hjqvra-ew.a.run.app/traffic'
    api_client = APIMessages(api_endpoint)
    monitor_network(api_client, 'en0')
