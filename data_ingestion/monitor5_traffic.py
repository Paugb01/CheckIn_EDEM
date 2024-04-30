import time
import json
import logging
from datetime import datetime
from scapy.all import sniff, Ether, DNS, DNSQR, IP, UDP
from google.cloud import pubsub_v1

# Configure logging
logging.basicConfig(level=logging.INFO)

class PubSubMessages:
    def __init__(self, project_id: str, topic_name: str):
        self.publisher = pubsub_v1.PublisherClient()
        self.project_id = project_id
        self.topic_name = topic_name

    def publishMessages(self, message: dict):
        json_str = json.dumps(message)
        topic_path = self.publisher.topic_path(self.project_id, self.topic_name)
        future = self.publisher.publish(topic_path, json_str.encode('utf-8'))
        future.result()
        logging.info("Message published to %s: %s", self.topic_name, json_str)

    def __del__(self):
        self.publisher.transport.close()
        logging.info("PubSub client closed.")

def handle_dns_packet(packet):
    """Process DNS packets and publish relevant information."""
    if packet.haslayer(DNS) and packet.haslayer(DNSQR) and packet.haslayer(Ether):
        timestamp = datetime.now().isoformat()
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        mac_src = packet[Ether].src
        mac_dst = packet[Ether].dst
        dns_query = packet[DNSQR].qname.decode()

        evento = {
            "TIME": timestamp,
            "IP_SRC": ip_src,
            "IP_DST": ip_dst,
            "MAC_SRC": mac_src,
            "MAC_DST": mac_dst,
            "DNS_QUERY": dns_query
        }

        print(json.dumps(evento, indent=4))
        return evento

def monitorear_red(pubsub_client, interface='eth0'):
    """Monitor network for DNS queries and publish changes to Pub/Sub."""
    sniff(filter="udp port 53", iface=interface, store=False, prn=lambda x: pubsub_client.publishMessages(handle_dns_packet(x)))

if __name__ == "__main__":
    project_id = 'gft-edem-hackathon'
    topic_name = 'mac_receiver'

    pubsub_client = PubSubMessages(project_id, topic_name)
    monitorear_red(pubsub_client, 'en0')
