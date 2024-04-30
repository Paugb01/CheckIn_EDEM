import requests
import time
from scapy.all import sniff, IP, Ether, DNS, DNSQR
from datetime import datetime
import json
from threading import Thread, Lock
import logging

logging.basicConfig(level=logging.INFO)

API_ENDPOINT = "https://api-mac-checker-traffic-vqe6hjqvra-ew.a.run.app/traffic"

events = []
events_lock = Lock()  # Mutex for thread-safe manipulation of the events list

def handle_packet(packet):
    if IP in packet and Ether in packet:
        dns_query = None
        if DNS in packet and DNSQR in packet:
            dns_query = packet[DNSQR].qname.decode('utf-8', 'ignore')
        event = {
            "TIME": datetime.now().strftime("%A, %B %d, %Y - %H:%M:%S"),
            "IP_SRC": packet[IP].src,
            "IP_DST": packet[IP].dst,
            "MAC_SRC": packet[Ether].src,
            "MAC_DST": packet[Ether].dst,
            "DNS_QUERY": dns_query
        }
        logging.info(f"Captured event: {event}")
        with events_lock:
            events.append(event)

def send_events():
    while True:
        with events_lock:
            if events:
                try:
                    response = requests.post(API_ENDPOINT, json=events)
                    if response.status_code == 200:
                        logging.info("Events sent successfully")
                    else:
                        logging.error(f"Failed to send events. Status code: {response.status_code}, Response: {response.text}")
                    events.clear()
                except requests.exceptions.RequestException as e:
                    logging.error(f"An error occurred: {e}")
        time.sleep(30)

def monitor_network(interface):
    try:
        sniff(iface=interface, store=False, prn=handle_packet, filter="ip")
    except Exception as e:
        logging.error(f"Failed to start network monitoring on {interface}. Error: {e}")

if __name__ == "__main__":
    interface = 'en0'  # Update this to the correct interface based on ifconfig
    thread = Thread(target=monitor_network, args=(interface,))
    thread.start()
    send_events()
