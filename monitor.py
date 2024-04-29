import time
from scapy.all import srp, Ether, ARP, conf
from ipcalc import Network
from datetime import datetime

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
            timestamp = datetime.now()
            dispositivos_actuales = obtener_dispositivos_activos(red)
            nuevos_dispositivos = {ip: mac for ip, mac in dispositivos_actuales.items() if ip not in dispositivos_conocidos}
            dispositivos_desconectados = {ip: mac for ip, mac in dispositivos_conocidos.items() if ip not in dispositivos_actuales}
            
            if nuevos_dispositivos:
                print("Nuevos dispositivos conectados:")
                for ip, mac in nuevos_dispositivos.items():
                    print(f"TIME: {timestamp},IP: {ip}, MAC: {mac}")
            
            if dispositivos_desconectados:
                print("Dispositivos desconectados:")
                for ip, mac in dispositivos_desconectados.items():
                    print(f"TIME: {timestamp}, IP: {ip}, MAC: {mac}")
            
            dispositivos_conocidos = dispositivos_actuales
            time.sleep(10)  # Pausa antes del siguiente escaneo
    except KeyboardInterrupt:
        print("Monitoreo detenido.")

# Reemplazar en caso de que la subred haya sido cambiada (actualmente conectada a la de invitados de EDEM)
monitorear_red('172.28.40.1/25')
