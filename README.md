# 🎭 DHCP Spoofing — Servidor DHCP Falso (Rogue DHCP)

## 🎯 Objetivo del Laboratorio

Demostrar cómo un atacante puede suplantar al servidor DHCP legítimo respondiendo más rápido a las solicitudes de las víctimas, asignándoles un gateway falso que redirige todo su tráfico a través del atacante (MitM automático) y un servidor DNS controlado.

---

## 📋 Objetivo del Script

El script `DHCP_Spoofing.py` implementa un servidor DHCP falso en **Fast Race Mode**: escucha DHCP Discovers y Requests, y responde en un hilo paralelo con ráfaga de 3 paquetes para ganar la carrera al servidor R1 legítimo. El pool falso comienza en `192.168.10.200`.

### Parámetros usados

| Parámetro | Valor | Descripción |
|-----------|-------|-------------|
| `INTERFACE` | `ens4.10` | Subinterfaz VLAN 10 de Kali |
| `IP_ATACANTE` | `192.168.10.50` | IP del servidor DHCP falso y gateway falso |
| `POOL_INICIO` | `192.168.10.200` | Primera IP asignada a víctimas |
| `MASCARA` | `255.255.255.0` | Máscara de red entregada |
| `DNS_FALSO` | `8.8.8.8` | Servidor DNS entregado (puede ser propio) |
| `LEASE_TIME` | `600 s` | Tiempo de concesión |
| `RAFAGA` | `3` | Repeticiones por respuesta |
| `RETARDO_RAFAGA` | `0.001 s` | Retardo entre paquetes de ráfaga |

### Requisitos para utilizar la herramienta

```bash
# Dependencias
pip install scapy

# El servidor DHCP legítimo (R1) debe tener pool activo
# para poder demostrar la carrera y la victoria del rogue.

# Ejecución
sudo python3 DHCP_Spoofing.py
```

---

## 🔧 Documentación del Funcionamiento del Script

### Flujo de ejecución

```
1. Abrir socket L2 persistente (una sola vez → sin overhead)
2. sniff() en ens4.10 filtrando UDP puertos 67/68
3. Por cada paquete recibido → lanzar hilo daemon inmediato
4. En el hilo:
     Si tipo == DISCOVER (1):
       → construir_offer() → pool_actual++ → BOOTP op=2
       → enviar_rafaga() × 3 (1ms entre cada uno)
     Si tipo == REQUEST (3):
       → construir_ack() → extraer IP solicitada
       → enviar_rafaga() × 3
5. El cliente acepta el primer OFFER/ACK que llega
   → si es el nuestro, obtiene IP del pool 192.168.10.200+
   → su gateway queda apuntando a 192.168.10.50 (Kali)
```

### Diferencia entre OFFER legítimo y falso

```
DHCP OFFER LEGÍTIMO (R1):
  yiaddr  : 192.168.10.100
  router  : 192.168.10.254   ← gateway real
  dns     : 8.8.8.8, 1.1.1.1
  server  : 192.168.10.254

DHCP OFFER FALSO (Kali):
  yiaddr  : 192.168.10.200   ← pool del atacante
  router  : 192.168.10.50    ← gateway FALSO (Kali)
  dns     : 8.8.8.8
  server  : 192.168.10.50
```

### Técnicas de velocidad implementadas

| Técnica | Beneficio |
|---------|-----------|
| Socket L2 persistente | Elimina overhead de apertura por paquete |
| Threading por paquete | No bloquea el sniff mientras se responde |
| Ráfaga × 3 | El cliente acepta el primero; cubre pérdidas |
| `bytes(pkt)` una vez | No reserializa en cada envío de la ráfaga |

---

## 🗺️ Documentación de la Red

### Topología

```
        [ R1 — IOU L3 ]          ← DHCP Server legítimo
        DHCP Pool: 192.168.10.100-199
               |
           e0/0 (trunk)
               |
        [ SW-1 — IOL L2 ]
         e0/1       e0/3
          |           |
       [SW-3]     [Kali]         ← Rogue DHCP Server
       VLAN 10     ens4.10       DHCP Pool: 192.168.10.200+
       VPC-1,4     192.168.10.50
```

### Interfaces y VLANs

| Dispositivo | Interfaz | Modo | IP |
|-------------|----------|------|----|
| R1 | E0/0.10 | subinterfaz | 192.168.10.254/24 |
| SW-1 | E0/3 | access VLAN 10 | Atacante |
| Kali | ens4.10 | subinterfaz VLAN 10 | 192.168.10.50/24 |
| VPC-1/4 | eth0 | access VLAN 10 | DHCP → .100 o .200 |

---

## 📸 Capturas de Pantalla

> Insertar capturas en esta sección:

1. **`img/01_dhcp_legitimo.png`** — VPC-1 con `ip dhcp` antes del ataque. Obtiene IP del pool legítimo (`.100`-`.199`) con gateway `192.168.10.254`.
2. **`img/02_script_corriendo.png`** — Terminal Kali con el servidor rogue activo mostrando `[OFFER x3]` y `[ACK x3]`.
3. **`img/03_ip_falsa.png`** — VPC-1 con nueva IP del pool falso (`.200+`) y gateway `192.168.10.50`.
4. **`img/04_show_dhcp_binding.png`** — `show ip dhcp binding` en R1 mostrando las MACs atendidas por el servidor legítimo vs las del atacante.

---

## 🛡️ Contra-medidas

### DHCP Snooping

```
! Habilitar DHCP Snooping globalmente
SW-1(config)# ip dhcp snooping
SW-1(config)# ip dhcp snooping vlan 10,20

! Marcar como confiable SOLO el puerto hacia R1
SW-1(config)# interface Ethernet0/0
SW-1(config-if)# ip dhcp snooping trust

! Limitar tasa en puertos de acceso (usuarios)
SW-1(config)# interface Ethernet0/3
SW-1(config-if)# ip dhcp snooping limit rate 15

! Verificación
SW-1# show ip dhcp snooping
SW-1# show ip dhcp snooping binding
SW-1# show ip dhcp snooping statistics
```

> **Efecto:** Con DHCP Snooping activo, cualquier DHCP OFFER proveniente de un puerto no confiable (como E0/3 donde está Kali) es descartado automáticamente. El cliente solo puede recibir OFFER del servidor legítimo.
