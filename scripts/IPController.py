"""
DB Bağlasnıtısı oluşturuldu başarlı bir şekilde veriler yükleniyor

Output:
PID: 8196, Process: chrome.exe, Local: 192.168.132.37:62093, Remote: 213.182.38.133:443,
    Protocol: ICMP, StartTime: 2024-05-23 23:56:02, CommunicationProtocol: HTTPS,
        LocalIP: 192.168.132.37, LocalPort: 62093, RemoteIP: 213.182.38.133, RemotePort: 443

PID: 8196, Process: chrome.exe, Local: 192.168.132.37:62108, Remote: 35.190.10.96:443,
    Protocol: ICMP, StartTime: 2024-05-23 23:56:02, CommunicationProtocol: HTTPS,
        LocalIP: 192.168.132.37, LocalPort: 62108, RemoteIP: 35.190.10.96, RemotePort: 443

Giden Gelen IP'ler kontrol edilir
Her 60 Saniyede Bir Bağlantıları Listeler
"""

import os
import psutil
import time
import socket
import psutil
import sqlite3
from datetime import datetime

PROTOCOL_NAMES = {
    socket.IPPROTO_TCP: "TCP",
    socket.IPPROTO_UDP: "UDP",
    socket.IPPROTO_ICMP: "ICMP",
}

COMMUNICATION_PROTOCOLS = {
    80: "HTTP",
    443: "HTTPS",
    25: "SMTP",
    22: "SSH",
}

DB_PATH = 'db.sqlite3'


def get_connections():
    connections = []
    for conn in psutil.net_connections(kind='inet'):
        if conn.status == psutil.CONN_ESTABLISHED:
            local_addr = conn.laddr
            remote_addr = conn.raddr
            try:
                process = psutil.Process(conn.pid)
                process_name = process.name()
                create_time = datetime.fromtimestamp(process.create_time()).strftime("%Y-%m-%d %H:%M:%S")
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                process_name = "?"
                create_time = "?"

            connection_key = f"{local_addr.ip}:{local_addr.port}-{remote_addr.ip}:{remote_addr.port}"
            protocol_name = get_protocol_name(conn.type)
            communication_protocol = get_communication_protocol(local_addr.port, remote_addr.port)

            # Paket boyutlarını ve toplam veri aktarımını psutil ile almak mümkün değildir.
            # Bunun için daha gelişmiş ağ izleme araçları olması gerekir.

            connections.append({
                "pid": conn.pid,
                "local_address": f"{local_addr.ip}:{local_addr.port}",
                "remote_address": f"{remote_addr.ip}:{remote_addr.port}" if remote_addr else "N/A",
                "protocol": protocol_name,
                "process_name": process_name,
                "start_time": create_time,
                "communication_protocol": communication_protocol,
                "local_ip": local_addr.ip,
                "local_port": local_addr.port,
                "remote_ip": remote_addr.ip if remote_addr else "N/A",
                "remote_port": remote_addr.port if remote_addr else "N/A",
                "key": connection_key
            })
    return connections

def send_alert(conn):
    # Uyarı gönderme mantığınızı buraya ekleyin
    # Örnek: E-posta, SMS veya log dosyasına yazma
    print(f"UYARI! Şüpheli bağlantı: {conn}")

def get_protocol_name(protocol_num):
    return PROTOCOL_NAMES.get(protocol_num, "UNKNOWN")

def get_communication_protocol(local_port, remote_port):
    return COMMUNICATION_PROTOCOLS.get(local_port) or COMMUNICATION_PROTOCOLS.get(remote_port) or "UNKNOWN"

def insert_connection_to_db(conn):
    db = sqlite3.connect(DB_PATH)
    cursor = db.cursor()
    cursor.execute('''
        INSERT INTO IpLogs (PID, Process, Local, Remote, Protocol, StartTime, CommunicationProtocol, LocalIP, LocalPort, RemoteIP, RemotePort)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (conn['pid'], conn['process_name'], conn['local_address'], conn['remote_address'], conn['protocol'], conn['start_time'], conn['communication_protocol'], conn['local_ip'], conn['local_port'], conn['remote_ip'], conn['remote_port']))
    db.commit()
    db.close()

if __name__ == "__main__":
    seen_connections = set()
    while True:
        connections = get_connections()
        for conn in connections:
            if conn['key'] not in seen_connections:
                seen_connections.add(conn['key'])
                if conn['remote_address'].startswith("10.57.1.27"):
                    send_alert(conn)
                else:
                    insert_connection_to_db(conn)
                    print(f"PID: {conn['pid']}, Process: {conn['process_name']}, "
                          f"Local: {conn['local_address']}, Remote: {conn['remote_address']}, "
                          f"Protocol: {conn['protocol']}, StartTime: {conn['start_time']}, "
                          f"CommunicationProtocol: {conn['communication_protocol']}, "
                          f"LocalIP: {conn['local_ip']}, LocalPort: {conn['local_port']}, "
                          f"RemoteIP: {conn['remote_ip']}, RemotePort: {conn['remote_port']}")
        time.sleep(1)
