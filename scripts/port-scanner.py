import socket
import tempfile

def scan_ports(ip, start_port, end_port):
    open_ports = []
    for port in range(start_port, end_port + 1):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        except socket.error:
            pass
    return open_ports

if __name__ == "__main__":
    ip = input("Enter the IP address to scan: ")
    start_port = int(input("Enter the starting port: "))
    end_port = int(input("Enter the ending port: "))

    open_ports = scan_ports(ip, start_port, end_port)

    with tempfile.NamedTemporaryFile(delete=False) as temp:
        for port in open_ports:
            temp.write((str(port) + "\n").encode())
        print("Temporary file path:", temp.name)

    print("Port scanning completed. Open ports saved to temporary file.")