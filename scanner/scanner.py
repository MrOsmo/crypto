import socket

def scan_port(ip, port):
    """Проверка одного порта."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)  
            s.connect((ip, port))
            print(f"[+] {ip}:{port} - Порт открыт")
    except (socket.timeout, ConnectionRefusedError):
        pass  


def scan_target(ip, ports):
    """Сканирование всех указанных портов для одного IP."""
    print(f"Сканирование {ip}...")
    for port in ports:
        scan_port(ip, port) 


def main():
    """Основная функция."""
    targets = ["192.168.1.1", "192.168.1.2", "127.0.0.1"]

    ports = range(1, 1025)

    for target in targets:
        scan_target(target, ports)


if __name__ == "__main__":
    main()
