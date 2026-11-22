#!/usr/bin/env python3
"""
port_scan.py

Escáner TCP connect() ligero en Python puro, usado para reconocer
puertos internos de un host (p. ej. payments.internal) cuando nmap
no estaba disponible en la máquina comprometida desde la que se
pivotaba.

Uso:
    python3 port_scan.py <host> [puerto_inicio] [puerto_fin]
"""
import socket
import sys
from concurrent.futures import ThreadPoolExecutor

def check(host: str, port: int) -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.5)
    try:
        s.connect((host, port))
        print(f"Puerto {port} ABIERTO")
    except OSError:
        pass
    finally:
        s.close()

def main() -> None:
    if len(sys.argv) < 2:
        print(f"Uso: {sys.argv[0]} <host> [puerto_inicio=1] [puerto_fin=65535]")
        sys.exit(1)

    host = sys.argv[1]
    start = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    end = int(sys.argv[3]) if len(sys.argv) > 3 else 65535

    with ThreadPoolExecutor(max_workers=200) as executor:
        executor.map(lambda p: check(host, p), range(start, end + 1))

if __name__ == "__main__":
    main()
