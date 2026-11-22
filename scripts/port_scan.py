#!/usr/bin/env python3
"""
port_scan.py

Escáner TCP connect() ligero en Python puro, usado para reconocer
puertos internos de un host (p. ej. un host interno descubierto durante
el movimiento lateral) cuando nmap no estaba disponible en la máquina
comprometida desde la que se pivotaba.

Uso:
    python3 port_scan.py <host> [puerto_inicio] [puerto_fin]
    python3 port_scan.py -h | --help
"""
import argparse
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


def parse_args(argv: list[str]) -> argparse.Namespace:
    # Los puertos se dejan como str en argparse (type=str) y se
    # convierten a mano más abajo, para poder dar un mensaje de error
    # limpio y un exit code 1 propio en vez del traceback / exit code 2
    # que daría `type=int` al fallar la conversión dentro de argparse.
    parser = argparse.ArgumentParser(
        prog="port_scan.py",
        description="Escáner TCP connect() ligero, sin dependencias externas.",
    )
    parser.add_argument("host", help="Host o IP a escanear.")
    parser.add_argument(
        "start_port",
        nargs="?",
        default="1",
        help="Puerto inicial (por defecto: 1).",
    )
    parser.add_argument(
        "end_port",
        nargs="?",
        default="65535",
        help="Puerto final (por defecto: 65535).",
    )
    # --help y errores de argparse (p.ej. argumentos desconocidos) usan
    # su propio exit code (0 y 2 respectivamente) y se dejan tal cual.
    args = parser.parse_args(argv)

    ports: dict[str, int] = {}
    for name, raw in (("puerto_inicio", args.start_port), ("puerto_fin", args.end_port)):
        try:
            value = int(raw)
        except ValueError:
            print(f"Error: {name} debe ser un número entero (recibido: {raw!r})", file=sys.stderr)
            sys.exit(1)
        if not (1 <= value <= 65535):
            print(f"Error: {name} debe estar entre 1 y 65535 (recibido: {value})", file=sys.stderr)
            sys.exit(1)
        ports[name] = value

    if ports["puerto_inicio"] > ports["puerto_fin"]:
        print("Error: puerto_inicio no puede ser mayor que puerto_fin", file=sys.stderr)
        sys.exit(1)

    args.start_port = ports["puerto_inicio"]
    args.end_port = ports["puerto_fin"]
    return args


def main() -> None:
    args = parse_args(sys.argv[1:])

    with ThreadPoolExecutor(max_workers=200) as executor:
        executor.map(lambda p: check(args.host, p), range(args.start_port, args.end_port + 1))


if __name__ == "__main__":
    main()
