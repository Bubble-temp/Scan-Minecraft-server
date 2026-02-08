#!/usr/bin/env python3
"""
scan.py — Scanner combiné : plage d'IP + plage de ports pour trouver des serveurs Minecraft.

Exemples d'utilisation :
  python scan.py --cidr 192.168.1.0/24 --start-port 25560 --end-port 25570
  python scan.py --start 10.0.0.1 --end 10.0.0.50 --start-port 25565 --end-port 25575
  python scan.py --ip 127.0.0.1 --start-port 25560 --end-port 25600
  python scan.py --cidr 192.168.1.0/24  (port unique par défaut : 25565)
"""

import asyncio
import argparse
import ipaddress
import json
import struct
import sys
from typing import Optional

# ====================== Protocole Minecraft ======================

def encode_varint(value: int) -> bytes:
    out = bytearray()
    value &= 0xFFFFFFFF
    while True:
        temp = value & 0x7F
        value >>= 7
        if value != 0:
            temp |= 0x80
        out.append(temp)
        if value == 0:
            break
    return bytes(out)


def pack_packet(packet_id: int, payload: bytes = b"") -> bytes:
    packet = encode_varint(packet_id) + payload
    return encode_varint(len(packet)) + packet


def build_handshake(host: str, port: int, protocol_version: int = 754) -> bytes:
    payload = (
        encode_varint(protocol_version)
        + encode_varint(len(host)) + host.encode("utf-8")
        + struct.pack(">H", port)
        + encode_varint(1)  # next state = status
    )
    return pack_packet(0x00, payload)


def build_status_request() -> bytes:
    return pack_packet(0x00, b"")


# ====================== Lecture réseau async ======================

async def read_varint_async(reader: asyncio.StreamReader, timeout: float) -> int:
    result = 0
    shift = 0
    while True:
        b = await asyncio.wait_for(reader.readexactly(1), timeout=timeout)
        byte = b[0]
        result |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            break
        shift += 7
        if shift >= 35:
            raise ValueError("VarInt trop grand")
    return result


# ====================== Requête serveur Minecraft ======================

async def query_minecraft(host: str, port: int, timeout: float = 3.0) -> Optional[dict]:
    """Interroge un serveur Minecraft et retourne le JSON de status, ou None."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
    except Exception:
        return None

    try:
        writer.write(build_handshake(host, port))
        writer.write(build_status_request())
        await writer.drain()

        # Lecture de la réponse
        await read_varint_async(reader, timeout)   # longueur du paquet
        await read_varint_async(reader, timeout)   # id du paquet
        str_len = await read_varint_async(reader, timeout)
        json_bytes = await asyncio.wait_for(reader.readexactly(str_len), timeout=timeout)
        return json.loads(json_bytes.decode("utf-8", errors="replace"))
    except Exception:
        return None
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


# ====================== Parsing du MOTD ======================

def parse_motd(data: dict) -> str:
    desc = data.get("description", "")
    if isinstance(desc, dict):
        motd = desc.get("text", "")
        if "extra" in desc and isinstance(desc["extra"], list):
            motd += "".join(part.get("text", "") for part in desc["extra"])
        if not motd:
            motd = json.dumps(desc, ensure_ascii=False)
    elif isinstance(desc, str):
        motd = desc
    else:
        motd = str(desc)
    return motd.strip()


# ====================== Scan combiné IP x Port ======================

async def worker(queue: asyncio.Queue, sem: asyncio.Semaphore,
                 timeout: float, results: list, total: int, counter: dict):
    while True:
        item = await queue.get()
        if item is None:
            queue.task_done()
            break

        host, port = item
        async with sem:
            counter["done"] += 1
            data = await query_minecraft(host, port, timeout=timeout)
            if data:
                motd = parse_motd(data)
                players = data.get("players", {})
                online = players.get("online", 0)
                maxp = players.get("max", 0)
                sample = players.get("sample", [])
                sample_names = [p.get("name") for p in sample] if isinstance(sample, list) else []

                results.append({
                    "host": host,
                    "port": port,
                    "motd": motd,
                    "online": online,
                    "max": maxp,
                    "sample": sample_names,
                    "version": data.get("version", {}).get("name", "?"),
                })
                print(f"  [{counter['done']}/{total}] [FOUND] {host}:{port} — MOTD: {motd!r} — joueurs: {online}/{maxp} — version: {data.get('version', {}).get('name', '?')}")
            else:
                # Affichage discret de la progression (uniquement toutes les 500 cibles ou si verbose)
                if counter["done"] % 500 == 0:
                    print(f"  [{counter['done']}/{total}] en cours ...")
        queue.task_done()


async def scan(hosts: list, ports: list, concurrency: int, timeout: float) -> list:
    """Scanne toutes les combinaisons (host, port)."""
    queue = asyncio.Queue()
    results = []
    total = len(hosts) * len(ports)
    counter = {"done": 0}

    # Remplir la queue avec toutes les combinaisons IP x port
    for host in hosts:
        for port in ports:
            queue.put_nowait((str(host), port))

    sem = asyncio.Semaphore(concurrency)
    num_workers = min(concurrency, 500, total)

    # Ajouter les sentinelles pour arrêter les workers
    for _ in range(num_workers):
        queue.put_nowait(None)

    # Lancer les workers
    workers = []
    for _ in range(num_workers):
        w = asyncio.create_task(worker(queue, sem, timeout, results, total, counter))
        workers.append(w)

    await queue.join()
    for w in workers:
        w.cancel()

    return results


# ====================== Expansion des IP ======================

def expand_hosts(args) -> list:
    if args.cidr:
        net = ipaddress.ip_network(args.cidr, strict=False)
        return list(net.hosts())
    elif args.start and args.end:
        s = int(ipaddress.ip_address(args.start))
        e = int(ipaddress.ip_address(args.end))
        if e < s:
            raise SystemExit("L'IP de fin doit être >= à l'IP de début")
        return [ipaddress.ip_address(ip) for ip in range(s, e + 1)]
    elif args.ip:
        return [ipaddress.ip_address(args.ip)]
    else:
        raise SystemExit("Aucune IP fournie")


def expand_ports(args) -> list:
    if args.start_port is not None and args.end_port is not None:
        if args.end_port < args.start_port:
            raise SystemExit("Le port de fin doit être >= au port de début")
        return list(range(args.start_port, args.end_port + 1))
    elif args.port is not None:
        return [args.port]
    else:
        return [25565]


# ====================== Main ======================

def main():
    parser = argparse.ArgumentParser(
        description="Scanner combiné : plage d'IP + plage de ports pour serveurs Minecraft",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples :
  python scan.py --cidr 192.168.1.0/24
  python scan.py --cidr 192.168.1.0/24 --start-port 25560 --end-port 25570
  python scan.py --start 10.0.0.1 --end 10.0.0.50 --start-port 25565 --end-port 25575
  python scan.py --ip 127.0.0.1 --start-port 25560 --end-port 25600
        """,
    )

    # --- Groupe IP ---
    ip_group = parser.add_mutually_exclusive_group(required=True)
    ip_group.add_argument("--cidr", help="Plage CIDR (ex: 192.168.1.0/24)")
    ip_group.add_argument("--start", help="IP de début (inclusive)")
    ip_group.add_argument("--ip", help="IP unique à scanner")
    parser.add_argument("--end", help="IP de fin (inclusive) — utilisé avec --start")

    # --- Groupe Port ---
    parser.add_argument("--port", type=int, default=None,
                        help="Port unique (défaut: 25565 si aucun port spécifié)")
    parser.add_argument("--start-port", type=int, default=None,
                        help="Port de début (inclusive)")
    parser.add_argument("--end-port", type=int, default=None,
                        help="Port de fin (inclusive)")

    # --- Options ---
    parser.add_argument("--concurrency", type=int, default=200,
                        help="Nombre de connexions simultanées (défaut: 200)")
    parser.add_argument("--timeout", type=float, default=3.0,
                        help="Délai d'attente par connexion en secondes (défaut: 3.0)")

    args = parser.parse_args()

    # Expansion des cibles
    try:
        hosts = expand_hosts(args)
    except Exception as e:
        print(f"Erreur IP : {e}")
        sys.exit(2)

    try:
        ports = expand_ports(args)
    except Exception as e:
        print(f"Erreur port : {e}")
        sys.exit(2)

    total = len(hosts) * len(ports)
    print(f"Scan de {len(hosts)} IP(s) x {len(ports)} port(s) = {total} cibles | concurrence: {args.concurrency} | timeout: {args.timeout}s")
    print(f"IPs   : {hosts[0]} -> {hosts[-1]}")
    print(f"Ports : {ports[0]} -> {ports[-1]}")
    print("=" * 60)

    try:
        results = asyncio.run(scan(hosts, ports, args.concurrency, args.timeout))
    except KeyboardInterrupt:
        print("\nScan interrompu par l'utilisateur.")
        sys.exit(1)

    # --- Résumé ---
    print("\n" + "=" * 60)
    print(f"  RÉSUMÉ — {len(results)} serveur(s) trouvé(s) sur {total} cibles scannées")
    print("=" * 60)

    if results:
        # Trier par IP puis par port
        results.sort(key=lambda r: (r["host"], r["port"]))
        for r in results:
            names = ", ".join(r["sample"]) if r["sample"] else "aucun"
            print(f"  {r['host']}:{r['port']}  |  v{r['version']}  |  {r['online']}/{r['max']} joueurs  |  MOTD: {r['motd']}")
            if r["sample"]:
                print(f"    -> Joueurs connectés : {names}")
    else:
        print("  Aucun serveur Minecraft détecté.")

    print()


if __name__ == "__main__":
    main()
