#!/usr/bin/env python3
"""
port-range.py — Scan a port range on one IP for Minecraft servers.

Usage:
  python3 port-range.py --ip 13.36.117.199 --start-port 25560 --end-port 25600
"""

import asyncio
import json
import struct
import argparse

# ------------------ VarInt helpers ------------------
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

# ------------------ Build handshake + status ------------------
def build_handshake(host: str, port: int, protocol_version: int = 754) -> bytes:
    payload = (
        encode_varint(protocol_version)
        + encode_varint(len(host)) + host.encode("utf-8")
        + struct.pack(">H", port)
        + encode_varint(1)
    )
    return pack_packet(0x00, payload)

def build_status_request() -> bytes:
    return pack_packet(0x00, b"")

# ------------------ Query ------------------
async def read_varint(reader: asyncio.StreamReader, timeout: float):
    result = 0
    shift = 0
    while True:
        b = await asyncio.wait_for(reader.readexactly(1), timeout=timeout)
        byte = b[0]
        result |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            break
        shift += 7
    return result

async def query_minecraft(host: str, port: int, timeout: float = 2.5):
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
    except Exception:
        return None

    try:
        writer.write(build_handshake(host, port))
        writer.write(build_status_request())
        await writer.drain()

        await read_varint(reader, timeout)  # packet length
        await read_varint(reader, timeout)  # packet id
        str_len = await read_varint(reader, timeout)
        data = await asyncio.wait_for(reader.readexactly(str_len), timeout=timeout)
        j = json.loads(data.decode("utf-8", errors="ignore"))
        return j
    except Exception:
        return None
    finally:
        writer.close()
        await writer.wait_closed()

# ------------------ Scan ports ------------------
async def scan_ports(ip: str, start: int, end: int, concurrency: int = 200):
    sem = asyncio.Semaphore(concurrency)
    results = []

    async def worker(port: int):
        async with sem:
            data = await query_minecraft(ip, port)
            if data:
                motd = ""
                desc = data.get("description", {})
                if isinstance(desc, dict):
                    motd = desc.get("text", "")
                    if "extra" in desc:
                        motd += "".join([p.get("text", "") for p in desc["extra"]])
                elif isinstance(desc, str):
                    motd = desc
                players = data.get("players", {})
                online, maxp = players.get("online", 0), players.get("max", 0)
                print(f"[✅ FOUND] {ip}:{port} — MOTD: {motd.strip()} — {online}/{maxp} players")
                results.append({
                    "port": port,
                    "motd": motd.strip(),
                    "online": online,
                    "max": maxp,
                    "sample": [p.get("name") for p in players.get("sample", [])] if "sample" in players else []
                })
            else:
                print(f"[❌] {ip}:{port} — no response")

    await asyncio.gather(*(worker(p) for p in range(start, end + 1)))
    return results

# ------------------ Main ------------------
def main():
    parser = argparse.ArgumentParser(description="Scan a range of ports on one IP for Minecraft servers")
    parser.add_argument("--ip", required=True, help="IP or hostname to scan")
    parser.add_argument("--start-port", type=int, required=True)
    parser.add_argument("--end-port", type=int, required=True)
    parser.add_argument("--concurrency", type=int, default=200)
    parser.add_argument("--timeout", type=float, default=2.5)
    args = parser.parse_args()

    print(f"🔎 Scanning {args.ip} ports {args.start_port}-{args.end_port} ...")
    results = asyncio.run(scan_ports(args.ip, args.start_port, args.end_port, args.concurrency))

    print("\n--- Résumé ---")
    if results:
        for r in results:
            print(f"{args.ip}:{r['port']} — {r['online']}/{r['max']} — MOTD: {r['motd']}")
    else:
        print("Aucun serveur Minecraft détecté.")

if __name__ == "__main__":
    main()
