#!/usr/bin/env python3
"""
ip-range.py — Scan IP range / CIDR for Minecraft servers and print MOTD + players

Usage examples:
  python3 ip-range.py --cidr 192.168.1.0/24
  python3 ip-range.py --start 10.0.0.1 --end 10.0.0.254 --port 25565 --concurrency 200
"""

import asyncio
import argparse
import ipaddress
import json
import struct
import sys
from typing import Optional

# ------------------ VarInt helpers (Minecraft protocol) ------------------
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

def decode_varint_from_buffer(buf: bytes, offset: int = 0):
    num_read = 0
    result = 0
    while True:
        if offset + num_read >= len(buf):
            raise ValueError("Buffer ended while reading varint")
        read = buf[offset + num_read]
        value = read & 0x7F
        result |= (value << (7 * num_read))
        num_read += 1
        if not (read & 0x80):
            break
        if num_read > 5:
            raise ValueError("VarInt too big")
    return result, num_read

def pack_packet(packet_id: int, payload: bytes = b"") -> bytes:
    packet = encode_varint(packet_id) + payload
    return encode_varint(len(packet)) + packet

# ------------------ Build handshake + status request ------------------
def build_handshake(host: str, port: int, protocol_version: int = 754) -> bytes:
    # Handshake structure:
    # VarInt: protocol version | String: server address | Unsigned Short: server port | VarInt: next state (1=status)
    payload = b""
    payload += encode_varint(protocol_version)
    # Write server address as: VarInt length + bytes (Minecraft uses a string prefixed with varint length)
    host_bytes = host.encode('utf-8')
    payload += encode_varint(len(host_bytes)) + host_bytes
    payload += struct.pack('>H', port)
    payload += encode_varint(1)  # Next state = 1 (status)
    return pack_packet(0x00, payload)

def build_status_request() -> bytes:
    return pack_packet(0x00, b"")

# ------------------ Network read helpers ------------------
async def read_exactly(reader: asyncio.StreamReader, n: int, timeout: float):
    try:
        data = await asyncio.wait_for(reader.readexactly(n), timeout=timeout)
        return data
    except asyncio.IncompleteReadError:
        raise
    except asyncio.TimeoutError:
        raise

async def read_varint_async(reader: asyncio.StreamReader, timeout: float):
    result = 0
    num_read = 0
    while True:
        b = await asyncio.wait_for(reader.readexactly(1), timeout=timeout)
        byte = b[0]
        result |= (byte & 0x7F) << (7 * num_read)
        num_read += 1
        if not (byte & 0x80):
            break
        if num_read > 5:
            raise ValueError("VarInt too big")
    return result

# ------------------ Query single server ------------------
async def query_minecraft(host: str, port: int = 25565, timeout: float = 3.0) -> Optional[dict]:
    """
    Returns parsed JSON status dict if server responded, else None.
    """
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
    except Exception:
        return None

    try:
        # Send handshake + status request
        writer.write(build_handshake(host, port))
        writer.write(build_status_request())
        await writer.drain()

        # Read packet length (varint)
        packet_length = await read_varint_async(reader, timeout)
        # Read packet id (varint)
        packet_id = await read_varint_async(reader, timeout)
        # Remaining payload length = packet_length - bytes_of_packetid (but we already read packet_id via varint)
        # Easiest: read the rest as bytes of length (packet_length - size_of_packetid_read)
        # But we don't directly know how many bytes were consumed for packet_id because we read varint streamwise.
        # Alternative simplified approach: after reading packet_length and packet_id, read until we get JSON string varint length + data.
        # Read varint string length:
        str_len = await read_varint_async(reader, timeout)
        # Now read the JSON bytes:
        json_bytes = await read_exactly(reader, str_len, timeout)
        text = json_bytes.decode('utf-8', errors='replace')
        data = json.loads(text)
        return data
    except Exception:
        return None
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

# ------------------ Main scanning logic ------------------
async def worker(queue: asyncio.Queue, sem: asyncio.Semaphore, port: int, timeout: float, results: list):
    while True:
        host = await queue.get()
        if host is None:
            queue.task_done()
            break
        async with sem:
            data = await query_minecraft(str(host), port=port, timeout=timeout)
            if data:
                motd = ""
                # Parse motd: can be a dict or string in different server versions
                if isinstance(data.get("description"), dict):
                    # legacy: description may be { "text": "...", ... } or with "extra"
                    # Try to handle simple cases
                    desc = data["description"]
                    if "text" in desc:
                        motd = desc["text"]
                    elif "extra" in desc and isinstance(desc["extra"], list):
                        motd = "".join(part.get("text", "") for part in desc["extra"])
                    else:
                        motd = json.dumps(desc, ensure_ascii=False)
                else:
                    motd = data.get("description", "") or ""

                # players
                players = data.get("players", {})
                online = players.get("online")
                maxp = players.get("max")
                sample = players.get("sample", [])
                sample_names = [p.get("name") for p in sample] if isinstance(sample, list) else []

                results.append({
                    "host": str(host),
                    "port": port,
                    "motd": motd.strip() if isinstance(motd, str) else str(motd),
                    "online": online,
                    "max": maxp,
                    "sample": sample_names
                })
                print(f"[FOUND] {host}:{port} — MOTD: {motd!r} — players: {online}/{maxp} — sample: {sample_names}")
        queue.task_done()

async def scan_hosts(hosts, port: int, concurrency: int, timeout: float):
    queue = asyncio.Queue()
    for h in hosts:
        queue.put_nowait(h)
    # Add sentinel for workers to exit
    workers = []
    sem = asyncio.Semaphore(concurrency)
    results = []
    num_workers = min(concurrency, 500)
    for _ in range(num_workers):
        queue.put_nowait(None)  # sentinel per worker

    for _ in range(num_workers):
        w = asyncio.create_task(worker(queue, sem, port, timeout, results))
        workers.append(w)

    await queue.join()
    for w in workers:
        w.cancel()
    return results

def expand_hosts_from_args(args):
    if args.cidr:
        net = ipaddress.ip_network(args.cidr, strict=False)
        return list(net.hosts())
    elif args.start and args.end:
        start = int(ipaddress.ip_address(args.start))
        end = int(ipaddress.ip_address(args.end))
        if end < start:
            raise SystemExit("end IP must be >= start IP")
        return [ipaddress.ip_address(ip) for ip in range(start, end + 1)]
    elif args.ip:
        return [ipaddress.ip_address(args.ip)]
    else:
        raise SystemExit("No IP range provided")

def main():
    parser = argparse.ArgumentParser(description="Scan IP range for Minecraft servers and display MOTD + players")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--cidr", help="CIDR range to scan, e.g. 192.168.1.0/24")
    group.add_argument("--start", help="Start IP (inclusive)")
    parser.add_argument("--end", help="End IP (inclusive) — used with --start")
    group.add_argument("--ip", help="Single IP to check")
    parser.add_argument("--port", type=int, default=25565, help="Minecraft server port (default 25565)")
    parser.add_argument("--concurrency", type=int, default=200, help="Number of concurrent connections (default 200)")
    parser.add_argument("--timeout", type=float, default=3.0, help="Connection / read timeout in seconds (default 3.0)")
    args = parser.parse_args()

    try:
        hosts = expand_hosts_from_args(args)
    except Exception as e:
        print("Invalid IP input:", e)
        sys.exit(2)

    print(f"Scanning {len(hosts)} hosts on port {args.port} with concurrency {args.concurrency} ... (CTRL+C to stop)")
    try:
        results = asyncio.run(scan_hosts(hosts, args.port, args.concurrency, args.timeout))
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
        sys.exit(1)

    if results:
        print("\n--- Summary ---")
        for r in results:
            print(f"{r['host']}:{r['port']} — {r['online']}/{r['max']} — MOTD: {r['motd']}")
    else:
        print("\nNo Minecraft servers found in the scanned range.")

if __name__ == "__main__":
    main()
