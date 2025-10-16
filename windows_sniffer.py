import argparse
import datetime as dt
import os
import sys
from typing import Optional

try:
    from scapy.all import sniff, get_if_list, conf, Ether, IP, IPv6, TCP, UDP, ICMP, Raw, wrpcap
except Exception as e:
    print("[!] Failed to import scapy. Install it via 'pip install scapy'. Error:", e, file=sys.stderr)
    sys.exit(1)


def hexdump_block(data: bytes, width: int = 16) -> str:
    """Return a classic hex+ASCII view of bytes."""
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i+width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
        lines.append(f"{i:04x}  {hex_part:<{width*3}}  {ascii_part}")
    return "\n".join(lines)


def proto_name(pkt) -> str:
    if pkt.haslayer(TCP):
        return "TCP"
    if pkt.haslayer(UDP):
        return "UDP"
    if pkt.haslayer(ICMP):
        return "ICMP"
    if pkt.haslayer(IP) or pkt.haslayer(IPv6):
        return "IP"
    return pkt.lastlayer().name if pkt is not None else "UNKNOWN"


def fmt_time(ts: float) -> str:
    return dt.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def packet_summary(pkt) -> str:
    ts = fmt_time(pkt.time)
    eth = pkt.getlayer(Ether)
    src_mac = eth.src if eth else "?"
    dst_mac = eth.dst if eth else "?"

    ip_src = ip_dst = "-"
    l3 = None
    if pkt.haslayer(IP):
        l3 = pkt[IP]
        ip_src, ip_dst = l3.src, l3.dst
    elif pkt.haslayer(IPv6):
        l3 = pkt[IPv6]
        ip_src, ip_dst = l3.src, l3.dst

    summary = [f"[{ts}] {proto_name(pkt)} {ip_src} -> {ip_dst}"]
    if pkt.haslayer(TCP):
        t = pkt[TCP]
        flags = t.flags
        flstr = ''.join([
            'F' if 'F' in flags else '',
            'S' if 'S' in flags else '',
            'R' if 'R' in flags else '',
            'P' if 'P' in flags else '',
            'A' if 'A' in flags else '',
            'U' if 'U' in flags else '',
            'E' if 'E' in flags else '',
            'C' if 'C' in flags else '',
        ])
        summary.append(f" TCP {t.sport} -> {t.dport} flags={flstr or 'NONE'} seq={t.seq} ack={t.ack}")
    elif pkt.haslayer(UDP):
        u = pkt[UDP]
        summary.append(f" UDP {u.sport} -> {u.dport} len={u.len}")
    elif pkt.haslayer(ICMP):
        i = pkt[ICMP]
        summary.append(f" ICMP type={i.type} code={i.code}")

    # Ethernet at the end (optional)
    summary.append(f"  (eth {src_mac} -> {dst_mac})")
    return "".join(summary)


def on_packet(pkt, args, pcap_buffer: Optional[list]):
    try:
        print(packet_summary(pkt))
        if args.show_hex and pkt.haslayer(Raw):
            data = bytes(pkt[Raw].load)
            if data:
                print("-- Payload (hex+ASCII) --")
                print(hexdump_block(data))
        elif args.show_bytes and pkt.haslayer(Raw):
            data = bytes(pkt[Raw].load)
            if data:
                print("-- Payload (bytes) --\n" + ' '.join(f"\\x{b:02x}" for b in data))

        if pcap_buffer is not None:  # write later in batch
            pcap_buffer.append(pkt)

    except Exception as e:
        print(f"[!] Error processing packet: {e}", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description="Windows Packet Sniffer (Scapy)")
    parser.add_argument("-i", "--interface", help="Interface name (use --list-ifaces to see options)")
    parser.add_argument("-f", "--filter", default=None, help="BPF filter, e.g. 'tcp or udp or icmp' or 'port 53'")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 = infinite)")
    parser.add_argument("--list-ifaces", action="store_true", help="List available interfaces and exit")
    parser.add_argument("--show-hex", action="store_true", help="Show payload in hex+ASCII (if present)")
    parser.add_argument("--show-bytes", action="store_true", help="Show payload as \\x.. bytes (if present)")
    parser.add_argument("--pcap", default=None, help="Write captured packets to this .pcap file")
    args = parser.parse_args()

    if args.list_ifaces:
        print("Available interfaces:")
        for name in get_if_list():
            print(" -", name)
        return

    # Scapy on Windows: ensure Npcap is used
    conf.use_pcap = True  # prefer pcap backend on Windows

    if args.interface is None:
        # Choose a default interface if user didn't provide one
        if_list = get_if_list()
        if not if_list:
            print("[!] No interfaces found. Ensure Npcap is installed and run as Administrator.", file=sys.stderr)
            sys.exit(2)
        print(f"[i] No interface provided, using default: {if_list[0]}")
        iface = if_list[0]
    else:
        iface = args.interface

    # Prepare pcap buffer if requested
    pcap_buffer = [] if args.pcap else None

    print("[i] Starting capture...")
    print(f"    Interface: {iface}")
    print(f"    Filter   : {args.filter or '(none)'}")
    print(f"    Count    : {args.count or '∞'}\n")

    try:
        sniff(
            iface=iface,
            filter=args.filter,
            prn=lambda pkt: on_packet(pkt, args, pcap_buffer),
            store=False,
            count=args.count if args.count > 0 else 0
        )
    except PermissionError:
        print("[!] Permission denied. Run PowerShell/Terminal as Administrator.", file=sys.stderr)
        sys.exit(1)
    except OSError as e:
        print(f"[!] OS error during sniff: {e}. If this is Windows, make sure Npcap is installed.", file=sys.stderr)
        sys.exit(1)
    finally:
        if args.pcap and pcap_buffer:
            try:
                wrpcap(args.pcap, pcap_buffer)
                print(f"\n[i] Wrote {len(pcap_buffer)} packets to {args.pcap}")
            except Exception as e:
                print(f"[!] Failed to write PCAP: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()
