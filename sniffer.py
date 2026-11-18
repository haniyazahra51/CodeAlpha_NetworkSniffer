#!/usr/bin/env python3
"""CodeAlpha Task 1: Basic Network Sniffer (educational use, on networks you own or are authorized to test)."""
import argparse
from datetime import datetime
from scapy.all import sniff, wrpcap, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, Raw

captured = []
stats = {}


def payload_preview(pkt, limit=60):
    if pkt.haslayer(Raw):
        data = bytes(pkt[Raw].load)[:limit]
        return "".join(chr(b) if 32 <= b < 127 else "." for b in data)
    return ""


def handle(pkt):
    captured.append(pkt)
    ts = datetime.now().strftime("%H:%M:%S")

    if pkt.haslayer(ARP):
        proto, src, dst, extra = "ARP", pkt[ARP].psrc, pkt[ARP].pdst, ""
    elif pkt.haslayer(IP) or pkt.haslayer(IPv6):
        ip = pkt[IP] if pkt.haslayer(IP) else pkt[IPv6]
        src, dst = ip.src, ip.dst
        if pkt.haslayer(TCP):
            proto = "TCP"
            extra = f"{pkt[TCP].sport} -> {pkt[TCP].dport} flags={pkt[TCP].flags}"
        elif pkt.haslayer(UDP):
            proto = "DNS" if pkt.haslayer(DNS) else "UDP"
            extra = f"{pkt[UDP].sport} -> {pkt[UDP].dport}"
            if pkt.haslayer(DNS) and pkt[DNS].qd:
                extra += f" query={pkt[DNS].qd.qname.decode(errors='ignore')}"
        elif pkt.haslayer(ICMP):
            proto, extra = "ICMP", f"type={pkt[ICMP].type}"
        else:
            proto, extra = "OTHER", ""
    else:
        return

    stats[proto] = stats.get(proto, 0) + 1
    print(f"[{ts}] {proto:<5} {src} -> {dst} | {extra} | len={len(pkt)}")
    preview = payload_preview(pkt)
    if preview:
        print(f"         payload: {preview}")


def main():
    p = argparse.ArgumentParser(description="Basic network sniffer")
    p.add_argument("-i", "--iface", help="interface (default: auto)")
    p.add_argument("-c", "--count", type=int, default=0, help="packets to capture (0 = until Ctrl+C)")
    p.add_argument("-f", "--filter", default="", help="BPF filter, e.g. 'tcp port 80'")
    p.add_argument("-w", "--write", help="save capture to .pcap file")
    a = p.parse_args()

    print("Sniffing... press Ctrl+C to stop (needs root/admin).")
    try:
        sniff(iface=a.iface, count=a.count, filter=a.filter, prn=handle, store=False)
    except KeyboardInterrupt:
        pass
    except PermissionError:
        print("Run with sudo / as Administrator.")
        return

    print("\n--- Summary ---")
    for proto, n in sorted(stats.items(), key=lambda x: -x[1]):
        print(f"{proto}: {n}")
    if a.write and captured:
        wrpcap(a.write, captured)
        print(f"Saved {len(captured)} packets to {a.write}")


if __name__ == "__main__":
    main()
