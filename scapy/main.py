from scapy.all import sniff, IP, TCP

def packet_callback(packet):
    """Обработка TCP SYN пакетов."""
    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]

        if tcp_layer.flags == 0x02:
            print(f"[SYN] IP {packet[IP].src}:{tcp_layer.sport} -> {packet[IP].dst}:{tcp_layer.dport}")


bpf_filter = "tcp[tcpflags] == 2"

sniff(filter=bpf_filter, prn=packet_callback, store=0)
