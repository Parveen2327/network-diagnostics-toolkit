from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
import csv
from datetime import datetime
import socket

protocol_map = {
    1: "ICMP",
    6: "TCP",
    17: "UDP"
}

def get_hostname(ip):

    try:
        return socket.gethostbyaddr(ip)[0]

    except:
        return "Unknown"


def start_sniffer():

    tcp_count = 0
    udp_count = 0
    icmp_count = 0

    # Create CSV file and header
    with open("packet_logs.csv", "w", newline="") as file:
        writer = csv.writer(file)

        writer.writerow([
            "Timestamp",
            "Source IP",
            "Destination IP",
            "Protocol",
            "Source Port",
            "Destination Port",
            "Packet Size"
        ])

    def process_packet(packet):

        nonlocal tcp_count
        nonlocal udp_count
        nonlocal icmp_count

        if IP in packet:

            protocol = protocol_map.get(
                packet[IP].proto,
                "OTHER"
            )

            if protocol == "TCP":
                tcp_count += 1

            elif protocol == "UDP":
                udp_count += 1

            elif protocol == "ICMP":
                icmp_count += 1

            src_port = "-"
            dst_port = "-"

            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport

            elif UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport

            src_host = get_hostname(packet[IP].src)
            dst_host = get_hostname(packet[IP].dst)

            # Save packet to CSV
            with open("packet_logs.csv", "a", newline="") as file:
                writer = csv.writer(file)

                writer.writerow([
                    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    packet[IP].src,
                    packet[IP].dst,
                    protocol,
                    src_port,
                    dst_port,
                    len(packet)
                ])

            print("\n========== Packet ==========")

            print(
                "Source IP        :",
                packet[IP].src,
                f"({src_host})"
            )

            print(
                "Destination IP   :",
                packet[IP].dst,
                f"({dst_host})"
            )

            print("Protocol         :", protocol)
            print("Source Port      :", src_port)
            print("Destination Port :", dst_port)
            print("Packet Size      :", len(packet), "bytes")

    print("Capturing 10 packets...\n")

    sniff(
        prn=process_packet,
        count=10
    )

    print("\n===== Traffic Summary =====")
    print("TCP  :", tcp_count)
    print("UDP  :", udp_count)
    print("ICMP :", icmp_count)

    print("\nPacket logs saved to packet_logs.csv")