from ping_tool import ping_host
from traceroute import traceroute_host
from packet_analyzer import start_sniffer
from port_scanner import scan_ports

while True:

    print("\n===== Network Diagnostics Toolkit =====")
    print("1. Ping Host")
    print("2. Traceroute")
    print("3. Packet Analyzer")
    print("4. Port Scanner")
    print("5. Exit")

    choice = input("\nEnter Choice: ")

    if choice == "1":

        host = input("Enter Host: ")
        ping_host(host)

    elif choice == "2":

        host = input("Enter Host: ")
        traceroute_host(host)

    elif choice == "3":

        start_sniffer()

    elif choice == "4":

        host = input("Enter Host: ")
        scan_ports(host)

    elif choice == "5":

        print("Exiting...")
        break

    else:

        print("Invalid Choice")