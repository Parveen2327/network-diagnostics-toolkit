import socket

services = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS"
}

def scan_ports(host):

    start_port = int(input("Start Port: "))
    end_port = int(input("End Port: "))

    print(f"\nScanning {host} from {start_port} to {end_port}...\n")

    open_ports = 0

    for port in range(start_port, end_port + 1):

        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        sock.settimeout(0.5)

        result = sock.connect_ex(
            (host, port)
        )

        if result == 0:

            service = services.get(
                port,
                "Unknown"
            )

            print(
                f"Port {port} : OPEN ({service})"
            )

            open_ports += 1

        sock.close()

    print(f"\nTotal Open Ports Found: {open_ports}")