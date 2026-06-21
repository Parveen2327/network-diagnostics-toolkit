from scapy.all import IP, ICMP, sr1

def traceroute_host(host):

    print(f"\nTracing route to {host}\n")

    for ttl in range(1, 20):

        packet = IP(
            dst=host,
            ttl=ttl
        ) / ICMP()

        reply = sr1(
            packet,
            timeout=2,
            verbose=0
        )

        if reply is None:

            print(ttl, "*")

        else:

            print(ttl, reply.src)

            if reply.src == host:
                break