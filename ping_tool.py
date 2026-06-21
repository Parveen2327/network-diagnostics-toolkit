import subprocess

def ping_host(host):

    print(f"\nPinging {host}...\n")

    result = subprocess.run(
        ["ping", host],
        capture_output=True,
        text=True
    )

    print(result.stdout)