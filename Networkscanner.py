import socket
import nmap
from datetime import datetime



def network_scan(target, start_port, end_port):
    print(f"\n[+] Starting network scan for target: {target}...")
    start_time = datetime.now()

    open_ports = port_scan(target, start_port, end_port)

    if open_ports:
        print(f"\n[+] Open ports found: {open_ports}")
    else:
        print("\n[-] No open ports found")

    
    for port in open_ports:
        banner = banner_grab(target, port)
        if banner:
            print(f"[+] Banner for {target}:{port} -> {banner}")
        else:
            print(f"[-] No banner found for {target}:{port}")

    
    vuln_info = vulnerability_scan(target)

    if vuln_info:
        print("\n[+] Nmap Scan Results:")

        if 'hostnames' in vuln_info:
            print(f"Hostnames: {vuln_info['hostnames']}")

        if 'osmatch' in vuln_info:
            print(f"Operating Systems: {vuln_info['osmatch']}")

        if 'vulns' in vuln_info:
            print(f"Vulnerabilities: {vuln_info['vulns']}")
        else:
            print("No vulnerabilities found")

    end_time = datetime.now()
    print(f"\n[+] Scan completed in {end_time - start_time}")



def port_scan(target, start_port, end_port):
    print(f"\n[+] Scanning ports {start_port} to {end_port} on {target}")

    open_ports = []

    for port in range(start_port, end_port + 1):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)

            result = sock.connect_ex((target, port))
            if result == 0:
                print(f"[+] Port {port} is OPEN")
                open_ports.append(port)

            sock.close()

        except Exception as e:
            pass

    return open_ports



def banner_grab(target, port):
    print(f"[+] Grabbing banner for {target}:{port}")

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((target, port))

        banner = sock.recv(1024).decode('utf-8', errors='ignore')
        sock.close()

        return banner.strip()

    except:
        return None



def vulnerability_scan(target):
    print(f"\n[+] Running Nmap scan on {target}...")

    try:
        nm = nmap.PortScanner()

        # -sV → service version detection
        # -O → OS detection
        nm.scan(target, arguments='-sV -O')

        result = {}

        if target in nm.all_hosts():
            host = nm[target]

            result['hostnames'] = host.hostname()

            if 'osmatch' in host:
                result['osmatch'] = host['osmatch']

            # Extract open ports + services
            vulns = []
            for proto in host.all_protocols():
                ports = host[proto].keys()
                for port in ports:
                    service = host[proto][port]
                    vulns.append({
                        "port": port,
                        "service": service.get('name'),
                        "product": service.get('product'),
                        "version": service.get('version')
                    })

            result['vulns'] = vulns

        return result

    except Exception as e:
        print(f"[-] Nmap scan failed: {e}")
        return None


# 🔹 Entry Point
if __name__ == "__main__":
    target_ip = input("Enter the target IP or Hostname: ")
    start_port = int(input("Enter the starting port: "))
    end_port = int(input("Enter the ending port: "))

    network_scan(target_ip, start_port, end_port)