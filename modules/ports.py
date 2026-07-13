import nmap


def scan_ports(ip):
    print(f"\nEscaneando puertos de {ip}:")
    try:
        nm = nmap.PortScanner()
        nm.scan(ip, '21,22,23,25,80,443,3306,3389,5432,8080,8443', '-T4')
        open_ports = []
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in ports:
                    state = nm[host][proto][port]['state']
                    service = nm[host][proto][port]['name']
                    if state == 'open':
                        print(f"  ABIERTO  {port}/{proto} - {service}")
                        open_ports.append({"puerto": port, "protocolo": proto, "servicio": service})
        if not open_ports:
            print("  No se encontraron puertos abiertos en el rango analizado")
        return open_ports
    except Exception as e:
        print(f"  Error: {e}")
        return []