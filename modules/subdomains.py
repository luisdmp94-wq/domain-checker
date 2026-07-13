import socket


def find_subdomains(domain):
    subdomains = ["www", "api", "mail", "admin", "dev", "staging", "app", "portal", "test", "vpn"]
    found = []
    print(f"\nBuscando subdominios de {domain}:")
    for sub in subdomains:
        target = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(target)
            print(f"  ENCONTRADO  {target} -> {ip}")
            found.append({"subdominio": target, "ip": ip})
        except socket.gaierror:
            pass
    if not found:
        print("  No se encontraron subdominios comunes")
    return found