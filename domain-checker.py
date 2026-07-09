import socket
import sys
import requests
import json
import ssl
from datetime import datetime

def get_ip(domain):
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except socket.gaierror:
        return "No se pudo resolver el dominio"

def get_headers(domain):
    try:
        response = requests.get(f"https://{domain}", timeout=5)
        return dict(response.headers)
    except requests.RequestException:
        return {}

def check_security_headers(headers):
    security_headers = {
        "Strict-Transport-Security": "HSTS — fuerza HTTPS",
        "Content-Security-Policy": "CSP — previene XSS",
        "X-Frame-Options": "Proteccion contra clickjacking",
        "X-Content-Type-Options": "Previene MIME sniffing",
        "Referrer-Policy": "Controla informacion del referrer",
        "Permissions-Policy": "Controla permisos del navegador",
        "X-XSS-Protection": "Proteccion XSS legacy"
    }
    
    results = {}
    print("\nAnalisis de cabeceras de seguridad:")
    for header, description in security_headers.items():
        present = header.lower() in [h.lower() for h in headers.keys()]
        results[header] = {"presente": present, "descripcion": description}
        status = "OK" if present else "FALTA"
        print(f"  {status}  {header} — {description}")
    
    return results

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

def check_ssl(domain):
    print(f"\nAnalizando SSL de {domain}:")
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                
                expiry = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                days_left = (expiry - datetime.utcnow()).days
                
                issuer = dict(x[0] for x in cert['issuer'])
                subject = dict(x[0] for x in cert['subject'])
                
                print(f"  Emisor: {issuer.get('organizationName', 'Desconocido')}")
                print(f"  Dominio: {subject.get('commonName', 'Desconocido')}")
                print(f"  Expira: {expiry.strftime('%Y-%m-%d')} ({days_left} dias restantes)")
                
                if days_left < 30:
                    print(f"  ALERTA: Certificado expira en menos de 30 dias")
                else:
                    print(f"  OK: Certificado valido")
                
                return {
                    "emisor": issuer.get('organizationName'),
                    "expira": expiry.strftime('%Y-%m-%d'),
                    "dias_restantes": days_left,
                    "valido": days_left > 0
                }
    except Exception as e:
        print(f"  Error SSL: {e}")
        return {"error": str(e)}

def save_report(data, domain):
    filename = f"report_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"\nReporte guardado en: {filename}")

def main():
    if len(sys.argv) < 2:
        print("Uso: python domain-checker.py <dominio>")
        sys.exit(1)
    
    domain = sys.argv[1]
    print(f"\nAnalizando: {domain}")
    
    ip = get_ip(domain)
    print(f"IP: {ip}")
    
    headers = get_headers(domain)
    security = check_security_headers(headers)
    subdomains = find_subdomains(domain)
    ssl_info = check_ssl(domain)
    
    report = {
        "dominio": domain,
        "fecha": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ip": ip,
        "ssl": ssl_info,
        "cabeceras_seguridad": security,
        "subdominios": subdomains
    }
    
    save_report(report, domain)

if __name__ == "__main__":
    main()
