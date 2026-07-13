from datetime import datetime
import socket
import ssl


def check_ssl(domain):
    print(f"\nAnalizando SSL de {domain}:")
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                expiry = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                days_left = (expiry - datetime.now()).days
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