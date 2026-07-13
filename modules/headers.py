import requests


def get_headers(domain):
    try:
        response = requests.get(f"https://{domain}", timeout=5)
        return dict(response.headers)
    except requests.RequestException:
        return {}
def check_security_headers(headers):
    security_headers = {
        "Strict-Transport-Security": "HSTS - fuerza HTTPS",
        "Content-Security-Policy": "CSP - previene XSS",
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
        print(f"  {status}  {header} - {description}")
    return results