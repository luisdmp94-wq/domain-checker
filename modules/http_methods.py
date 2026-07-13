import requests


def check_http_methods(domain):
    print(f"\nVerificando metodos HTTP de {domain}:")
    dangerous_methods = ["PUT", "DELETE", "TRACE", "CONNECT", "PATCH", "OPTIONS"]
    results = []
    for method in dangerous_methods:
        try:
            r = requests.request(method, f"https://{domain}/", timeout=5)
            if r.status_code not in [405, 501, 403]:
                print(f"  ALERTA  {method} permitido - Status {r.status_code}")
                results.append({"metodo": method, "status": r.status_code})
            else:
                print(f"  OK  {method} bloqueado - Status {r.status_code}")
        except:
            pass
    if not results:
        print(f"  OK: No se detectaron metodos peligrosos habilitados")
    return results