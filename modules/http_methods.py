import requests


def check_http_methods(domain):
    print(f"\nVerificando metodos HTTP de {domain}:")
    dangerous_methods = ["PUT", "DELETE", "TRACE", "CONNECT", "PATCH"]
    results = []

    for method in dangerous_methods:
        try:
            r = requests.request(method, f"https://{domain}/", timeout=5)

            if 200 <= r.status_code < 300:
                print(f"  REVISAR  {method} respondio - Status {r.status_code}")
                results.append({"metodo": method, "status": r.status_code})
            else:
                print(f"  OK  {method} no habilitado - Status {r.status_code}")

        except requests.RequestException as exc:
            print(f"  ERROR  {method}: {exc}")

    if not results:
        print("  OK: No se detectaron metodos peligrosos habilitados")

    return results
