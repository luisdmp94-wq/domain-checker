import requests


def check_http_redirect(domain):
    print(f"\nVerificando redireccion HTTP->HTTPS de {domain}:")
    try:
        r = requests.get(f"http://{domain}", timeout=5, allow_redirects=False)
        if r.status_code in [301, 302, 307, 308]:
            location = r.headers.get('Location', '')
            if location.startswith('https://'):
                print(f"  OK: Redirige a HTTPS ({r.status_code})")
                return {"redirige": True, "status": r.status_code, "destino": location}
            else:
                print(f"  ALERTA: Redirige pero NO a HTTPS - {location}")
                return {"redirige": False, "status": r.status_code, "destino": location}
        else:
            print(f"  ALERTA: No redirige a HTTPS (status {r.status_code})")
            return {"redirige": False, "status": r.status_code}
    except Exception as e:
        print(f"  Error: {e}")
        return {"error": str(e)}