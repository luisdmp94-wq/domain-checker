from urllib.parse import urlparse
import requests


def check_open_redirect(domain):
    print(f"\nBuscando open redirects en {domain}:")
    findings = []

    payloads = [
        f"https://{domain}/redirect?url=https://evil.com",
        f"https://{domain}/redirect?next=https://evil.com",
        f"https://{domain}/redirect?to=https://evil.com",
        f"https://{domain}/login?redirect=https://evil.com",
        f"https://{domain}/login?next=https://evil.com",
        f"https://{domain}/logout?redirect=https://evil.com",
        f"https://{domain}/out?url=https://evil.com",
        f"https://{domain}/?url=https://evil.com",
        f"https://{domain}/?next=https://evil.com",
        f"https://{domain}/?return=https://evil.com",
    ]

    for url in payloads:
        try:
            # Seguir todos los redirects y ver el destino final
            r = requests.get(url, timeout=5, allow_redirects=True, stream=True)
            final_url = r.url

            # Verificar que el DOMINIO de destino final es evil.com
            from urllib.parse import urlparse as _urlparse
            final_domain = _urlparse(final_url).netloc
            if final_domain == "evil.com" or final_domain.endswith(".evil.com"):
                print(f"  VULNERABLE  Open redirect confirmado: {url}")
                print(f"  Destino final: {final_url}")
                findings.append({
                    "url": url,
                    "destino_final": final_url,
                    "confirmado": True
                })
            else:
                # Verificar el primer redirect por si hay filtros intermedios
                r2 = requests.get(url, timeout=5, allow_redirects=False)
                if r2.status_code in [301, 302, 307, 308]:
                    location = r2.headers.get("Location", "")
                    # Solo reportar si evil.com aparece en location Y
                    # el dominio de destino no es el mismo que el origen
                    if "evil.com" in location:
                        try:
                            from urllib.parse import urlparse
                            dest = urlparse(location)
                            src = urlparse(url)
                            if dest.netloc and dest.netloc != src.netloc:
                                print(f"  VULNERABLE  Open redirect (1 hop): {url}")
                                print(f"  Location: {location}")
                                findings.append({
                                    "url": url,
                                    "destino_final": location,
                                    "confirmado": False
                                })
                        except:
                            pass
        except:
            pass

    if not findings:
        print(f"  OK: No se detectaron open redirects")

    return findings