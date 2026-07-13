import requests


def check_subdomain_headers(subdomains):
    print(f"\nAnalizando cabeceras de seguridad en subdominios:")
    findings = []
    
    security_headers = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options"
    ]
    
    for sub in subdomains[:5]:
        target = sub["subdominio"]
        try:
            r = requests.get(f"https://{target}", timeout=5, allow_redirects=True)
            missing = []
            for header in security_headers:
                if header.lower() not in [h.lower() for h in r.headers.keys()]:
                    missing.append(header)
            
            if missing:
                print(f"  FALTA  {target}: {', '.join(missing)}")
                findings.append({"subdominio": target, "cabeceras_faltantes": missing})
            else:
                print(f"  OK  {target}: todas las cabeceras presentes")
        except:
            print(f"  ERROR  {target}: no accesible")
    
    return findings