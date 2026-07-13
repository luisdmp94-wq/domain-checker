import requests
import re

def check_ct_logs(domain):
    print(f"\nBuscando subdominios via recon pasivo ({domain}):")
    found = []

    # Fuente 1: RapidDNS
    try:
        r = requests.get(
            f"https://rapiddns.io/subdomain/{domain}?full=1&down=1",
            timeout=15,
            headers={"User-Agent": "Mozilla/5.0 (security-research)"}
        )
        if r.status_code == 200:
            subdomains = re.findall(rf'<td>([a-zA-Z0-9\-\.]+\.{re.escape(domain)})</td>', r.text)
            subdomains = list(set(subdomains))
            for sub in sorted(subdomains):
                if sub not in found:
                    found.append(sub)
            print(f"  RapidDNS: {len(subdomains)} subdominios encontrados")
    except Exception as e:
        print(f"  RapidDNS error: {e}")

    # Fuente 2: crt.sh (fallback)
    if not found:
        try:
            r = requests.get(
                f"https://crt.sh/?q=%.{domain}&output=json",
                timeout=20,
                headers={"User-Agent": "Mozilla/5.0 (security-research)"}
            )
            if r.status_code == 200:
                data = r.json()
                subdomains = set()
                for entry in data:
                    name = entry.get("name_value", "")
                    for sub in name.split("\n"):
                        sub = sub.strip().lower()
                        if sub.endswith(f".{domain}") and "*" not in sub:
                            subdomains.add(sub)
                found = sorted(subdomains)
                print(f"  crt.sh: {len(found)} subdominios encontrados")
        except Exception as e:
            print(f"  crt.sh error: {e}")

    # Mostrar resultados
    for sub in found:
        print(f"  ENCONTRADO  {sub}")

    if not found:
        print("  No se encontraron subdominios via recon pasivo")

    return found
