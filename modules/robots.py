import requests


def check_robots_and_sitemap(domain):
    print(f"\nAnalizando robots.txt y sitemap de {domain}:")
    result = {"robots": None, "sitemap": None, "rutas_interesantes": []}
    keywords = ["admin", "login", "api", "dashboard", "backup", "config", "secret", "private", "internal", "dev"]
    try:
        r = requests.get(f"https://{domain}/robots.txt", timeout=5)
        if r.status_code == 200:
            result["robots"] = r.text[:500]
            print(f"  robots.txt: ENCONTRADO")
            lines = r.text.split('\n')
            for line in lines:
                for keyword in keywords:
                    if keyword in line.lower() and ('disallow' in line.lower() or 'allow' in line.lower()):
                        print(f"  INTERESANTE: {line.strip()}")
                        result["rutas_interesantes"].append(line.strip())
        else:
            print(f"  robots.txt: No encontrado ({r.status_code})")
    except Exception as e:
        print(f"  robots.txt: Error - {e}")
    try:
        r = requests.get(f"https://{domain}/sitemap.xml", timeout=5)
        if r.status_code == 200:
            result["sitemap"] = "Encontrado"
            print(f"  sitemap.xml: ENCONTRADO")
        else:
            print(f"  sitemap.xml: No encontrado ({r.status_code})")
    except Exception as e:
        print(f"  sitemap.xml: Error - {e}")
    return result