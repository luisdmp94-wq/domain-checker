import requests


def check_subdomain_takeover(subdomains):
    print(f"\nVerificando subdomain takeover:")
    
    vulnerable_fingerprints = {
        "GitHub Pages": ["There isn't a GitHub Pages site here", "For root URLs"],
        "Heroku": ["No such app", "herokucdn.com"],
        "AWS S3": ["NoSuchBucket", "The specified bucket does not exist"],
        "Shopify": ["Sorry, this shop is currently unavailable"],
        "Fastly": ["Fastly error: unknown domain"],
        "Ghost": ["The thing you were looking for is no longer here"],
        "Surge": ["project not found"],
        "Tumblr": ["Whatever you were looking for doesn't live here"],
        "WordPress": ["Do you want to register"],
        "Zendesk": ["Help Center Closed"],
        "Pantheon": ["404 error unknown site"],
        "Azure": ["404 Web Site not found"]
    }
    
    vulnerable = []
    
    for sub in subdomains:
        target = sub["subdominio"]
        try:
            r = requests.get(f"https://{target}", timeout=5, allow_redirects=True)
            for service, fingerprints in vulnerable_fingerprints.items():
                for fingerprint in fingerprints:
                    if fingerprint.lower() in r.text.lower():
                        print(f"  VULNERABLE  {target} - Posible takeover de {service}")
                        vulnerable.append({"subdominio": target, "servicio": service})
                        break
        except:
            pass
    
    if not vulnerable:
        print(f"  OK: No se detectaron subdominios vulnerables a takeover")
    
    return vulnerable