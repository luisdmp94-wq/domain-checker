import requests


def check_cookies(domain):
    print(f"\nAnalizando cookies de {domain}:")
    try:
        r = requests.get(f"https://{domain}/login", timeout=5, allow_redirects=True)
        cookies = r.cookies
        results = []
        if not cookies:
            print(f"  No se encontraron cookies")
            return results
        for cookie in cookies:
            issues = []
            if not cookie.secure:
                issues.append("sin Secure flag")
            if not cookie.has_nonstandard_attr('HttpOnly'):
                issues.append("sin HttpOnly flag")
            if not cookie.has_nonstandard_attr('SameSite'):
                issues.append("sin SameSite flag")
            if issues:
                print(f"  ALERTA  {cookie.name}: {', '.join(issues)}")
            else:
                print(f"  OK  {cookie.name}: bien configurada")
            results.append({
                "nombre": cookie.name,
                "secure": cookie.secure,
                "problemas": issues
            })
        return results
    except Exception as e:
        print(f"  Error: {e}")
        return []