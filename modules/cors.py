import requests


def check_cors(domain):
    print(f"\nAnalizando CORS de {domain}:")
    results = []
    test_origins = [
        f"https://evil.com",
        f"https://attacker.com",
        f"null",
        f"https://{domain}.evil.com",
    ]
    endpoints = [
        f"https://{domain}/",
        f"https://api.{domain}/",
    ]
    for endpoint in endpoints:
        for origin in test_origins:
            try:
                r = requests.get(endpoint, headers={"Origin": origin}, timeout=5)
                acao = r.headers.get('Access-Control-Allow-Origin', '')
                acac = r.headers.get('Access-Control-Allow-Credentials', '')
                if acao == '*':
                    print(f"  ALERTA  {endpoint} - CORS wildcard (*) detectado")
                    results.append({"endpoint": endpoint, "origen": origin, "problema": "wildcard *", "credentials": acac})
                elif acao == origin:
                    if acac.lower() == 'true':
                        print(f"  CRITICO  {endpoint} - Refleja origen {origin} con credentials=true")
                        results.append({"endpoint": endpoint, "origen": origin, "problema": "refleja origen con credentials", "credentials": acac})
                    else:
                        print(f"  MEDIO  {endpoint} - Refleja origen {origin}")
                        results.append({"endpoint": endpoint, "origen": origin, "problema": "refleja origen", "credentials": acac})
                elif acao == 'null' and origin == 'null':
                    print(f"  ALERTA  {endpoint} - Acepta origen null")
                    results.append({"endpoint": endpoint, "origen": origin, "problema": "acepta null origin", "credentials": acac})
            except:
                pass
    if not results:
        print(f"  OK: No se detectaron problemas CORS")
    return results