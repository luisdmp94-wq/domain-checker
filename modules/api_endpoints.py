import requests


def check_api_endpoints(domain):
    print(f"\nBuscando endpoints de API expuestos en {domain}:")
    import re as _re

    ENDPOINTS = [
        {"path": "/api/v1/users", "severidad": "HIGH", "descripcion": "Lista de usuarios expuesta"},
        {"path": "/api/v1/user", "severidad": "HIGH", "descripcion": "Datos de usuario expuestos"},
        {"path": "/api/v1/admin", "severidad": "CRITICAL", "descripcion": "Endpoint admin sin autenticacion"},
        {"path": "/api/v1/config", "severidad": "CRITICAL", "descripcion": "Configuracion expuesta"},
        {"path": "/api/v1/settings", "severidad": "HIGH", "descripcion": "Settings expuestos"},
        {"path": "/api/v1/keys", "severidad": "CRITICAL", "descripcion": "API keys expuestas"},
        {"path": "/api/v1/tokens", "severidad": "CRITICAL", "descripcion": "Tokens expuestos"},
        {"path": "/api/v1/accounts", "severidad": "HIGH", "descripcion": "Cuentas expuestas"},
        {"path": "/api/v1/payments", "severidad": "CRITICAL", "descripcion": "Datos de pago expuestos"},
        {"path": "/api/v1/invoices", "severidad": "HIGH", "descripcion": "Facturas expuestas"},
        {"path": "/api/v2/users", "severidad": "HIGH", "descripcion": "Lista de usuarios v2 expuesta"},
        {"path": "/api/v2/admin", "severidad": "CRITICAL", "descripcion": "Endpoint admin v2 sin autenticacion"},
        {"path": "/api/v2/config", "severidad": "CRITICAL", "descripcion": "Configuracion v2 expuesta"},
        {"path": "/api/v2/accounts", "severidad": "HIGH", "descripcion": "Cuentas v2 expuestas"},
        {"path": "/api/v2/payments", "severidad": "CRITICAL", "descripcion": "Datos de pago v2 expuestos"},
        {"path": "/api/internal/users", "severidad": "CRITICAL", "descripcion": "API interna de usuarios expuesta"},
        {"path": "/api/internal/config", "severidad": "CRITICAL", "descripcion": "API interna de config expuesta"},
        {"path": "/api/internal/admin", "severidad": "CRITICAL", "descripcion": "API interna admin expuesta"},
        {"path": "/v1/users", "severidad": "HIGH", "descripcion": "Usuarios sin prefijo api expuestos"},
        {"path": "/v1/admin", "severidad": "CRITICAL", "descripcion": "Admin sin prefijo api expuesto"},
        {"path": "/v2/users", "severidad": "HIGH", "descripcion": "Usuarios v2 sin prefijo expuestos"},
        {"path": "/rest/v1/users", "severidad": "HIGH", "descripcion": "REST usuarios expuestos"},
        {"path": "/rest/v1/admin", "severidad": "CRITICAL", "descripcion": "REST admin expuesto"},
    ]

    # Indicadores de datos sensibles en respuesta
    SENSITIVE_PATTERNS = [
        r'"email"',
        r'"password"',
        r'"token"',
        r'"api_key"',
        r'"secret"',
        r'"users"',
        r'"admin"',
        r'"role"',
        r'"id"',
    ]

    found = []
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (security-research)",
        "Accept": "application/json",
        "Content-Type": "application/json"
    })

    for entry in ENDPOINTS:
        url = f"https://{domain}{entry['path']}"
        try:
            response = session.get(url, timeout=5, allow_redirects=False)

            # Solo nos interesan respuestas 200 sin autenticacion
            if response.status_code != 200:
                continue

            body = response.text
            content_type = response.headers.get("Content-Type", "")

            # Verificar que devuelve JSON o datos reales
            if not any(ct in content_type for ct in ["json", "text/plain", "application/xml"]):
                # Puede ser HTML de login redirect - no es finding real
                if "<html" in body.lower() or "<!doctype" in body.lower():
                    print(f"  SKIP  {entry['path']} (200 pero devuelve HTML)")
                    continue

            # Buscar datos sensibles en la respuesta
            datos_sensibles = []
            for pattern in SENSITIVE_PATTERNS:
                if _re.search(pattern, body, _re.IGNORECASE):
                    match = _re.search(pattern, body, _re.IGNORECASE)
                    if match:
                        datos_sensibles.append(match.group(0)[:50])

            resultado = {
                "path": entry["path"],
                "url_completa": url,
                "severidad": entry["severidad"],
                "descripcion": entry["descripcion"],
                "status_code": response.status_code,
                "content_type": content_type,
                "datos_sensibles": datos_sensibles,
                "evidencia": body[:300].strip()
            }

            found.append(resultado)
            print(f"  EXPUESTO [{entry['severidad']}]  {entry['path']} - {entry['descripcion']}")
            if datos_sensibles:
                print(f"    Datos sensibles: {datos_sensibles[0][:60]}")

        except requests.RequestException:
            pass

    if not found:
        print("  No se encontraron endpoints de API expuestos sin autenticacion")

    return found