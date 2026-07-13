

def calculate_risk_score(report):
    print(f"\nCalculando puntuacion de riesgo...")
    score = 100
    issues = []

    # Cabeceras de seguridad (-5 por cada una que falta)
    missing_headers = [h for h, v in report['cabeceras_seguridad'].items() if not v['presente']]
    score -= len(missing_headers) * 5
    for h in missing_headers:
        issues.append(f"Cabecera faltante: {h}")

    # SSL (-20 si expira en menos de 30 dias)
    ssl = report['ssl']
    if ssl.get('dias_restantes', 999) < 30:
        score -= 20
        issues.append("Certificado SSL expira pronto")

    # Sin WAF (-10)
    if not report['waf'].get('detectado'):
        score -= 10
        issues.append("Sin WAF detectado")

    # Sin redireccion HTTPS (-15)
    if not report['http_redirect'].get('redirige'):
        score -= 15
        issues.append("No redirige HTTP a HTTPS")

    # Archivos sensibles (-25 por cada uno)
    for f in report['archivos_sensibles']:
        score -= 25
        issues.append(f"Archivo sensible expuesto: {f['archivo']}")

    # CORS problemas (-15)
    cors_criticos = [c for c in report['cors'] if 'credentials' in c.get('problema', '')]
    if cors_criticos:
        score -= 15
        issues.append("CORS critico con credentials detectado")

    # Metodos HTTP peligrosos (-10)
    real_dangerous = [m for m in report['http_methods'] if not (m['metodo'] == 'CONNECT' and m['status'] == 400)]
    if real_dangerous:
        score -= 10
        issues.append("Metodos HTTP peligrosos habilitados")

    # DNS faltante (-10)
    if not report['dns'].get('spf_presente'):
        score -= 10
        issues.append("SPF faltante - riesgo email spoofing")
    if not report['dns'].get('dmarc_presente'):
        score -= 10
        issues.append("DMARC faltante - riesgo email spoofing")

    # Informacion sensible en codigo (-10)
    sensitive_findings = [s for s in report['codigo_fuente'] if s['tipo'] in ['api_key', 'aws_key', 'token', 'ip_interna']]
    if sensitive_findings:
        score -= 10
        issues.append("Informacion sensible en codigo fuente")

    severidad_puntos = {"CRITICAL": 30, "HIGH": 20, "MEDIUM": 10, "LOW": 5}
    for p in report.get("exposed_paths", []):
        sev = p.get("severidad", "LOW")
        score -= severidad_puntos.get(sev, 5)
        issues.append("Path expuesto [" + sev + "]: " + p["path"] + " - " + p["descripcion"])
    # API endpoints expuestos sin auth
    severidad_api = {"CRITICAL": 40, "HIGH": 25, "MEDIUM": 10}
    for ep in report.get("api_endpoints", []):
        sev = ep.get("severidad", "HIGH")
        score -= severidad_api.get(sev, 10)
        issues.append(f"API endpoint expuesto [{sev}]: {ep['path']} - {ep['descripcion']}")
    score = max(0, score)

    if score >= 80:
        nivel = "BAJO"
    elif score >= 60:
        nivel = "MEDIO"
    elif score >= 40:
        nivel = "ALTO"
    else:
        nivel = "CRITICO"

    print(f"  Puntuacion: {score}/100 - Riesgo {nivel}")
    for issue in issues:
        print(f"  - {issue}")

    return {"score": score, "nivel": nivel, "issues": issues}