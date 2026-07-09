import socket
import sys
import requests
import json
import ssl
import builtwith
import nmap
import subprocess
import dns.resolver
import re
from datetime import datetime

WAFW00F_PATH = r"C:\Users\Luisd\AppData\Local\Python\pythoncore-3.14-64\Scripts\wafw00f.exe"

def get_ip(domain):
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except socket.gaierror:
        return "No se pudo resolver el dominio"

def get_headers(domain):
    try:
        response = requests.get(f"https://{domain}", timeout=5)
        return dict(response.headers)
    except requests.RequestException:
        return {}

def check_security_headers(headers):
    security_headers = {
        "Strict-Transport-Security": "HSTS - fuerza HTTPS",
        "Content-Security-Policy": "CSP - previene XSS",
        "X-Frame-Options": "Proteccion contra clickjacking",
        "X-Content-Type-Options": "Previene MIME sniffing",
        "Referrer-Policy": "Controla informacion del referrer",
        "Permissions-Policy": "Controla permisos del navegador",
        "X-XSS-Protection": "Proteccion XSS legacy"
    }
    results = {}
    print("\nAnalisis de cabeceras de seguridad:")
    for header, description in security_headers.items():
        present = header.lower() in [h.lower() for h in headers.keys()]
        results[header] = {"presente": present, "descripcion": description}
        status = "OK" if present else "FALTA"
        print(f"  {status}  {header} - {description}")
    return results

def find_subdomains(domain):
    subdomains = ["www", "api", "mail", "admin", "dev", "staging", "app", "portal", "test", "vpn"]
    found = []
    print(f"\nBuscando subdominios de {domain}:")
    for sub in subdomains:
        target = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(target)
            print(f"  ENCONTRADO  {target} -> {ip}")
            found.append({"subdominio": target, "ip": ip})
        except socket.gaierror:
            pass
    if not found:
        print("  No se encontraron subdominios comunes")
    return found

def check_ssl(domain):
    print(f"\nAnalizando SSL de {domain}:")
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                expiry = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                days_left = (expiry - datetime.now()).days
                issuer = dict(x[0] for x in cert['issuer'])
                subject = dict(x[0] for x in cert['subject'])
                print(f"  Emisor: {issuer.get('organizationName', 'Desconocido')}")
                print(f"  Dominio: {subject.get('commonName', 'Desconocido')}")
                print(f"  Expira: {expiry.strftime('%Y-%m-%d')} ({days_left} dias restantes)")
                if days_left < 30:
                    print(f"  ALERTA: Certificado expira en menos de 30 dias")
                else:
                    print(f"  OK: Certificado valido")
                return {
                    "emisor": issuer.get('organizationName'),
                    "expira": expiry.strftime('%Y-%m-%d'),
                    "dias_restantes": days_left,
                    "valido": days_left > 0
                }
    except Exception as e:
        print(f"  Error SSL: {e}")
        return {"error": str(e)}

def detect_technologies(domain):
    print(f"\nDetectando tecnologias de {domain}:")
    try:
        info = builtwith.parse(f"https://{domain}")
        if info:
            for category, techs in info.items():
                print(f"  {category}: {', '.join(techs)}")
        else:
            print("  No se detectaron tecnologias")
        return info
    except Exception as e:
        print(f"  Error: {e}")
        return {}

def scan_ports(ip):
    print(f"\nEscaneando puertos de {ip}:")
    try:
        nm = nmap.PortScanner()
        nm.scan(ip, '21,22,23,25,80,443,3306,3389,5432,8080,8443', '-T4')
        open_ports = []
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in ports:
                    state = nm[host][proto][port]['state']
                    service = nm[host][proto][port]['name']
                    if state == 'open':
                        print(f"  ABIERTO  {port}/{proto} - {service}")
                        open_ports.append({"puerto": port, "protocolo": proto, "servicio": service})
        if not open_ports:
            print("  No se encontraron puertos abiertos en el rango analizado")
        return open_ports
    except Exception as e:
        print(f"  Error: {e}")
        return []

def detect_waf(domain):
    print(f"\nDetectando WAF de {domain}:")
    try:
        result = subprocess.run(
            [WAFW00F_PATH, f"https://{domain}"],
            capture_output=True, text=True, timeout=30
        )
        output = result.stdout
        if "is behind" in output:
            lines = [l for l in output.split('\n') if "is behind" in l]
            waf_name = lines[0].strip() if lines else "WAF detectado"
            print(f"  WAF detectado: {waf_name}")
            return {"detectado": True, "nombre": waf_name}
        elif "No WAF" in output or "not behind" in output:
            print(f"  No se detecto WAF")
            return {"detectado": False, "nombre": None}
        else:
            print(f"  No se pudo determinar")
            return {"detectado": None, "nombre": None}
    except Exception as e:
        print(f"  Error: {e}")
        return {"error": str(e)}

def check_dns_records(domain):
    print(f"\nAnalizando registros DNS de {domain}:")
    records = {}
    spf_found = False
    dmarc_found = False
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        records['MX'] = [str(r.exchange) for r in mx_records]
        print(f"  MX: {', '.join(records['MX'])}")
    except:
        records['MX'] = []
        print(f"  MX: No encontrado")
    try:
        ns_records = dns.resolver.resolve(domain, 'NS')
        records['NS'] = [str(r) for r in ns_records]
        print(f"  NS: {', '.join(records['NS'])}")
    except:
        records['NS'] = []
        print(f"  NS: No encontrado")
    try:
        txt_records = dns.resolver.resolve(domain, 'TXT')
        records['TXT'] = [str(r) for r in txt_records]
        for txt in records['TXT']:
            if 'v=spf1' in txt:
                spf_found = True
                print(f"  SPF: OK - {txt[:60]}...")
            if 'v=DMARC1' in txt:
                dmarc_found = True
                print(f"  DMARC: OK")
        if not spf_found:
            print(f"  SPF: FALTA - riesgo de email spoofing")
        if not dmarc_found:
            print(f"  DMARC: verificando subdominio...")
    except:
        records['TXT'] = []
    try:
        dmarc_records = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
        dmarc_found = True
        records['DMARC'] = [str(r) for r in dmarc_records]
        print(f"  DMARC: OK")
    except:
        if not dmarc_found:
            records['DMARC'] = []
            print(f"  DMARC: FALTA - riesgo de email spoofing")
    records['spf_presente'] = spf_found
    records['dmarc_presente'] = dmarc_found
    return records

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

def check_sensitive_files(domain):
    print(f"\nBuscando archivos sensibles en {domain}:")
    sensitive_files = [
        ".env", ".env.backup", ".env.local",
        "config.php", "wp-config.php", "config.js",
        "backup.zip", "backup.sql", "database.sql",
        ".git/config", ".git/HEAD",
        "phpinfo.php", "info.php",
        "admin.php", "login.php",
        "composer.json", "package.json",
        ".htaccess", "web.config",
        "debug.log", "error.log"
    ]
    found = []
    for file in sensitive_files:
        try:
            r = requests.get(f"https://{domain}/{file}", timeout=5, allow_redirects=False)
            if r.status_code == 200:
                print(f"  ENCONTRADO  /{file} (200 OK) - {len(r.content)} bytes")
                found.append({"archivo": file, "status": r.status_code, "bytes": len(r.content)})
            elif r.status_code == 403:
                print(f"  BLOQUEADO   /{file} (403 Forbidden)")
        except:
            pass
    if not found:
        print(f"  No se encontraron archivos sensibles accesibles")
    return found

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

def check_cookies(domain):
    print(f"\nAnalizando cookies de {domain}:")
    try:
        r = requests.get(f"https://{domain}", timeout=5)
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

def check_http_methods(domain):
    print(f"\nVerificando metodos HTTP de {domain}:")
    dangerous_methods = ["PUT", "DELETE", "TRACE", "CONNECT", "PATCH", "OPTIONS"]
    results = []
    for method in dangerous_methods:
        try:
            r = requests.request(method, f"https://{domain}/", timeout=5)
            if r.status_code not in [405, 501, 403]:
                print(f"  ALERTA  {method} permitido - Status {r.status_code}")
                results.append({"metodo": method, "status": r.status_code})
            else:
                print(f"  OK  {method} bloqueado - Status {r.status_code}")
        except:
            pass
    if not results:
        print(f"  OK: No se detectaron metodos peligrosos habilitados")
    return results

def check_source_code(domain):
    print(f"\nAnalizando codigo fuente de {domain}:")
    findings = []
    
    patterns = {
        "email": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        "ip_interna": r'(?:10\.|192\.168\.|172\.(?:1[6-9]|2[0-9]|3[01])\.)\d{1,3}\.\d{1,3}',
        "api_key": r'(?:api[_-]?key|apikey|api[_-]?token)["\s]*[:=]["\s]*([a-zA-Z0-9_\-]{20,})',
        "aws_key": r'AKIA[0-9A-Z]{16}',
        "token": r'(?:token|secret|password)["\s]*[:=]["\s]*["\']([a-zA-Z0-9_\-]{8,})["\']',
        "comentario": r'<!--.*?-->',
        "todo": r'(?:TODO|FIXME|HACK|XXX|BUG).*',
    }
    
    try:
        r = requests.get(f"https://{domain}", timeout=5)
        html = r.text
        
        for pattern_name, pattern in patterns.items():
            matches = re.findall(pattern, html, re.IGNORECASE | re.DOTALL)
            if matches:
                unique_matches = list(set(matches))[:5]
                for match in unique_matches:
                    match_str = match[:100] if isinstance(match, str) else str(match)[:100]
                    print(f"  ENCONTRADO  {pattern_name}: {match_str}")
                    findings.append({"tipo": pattern_name, "valor": match_str})
        
        if not findings:
            print(f"  No se encontro informacion sensible en el codigo fuente")
    
    except Exception as e:
        print(f"  Error: {e}")
    
    return findings


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
    if report['http_methods']:
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
def generate_markdown(report):
    domain = report['dominio']
    fecha = report['fecha']
    ip = report['ip']
    ssl_info = report['ssl']
    security = report['cabeceras_seguridad']
    subdomains = report['subdominios']
    techs = report['tecnologias']
    ports = report['puertos']
    waf = report['waf']
    dns_info = report['dns']
    robots = report['robots_sitemap']
    sensitive = report['archivos_sensibles']
    redirect = report['http_redirect']
    cookies = report['cookies']
    cors = report['cors']
    methods = report['http_methods']
    source = report['codigo_fuente']

    ok = [h for h, v in security.items() if v['presente']]
    missing = [h for h, v in security.items() if not v['presente']]
    cookie_issues = [c for c in cookies if c.get('problemas')]

    if len(missing) == 0 and not sensitive and not cookie_issues and not cors and not methods and not source:
        risk = "BAJO"
    elif len(missing) <= 3 and not sensitive:
        risk = "MEDIO"
    else:
        risk = "ALTO"

    waf_text = waf.get('nombre') if waf.get('detectado') else "No detectado"
    redirect_text = "OK - Redirige a HTTPS" if redirect.get('redirige') else "ALERTA - No redirige a HTTPS"

    md = f"""# Informe de Seguridad - {domain}

**Fecha:** {fecha}
**IP:** {ip}
**Riesgo general:** {risk}
**WAF:** {waf_text}
**HTTP->HTTPS:** {redirect_text}

---

## SSL / HTTPS

- **Emisor:** {ssl_info.get('emisor', 'N/A')}
- **Expira:** {ssl_info.get('expira', 'N/A')}
- **Dias restantes:** {ssl_info.get('dias_restantes', 'N/A')}
- **Estado:** {'OK' if ssl_info.get('valido') else 'ALERTA'}

---

## Informacion Sensible en Codigo Fuente

{chr(10).join(f'- {s["tipo"].upper()}: {s["valor"]}' for s in source) if source else '- No se encontro informacion sensible'}

---

## CORS

{chr(10).join(f'- {c["problema"].upper()}: {c["endpoint"]}' for c in cors) if cors else '- OK: Sin problemas CORS'}

---

## Metodos HTTP Peligrosos

{chr(10).join(f'- ALERTA: {m["metodo"]} habilitado (status {m["status"]})' for m in methods) if methods else '- OK: Sin metodos peligrosos'}

---

## Cookies

{chr(10).join(f'- {c["nombre"]}: {", ".join(c["problemas"]) if c["problemas"] else "OK"}' for c in cookies) if cookies else '- No se encontraron cookies'}

---

## Registros DNS

- **SPF:** {'OK' if dns_info.get('spf_presente') else 'FALTA'}
- **DMARC:** {'OK' if dns_info.get('dmarc_presente') else 'FALTA'}
- **MX:** {', '.join(dns_info.get('MX', [])) or 'No encontrado'}

---

## Archivos Sensibles

{chr(10).join(f'- ENCONTRADO: /{f["archivo"]}' for f in sensitive) if sensitive else '- Ninguno encontrado'}

---

## Robots.txt

- **robots.txt:** {'Encontrado' if robots.get('robots') else 'No encontrado'}
{chr(10).join(f'- INTERESANTE: {r}' for r in robots.get('rutas_interesantes', []))}

---

## Cabeceras de Seguridad

### Presentes
{chr(10).join(f'- {h}' for h in ok) if ok else '- Ninguna'}

### Faltantes
{chr(10).join(f'- {h}' for h in missing) if missing else '- Ninguna'}

---

## Puertos Abiertos

{chr(10).join(f'- {p["puerto"]}/{p["protocolo"]} - {p["servicio"]}' for p in ports) if ports else '- Ninguno'}

---

## Subdominios

{chr(10).join(f'- {s["subdominio"]} -> {s["ip"]}' for s in subdomains) if subdomains else '- Ninguno'}

---

## Tecnologias

{chr(10).join(f'- **{cat}:** {", ".join(t)}' for cat, t in techs.items()) if techs else '- No detectadas'}

---

*Informe generado automaticamente por domain-checker*
"""
    filename = f"report_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
    with open(filename, "w", encoding="utf-8") as f:
        f.write(md)
    print(f"\nInforme Markdown guardado en: {filename}")

def save_report(data, domain):
    filename = f"report_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"Reporte JSON guardado en: {filename}")

def main():
    if len(sys.argv) < 2:
        print("Uso: python domain-checker.py <dominio>")
        sys.exit(1)
    
    domain = sys.argv[1]
    print(f"\nAnalizando: {domain}")
    
    ip = get_ip(domain)
    print(f"IP: {ip}")
    
    headers = get_headers(domain)
    security = check_security_headers(headers)
    subdomains = find_subdomains(domain)
    ssl_info = check_ssl(domain)
    technologies = detect_technologies(domain)
    ports = scan_ports(ip)
    waf = detect_waf(domain)
    dns_info = check_dns_records(domain)
    robots_sitemap = check_robots_and_sitemap(domain)
    sensitive_files = check_sensitive_files(domain)
    http_redirect = check_http_redirect(domain)
    cookies = check_cookies(domain)
    cors = check_cors(domain)
    http_methods = check_http_methods(domain)
    source_code = check_source_code(domain)
    risk_score = calculate_risk_score({"cabeceras_seguridad": security, "ssl": ssl_info, "waf": waf, "http_redirect": http_redirect, "archivos_sensibles": sensitive_files, "cors": cors, "http_methods": http_methods, "dns": dns_info, "codigo_fuente": source_code})
    
    report = {
        "dominio": domain,
        "fecha": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ip": ip,
        "ssl": ssl_info,
        "cabeceras_seguridad": security,
        "subdominios": subdomains,
        "tecnologias": technologies,
        "puertos": ports,
        "waf": waf,
        "dns": dns_info,
        "robots_sitemap": robots_sitemap,
        "archivos_sensibles": sensitive_files,
        "http_redirect": http_redirect,
        "cookies": cookies,
        "cors": cors,
        "http_methods": http_methods,
        "codigo_fuente": source_code
    }
    
    save_report(report, domain)
    generate_markdown(report)

if __name__ == "__main__":
    main()


