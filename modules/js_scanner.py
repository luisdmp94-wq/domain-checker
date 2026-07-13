import re
import requests


def scan_js_files(domain):
    import re as _re
    print(f"\nEscaneando archivos JavaScript de {domain}:")
    findings = []
    try:
        r = requests.get(f"https://{domain}/login", timeout=5, allow_redirects=True)
        html = r.text
        # Extraer JS desde tags src= y desde headers link:
        js_pattern_html = r'src=["\'"]([^"\'"]+\.js[^"\'"]*)["\'"]' 
        js_files = _re.findall(js_pattern_html, html)
        # Tambien buscar en header link: (preload)
        link_header = r.headers.get("link", "")
        link_pattern = r'<([^>]+\.js[^>]*)>'''
        js_files += _re.findall(link_pattern, link_header)
        js_urls = []
        for js in js_files[:10]:
            if js.startswith("http"):
                js_urls.append(js)
            elif js.startswith("//"):
                js_urls.append(f"https:{js}")
            elif js.startswith("/"):
                js_urls.append(f"https://{domain}{js}")
            else:
                js_urls.append(f"https://{domain}/{js}")
        print(f"  Encontrados {len(js_urls)} archivos JS")
        patterns = {
            "aws_key": r'AKIA[0-9A-Z]{16}(?![0-9A-Z])',
            "gcp_key": r'AIza[0-9A-Za-z_\-]{35}(?![0-9A-Za-z_\-])',
            "github_token": r'gh[pousr]_[0-9A-Za-z]{36,}',
            "jwt_token": r'eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+',
            "api_key": r'(?:api[_-]?key|apikey|x-api-key)\s*[:=]\s*["\']([ a-zA-Z0-9_\-]{32,})["\']',
            "secret": r'(?:client_secret|app_secret|auth_secret)\s*[:=]\s*["\'"]([a-zA-Z0-9_\-]{16,})["\']',
            "endpoint": r'["\'][/](?:api|graphql|rest|v[0-9]+)[/][a-zA-Z0-9/_\-]{4,}["\']',
            "ip_interna": r'(?:10\.|192\.168\.|172\.(?:1[6-9]|2[0-9]|3[01])\.)\d{1,3}\.\d{1,3}',
        }
        FP_KEYWORDS = {
            "onetimepassword", "placeholder", "example", "your_key",
            "your_secret", "insert_here", "xxxxxxxxxx", "aaaaaaaaa",
            "undefined", "null", "false", "true", "function", "return"
        }
        for js_url in js_urls:
            try:
                js_r = requests.get(js_url, timeout=5)
                js_content = js_r.text
                for pattern_name, pattern in patterns.items():
                    matches = _re.findall(pattern, js_content, _re.IGNORECASE)
                    if not matches:
                        continue
                    unique = list(set(matches))[:3]
                    for match in unique:
                        match_str = match[:80] if isinstance(match, str) else str(match)[:80]
                        match_lower = match_str.lower()
                        if any(fp in match_lower for fp in FP_KEYWORDS):
                            print(f"  SKIP FP  {pattern_name}: {match_str[:40]}")
                            continue
                        if pattern_name == "endpoint":
                            if _re.search(r'[(){}\[\]<>+*=;,]', match_str):
                                continue
                            if len(match_str) < 8:
                                continue
                        if pattern_name == "aws_key":
                            if not _re.search(r'AKIA[0-9A-Z]{16}', match_str):
                                continue
                        print(f"  ENCONTRADO  {pattern_name} en {js_url.split('/')[-1]}: {match_str}")
                        findings.append({"tipo": pattern_name, "archivo": js_url.split('/')[-1], "valor": match_str})
            except:
                pass
        if not findings:
            print(f"  No se encontro informacion sensible en archivos JS")
    except Exception as e:
        print(f"  Error: {e}")
    return findings, js_urls