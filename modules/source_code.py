import requests
import re


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
        r = requests.get(f"https://{domain}/login", timeout=5, allow_redirects=True)
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