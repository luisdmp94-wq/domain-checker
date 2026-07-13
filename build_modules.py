import re

content = open('domain-checker.py', 'r', encoding='utf-8').read()

# Mapa de funcion -> archivo destino
MODULE_MAP = {
    'get_ip': ('modules/ip.py', ['import socket']),
    'get_headers': ('modules/headers.py', ['import requests']),
    'check_security_headers': ('modules/headers.py', []),
    'find_subdomains': ('modules/subdomains.py', ['import socket']),
    'check_ssl': ('modules/ssl_check.py', ['import ssl', 'import socket', 'from datetime import datetime']),
    'detect_technologies': ('modules/technologies.py', ['import builtwith']),
    'scan_ports': ('modules/ports.py', ['import nmap']),
    'detect_waf': ('modules/waf.py', ['import subprocess']),
    'check_dns_records': ('modules/dns_check.py', ['import dns.resolver']),
    'check_robots_and_sitemap': ('modules/robots.py', ['import requests']),
    'check_sensitive_files': ('modules/sensitive_files.py', ['import requests']),
    'check_http_redirect': ('modules/http_redirect.py', ['import requests']),
    'check_cookies': ('modules/cookies.py', ['import requests']),
    'check_cors': ('modules/cors.py', ['import requests']),
    'check_http_methods': ('modules/http_methods.py', ['import requests']),
    'check_source_code': ('modules/source_code.py', ['import requests', 're']),
    'scan_js_files': ('modules/js_scanner.py', ['import requests', 'import re']),
    'check_email_spoofing': ('modules/email_spoofing.py', ['import dns.resolver']),
    'check_server_info': ('modules/server_info.py', ['import requests']),
    'check_shodan': ('modules/shodan_check.py', ['import requests']),
    'check_subdomain_takeover': ('modules/subdomain_takeover.py', ['import requests']),
    'check_cves': ('modules/cves.py', ['import requests']),
    'check_open_redirect': ('modules/open_redirect.py', ['import requests', 'from urllib.parse import urlparse']),
    'check_csrf': ('modules/csrf.py', ['import requests', 're']),
    'check_subdomain_headers': ('modules/subdomain_headers.py', ['import requests']),
    'check_exposed_paths': ('modules/exposed_paths.py', ['import requests']),
    'check_api_endpoints': ('modules/api_endpoints.py', ['import requests']),
    'calculate_risk_score': ('core/risk_score.py', []),
    'generate_html': ('reporting/html_report.py', ['from datetime import datetime']),
    'generate_markdown': ('reporting/markdown_report.py', ['from datetime import datetime']),
    'save_report': ('reporting/json_report.py', ['import json', 'from datetime import datetime']),
}

# Extraer funciones
def extract_function(content, func_name):
    pattern = rf'(^def {func_name}\(.*?(?=^def |\Z))'
    match = re.search(pattern, content, re.MULTILINE | re.DOTALL)
    if match:
        return match.group(1).rstrip()
    return None

# Agrupar por archivo
files = {}
for func_name, (filepath, imports) in MODULE_MAP.items():
    func_code = extract_function(content, func_name)
    if not func_code:
        print(f'WARNING: {func_name} no encontrada')
        continue
    if filepath not in files:
        files[filepath] = {'imports': set(), 'functions': []}
    for imp in imports:
        files[filepath]['imports'].add(imp)
    files[filepath]['functions'].append(func_code)

# Escribir archivos
for filepath, data in files.items():
    lines = []
    for imp in sorted(data['imports']):
        if imp.startswith('import') or imp.startswith('from'):
            lines.append(imp)
        else:
            lines.append(f'import {imp}')
    lines.append('')
    lines.append('')
    lines.extend(data['functions'])
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))
    print(f'Creado: {filepath}')

print('Done')
