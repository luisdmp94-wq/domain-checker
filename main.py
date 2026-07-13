import sys
from modules.ip import get_ip
from modules.headers import get_headers, check_security_headers
from modules.subdomains import find_subdomains
from modules.ssl_check import check_ssl
from modules.technologies import detect_technologies
from modules.ports import scan_ports
from modules.waf import detect_waf
from modules.dns_check import check_dns_records
from modules.robots import check_robots_and_sitemap
from modules.sensitive_files import check_sensitive_files
from modules.http_redirect import check_http_redirect
from modules.cookies import check_cookies
from modules.cors import check_cors
from modules.http_methods import check_http_methods
from modules.source_code import check_source_code
from modules.js_scanner import scan_js_files
from modules.email_spoofing import check_email_spoofing
from modules.server_info import check_server_info
from modules.shodan_check import check_shodan
from modules.subdomain_takeover import check_subdomain_takeover
from modules.cves import check_cves
from modules.open_redirect import check_open_redirect
from modules.csrf import check_csrf
from modules.subdomain_headers import check_subdomain_headers
from modules.exposed_paths import check_exposed_paths
from modules.api_endpoints import check_api_endpoints
from modules.js_diff import check_js_diff
from core.risk_score import calculate_risk_score
from reporting.html_report import generate_html
from reporting.markdown_report import generate_markdown
from reporting.json_report import save_report
from datetime import datetime

def main():
    if len(sys.argv) < 2:
        print("Uso: python main.py <dominio>")
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
    js_findings, js_urls = scan_js_files(domain)
    js_diff = check_js_diff(domain, js_urls)
    shodan_info = check_shodan(ip)
    email_spoofing = check_email_spoofing(domain)
    server_info = check_server_info(domain)
    takeover = check_subdomain_takeover(subdomains)
    cves = check_cves(technologies)
    open_redirects = check_open_redirect(domain)
    csrf = check_csrf(domain)
    subdomain_headers = check_subdomain_headers(subdomains)
    exposed_paths = check_exposed_paths(domain)
    api_endpoints = check_api_endpoints(domain)
    risk_score = calculate_risk_score({
        "cabeceras_seguridad": security, "ssl": ssl_info, "waf": waf,
        "http_redirect": http_redirect, "archivos_sensibles": sensitive_files,
        "cors": cors, "http_methods": http_methods, "dns": dns_info,
        "codigo_fuente": source_code, "js_files": js_findings,
        "shodan": shodan_info, "email_spoofing": email_spoofing,
        "server_info": server_info, "subdomain_takeover": takeover,
        "exposed_paths": exposed_paths, "api_endpoints": api_endpoints
    })

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
        "codigo_fuente": source_code,
        "js_files": js_findings,
        "js_diff": js_diff,
        "shodan": shodan_info,
        "email_spoofing": email_spoofing,
        "server_info": server_info,
        "subdomain_takeover": takeover,
        "cves": cves,
        "open_redirects": open_redirects,
        "csrf": csrf,
        "subdomain_headers": subdomain_headers,
        "exposed_paths": exposed_paths,
        "api_endpoints": api_endpoints,
        "risk_score": risk_score
    }

    save_report(report, domain)
    generate_markdown(report)
    generate_html(report)

if __name__ == "__main__":
    main()
