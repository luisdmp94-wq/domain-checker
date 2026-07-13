from datetime import datetime


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