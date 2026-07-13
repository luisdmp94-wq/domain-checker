from datetime import datetime


def generate_html(report):
    domain = report["dominio"]
    fecha = report["fecha"]
    ip = report["ip"]
    score = report.get("risk_score", {}).get("score", "N/A")
    nivel = report.get("risk_score", {}).get("nivel", "N/A")
    ssl = report["ssl"]
    security = report["cabeceras_seguridad"]
    subdomains = report["subdominios"]
    ports = report["puertos"]
    dns = report["dns"]
    waf = report["waf"]
    cors = report["cors"]
    sensitive = report["archivos_sensibles"]
    takeover = report.get("subdomain_takeover", [])
    email = report.get("email_spoofing", {})

    ok_headers = [h for h, v in security.items() if v["presente"]]
    missing_headers = [h for h, v in security.items() if not v["presente"]]
    
    color = "#27ae60" if nivel == "BAJO" else "#f39c12" if nivel == "MEDIO" else "#e74c3c"

    html = f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<title>Informe de Seguridad - {domain}</title>
<style>
  body {{ font-family: Arial, sans-serif; background: #f5f6fa; margin: 0; padding: 20px; color: #333; }}
  .container {{ max-width: 900px; margin: auto; background: white; border-radius: 10px; padding: 30px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
  h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }}
  h2 {{ color: #2c3e50; margin-top: 30px; }}
  .score {{ font-size: 48px; font-weight: bold; color: {color}; }}
  .nivel {{ font-size: 24px; color: {color}; }}
  .badge {{ display: inline-block; padding: 4px 10px; border-radius: 20px; font-size: 12px; font-weight: bold; }}
  .ok {{ background: #d5f5e3; color: #27ae60; }}
  .fail {{ background: #fadbd8; color: #e74c3c; }}
  .warn {{ background: #fef9e7; color: #f39c12; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
  th {{ background: #3498db; color: white; padding: 10px; text-align: left; }}
  td {{ padding: 8px 10px; border-bottom: 1px solid #eee; }}
  tr:hover {{ background: #f8f9fa; }}
  .meta {{ color: #7f8c8d; font-size: 14px; margin-bottom: 20px; }}
  .section {{ margin-bottom: 30px; }}
</style>
</head>
<body>
<div class="container">
  <h1>Informe de Seguridad</h1>
  <div class="meta">Dominio: <strong>{domain}</strong> | IP: {ip} | Fecha: {fecha}</div>
  
  <div class="section">
    <div class="score">{score}/100</div>
    <div class="nivel">Riesgo {nivel}</div>
  </div>

  <div class="section">
    <h2>SSL / HTTPS</h2>
    <table>
      <tr><th>Campo</th><th>Valor</th></tr>
      <tr><td>Emisor</td><td>{ssl.get("emisor", "N/A")}</td></tr>
      <tr><td>Expira</td><td>{ssl.get("expira", "N/A")}</td></tr>
      <tr><td>Dias restantes</td><td>{ssl.get("dias_restantes", "N/A")}</td></tr>
      <tr><td>Estado</td><td><span class="badge {'ok' if ssl.get('valido') else 'fail'}">{'Valido' if ssl.get('valido') else 'EXPIRADO'}</span></td></tr>
    </table>
  </div>

  <div class="section">
    <h2>Cabeceras de Seguridad</h2>
    <table>
      <tr><th>Cabecera</th><th>Estado</th></tr>
      {''.join(f'<tr><td>{h}</td><td><span class="badge ok">OK</span></td></tr>' for h in ok_headers)}
      {''.join(f'<tr><td>{h}</td><td><span class="badge fail">FALTA</span></td></tr>' for h in missing_headers)}
    </table>
  </div>

  <div class="section">
    <h2>DNS</h2>
    <table>
      <tr><th>Registro</th><th>Estado</th></tr>
      <tr><td>SPF</td><td><span class="badge {'ok' if dns.get('spf_presente') else 'fail'}">{'OK' if dns.get('spf_presente') else 'FALTA'}</span></td></tr>
      <tr><td>DMARC</td><td><span class="badge {'ok' if dns.get('dmarc_presente') else 'fail'}">{'OK' if dns.get('dmarc_presente') else 'FALTA'}</span></td></tr>
      <tr><td>MX</td><td>{', '.join(dns.get('MX', [])) or 'No encontrado'}</td></tr>
    </table>
  </div>

  <div class="section">
    <h2>Subdominios ({len(subdomains)} encontrados)</h2>
    <table>
      <tr><th>Subdominio</th><th>IP</th></tr>
      {''.join(f'<tr><td>{s["subdominio"]}</td><td>{s["ip"]}</td></tr>' for s in subdomains)}
    </table>
  </div>

  <div class="section">
    <h2>Puertos Abiertos</h2>
    <table>
      <tr><th>Puerto</th><th>Protocolo</th><th>Servicio</th></tr>
      {''.join(f'<tr><td>{p["puerto"]}</td><td>{p["protocolo"]}</td><td>{p["servicio"]}</td></tr>' for p in ports) if ports else '<tr><td colspan="3">Ninguno encontrado</td></tr>'}
    </table>
  </div>

  {'<div class="section"><h2>Archivos Sensibles</h2><table><tr><th>Archivo</th><th>Bytes</th></tr>' + ''.join(f'<tr><td>{f["archivo"]}</td><td>{f["bytes"]}</td></tr>' for f in sensitive) + '</table></div>' if sensitive else ''}
  
    <div class="section">
    <h2>WAF</h2>
    <p>{waf.get('nombre') if waf.get('detectado') else 'No detectado'}</p>
  </div>
  <div class="section">
    <h2>Email Spoofing</h2>
    <table>
      <tr><th>Registro</th><th>Estado</th></tr>
      <tr><td>SPF</td><td>{email.get('spf', 'N/A')}</td></tr>
      <tr><td>DMARC</td><td>{email.get('dmarc', 'N/A')}</td></tr>
      <tr><td>DKIM</td><td>{email.get('dkim', 'N/A')}</td></tr>
      <tr><td>Vulnerable</td><td>{'SI' if email.get('vulnerable') else 'NO'}</td></tr>
    </table>
  </div>
  <div class="section">
    <h2>CORS</h2>
    <p>{('PROBLEMAS DETECTADOS: ' + str(len(cors))) if cors else 'OK: Sin problemas CORS'}</p>
  </div>
  <div class="section">
    <h2>CVEs Detectados</h2>
    <p>{(str(len(report.get('cves', []))) + ' CVEs encontrados') if report.get('cves') else 'No se encontraron CVEs'}</p>
  </div>
  <div class="section">
    <h2>Open Redirects</h2>
    <p>{('VULNERABLE: ' + str(len(report.get('open_redirects', [])))) if report.get('open_redirects') else 'OK: No se detectaron open redirects'}</p>
  </div>
  <div class="section">
    <h2>CSRF</h2>
    <p>{('ALERTA: ' + str(len(report.get('csrf', []))) + ' formularios sin proteccion') if report.get('csrf') else 'OK: Todos los formularios protegidos'}</p>
  </div>
  {'<div class="section"><h2>Subdomain Takeover</h2><table><tr><th>Subdominio</th><th>Servicio</th></tr>' + ''.join(f'<tr><td>{t["subdominio"]}</td><td>{t["servicio"]}</td></tr>' for t in report.get("subdomain_takeover", [])) + '</table></div>' if report.get("subdomain_takeover") else ''}
  <div class="section">
    <h2>Cabeceras en Subdominios</h2>
    <table>
      <tr><th>Subdominio</th><th>Cabeceras Faltantes</th></tr>
      {''.join(f'<tr><td>{s["subdominio"]}</td><td>{", ".join(s["cabeceras_faltantes"])}</td></tr>' for s in report.get("subdomain_headers", []))}
    </table>
  </div>
  {'<div class="section"><h2>Paths Sensibles Expuestos</h2><table><tr><th>Path</th><th>Severidad</th><th>Descripcion</th></tr>' + ''.join(f'<tr><td>{p["path"]}</td><td style="color:red">{p["severidad"]}</td><td>{p["descripcion"]}</td></tr>' for p in report.get("exposed_paths", [])) + '</table></div>' if report.get("exposed_paths") else '<div class="section"><h2>Paths Sensibles Expuestos</h2><p style="color:green">OK: No se encontraron paths sensibles</p></div>'}
  {'<div class="section"><h2>API Endpoints Expuestos</h2><table><tr><th>Path</th><th>Severidad</th><th>Descripcion</th></tr>' + ''.join(f'<tr><td>{e["path"]}</td><td style="color:red">{e["severidad"]}</td><td>{e["descripcion"]}</td></tr>' for e in report.get("api_endpoints", [])) + '</table></div>' if report.get("api_endpoints") else '<div class="section"><h2>API Endpoints Expuestos</h2><p style="color:green">OK: No se encontraron endpoints expuestos</p></div>'}
  {'<div class="section"><h2>JavaScript Findings</h2><table><tr><th>Tipo</th><th>Archivo</th><th>Valor</th></tr>' + ''.join(f'<tr><td>{j["tipo"]}</td><td>{j["archivo"][:40]}</td><td>{j["valor"][:60]}</td></tr>' for j in report.get("js_files", [])) + '</table></div>' if report.get("js_files") else '<div class="section"><h2>JavaScript Findings</h2><p style="color:green">OK: No se encontraron secretos en JS</p></div>'}
  {'<div class="section"><h2>Cookies</h2><table><tr><th>Nombre</th><th>Problemas</th></tr>' + ''.join(f'<tr><td>{c["nombre"]}</td><td>{", ".join(c.get("problemas", ["OK"]))}</td></tr>' for c in report.get("cookies", [])) + '</table></div>' if report.get("cookies") else ''}
  {'<div class="section"><h2>Server Info</h2><table><tr><th>Header</th><th>Valor</th></tr>' + ''.join(f'<tr><td>{s["header"]}</td><td>{s["valor"]}</td></tr>' for s in report.get("server_info", [])) + '</table></div>' if report.get("server_info") else ''}
  <div class="section" style="text-align:center; color:#7f8c8d; font-size:12px; margin-top:40px;">
    Informe generado automaticamente por domain-checker | vaalsec
  </div>
</div>
</body>
</html>"""
    filename = f"report_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"\nInforme HTML guardado en: {filename}")
    return filename