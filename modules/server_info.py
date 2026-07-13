import requests


def check_server_info(domain):
    print(f"\nAnalizando informacion del servidor de {domain}:")
    findings = []
    try:
        r = requests.get(f"https://{domain}/login", timeout=5, allow_redirects=True)
        headers = dict(r.headers)
        info_headers = {
            "Server": "Version del servidor web",
            "X-Powered-By": "Tecnologia del backend",
            "X-AspNet-Version": "Version de ASP.NET",
            "X-Generator": "Generador del sitio",
            "Via": "Proxy/CDN info",
            "X-Backend-Server": "Servidor backend expuesto",
            "X-Runtime": "Runtime del servidor",
            "X-Version": "Version expuesta"
        }
        for header, description in info_headers.items():
            value = headers.get(header, "")
            if value:
                print(f"  ENCONTRADO  {header}: {value}")
                findings.append({"header": header, "valor": value})
        server = headers.get("Server", "")
        if server and any(char.isdigit() for char in server):
            print(f"  ALERTA: Server header revela version: {server}")
        if not findings:
            print(f"  OK: No se encontro informacion sensible del servidor")
    except Exception as e:
        print(f"  Error: {e}")
    return findings