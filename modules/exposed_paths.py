import requests


def check_exposed_paths(domain):
    print(f"\nBuscando paths sensibles expuestos en {domain}:")
    PATHS = [
        {"path": "/metrics", "categoria": "monitoring", "severidad": "HIGH", "descripcion": "Prometheus metrics endpoint expuesto", "firmas": ["# HELP", "# TYPE", "http_requests_total", "process_cpu"]},
        {"path": "/actuator", "categoria": "monitoring", "severidad": "HIGH", "descripcion": "Spring Boot Actuator expuesto", "firmas": ["_links", "actuator", "health", "env"]},
        {"path": "/actuator/env", "categoria": "monitoring", "severidad": "CRITICAL", "descripcion": "Spring Boot Actuator env - variables de entorno", "firmas": ["activeProfiles", "propertySources", "systemEnvironment"]},
        {"path": "/actuator/health", "categoria": "monitoring", "severidad": "MEDIUM", "descripcion": "Spring Boot health endpoint", "firmas": ["status", "UP", "DOWN", "components"]},
        {"path": "/debug/pprof/", "categoria": "monitoring", "severidad": "HIGH", "descripcion": "Go pprof profiling endpoint expuesto", "firmas": ["goroutine", "heap", "profile", "cmdline"]},
        {"path": "/health", "categoria": "monitoring", "severidad": "LOW", "descripcion": "Health check endpoint", "firmas": ["status", "healthy", "ok", "UP"]},
        {"path": "/status", "categoria": "monitoring", "severidad": "LOW", "descripcion": "Status endpoint", "firmas": ["status", "version", "uptime", "ok"]},
        {"path": "/.git/HEAD", "categoria": "vcs", "severidad": "CRITICAL", "descripcion": "Repositorio Git expuesto", "firmas": ["ref:", "refs/heads/"]},
        {"path": "/.git/config", "categoria": "vcs", "severidad": "CRITICAL", "descripcion": "Git config expuesto", "firmas": ["[core]", "[remote", "repositoryformatversion"]},
        {"path": "/.svn/entries", "categoria": "vcs", "severidad": "CRITICAL", "descripcion": "Repositorio SVN expuesto", "firmas": ["dir", "svn:", "http"]},
        {"path": "/.env", "categoria": "secrets", "severidad": "CRITICAL", "descripcion": "Archivo .env con variables de entorno", "firmas": ["DB_", "SECRET", "PASSWORD", "API_KEY", "TOKEN", "APP_"]},
        {"path": "/.env.local", "categoria": "secrets", "severidad": "CRITICAL", "descripcion": "Archivo .env.local", "firmas": ["DB_", "SECRET", "PASSWORD", "API_KEY", "TOKEN"]},
        {"path": "/.env.production", "categoria": "secrets", "severidad": "CRITICAL", "descripcion": "Archivo .env.production", "firmas": ["DB_", "SECRET", "PASSWORD", "API_KEY", "TOKEN"]},
        {"path": "/config.json", "categoria": "secrets", "severidad": "HIGH", "descripcion": "Archivo de configuracion expuesto", "firmas": ["password", "secret", "api_key", "token", "database", "host"]},
        {"path": "/appsettings.json", "categoria": "secrets", "severidad": "HIGH", "descripcion": "ASP.NET appsettings expuesto", "firmas": ["ConnectionStrings", "Password", "Secret", "Logging"]},
        {"path": "/wp-config.php.bak", "categoria": "secrets", "severidad": "CRITICAL", "descripcion": "Backup wp-config con credenciales DB", "firmas": ["DB_NAME", "DB_PASSWORD", "DB_HOST", "table_prefix"]},
        {"path": "/swagger.json", "categoria": "api_docs", "severidad": "MEDIUM", "descripcion": "Swagger spec expuesto", "firmas": ["swagger", "openapi", "paths", "info"]},
        {"path": "/swagger/v1/swagger.json", "categoria": "api_docs", "severidad": "MEDIUM", "descripcion": "Swagger v1 spec expuesto", "firmas": ["swagger", "openapi", "paths", "info"]},
        {"path": "/openapi.json", "categoria": "api_docs", "severidad": "MEDIUM", "descripcion": "OpenAPI spec expuesto", "firmas": ["openapi", "paths", "info", "components"]},
        {"path": "/api-docs", "categoria": "api_docs", "severidad": "MEDIUM", "descripcion": "API docs endpoint", "firmas": ["swagger", "openapi", "paths", "api"]},
        {"path": "/api/v1", "categoria": "api_docs", "severidad": "LOW", "descripcion": "API v1 root expuesto", "firmas": ["version", "endpoints", "api", "routes"]},
        {"path": "/graphql", "categoria": "graphql", "severidad": "HIGH", "descripcion": "GraphQL endpoint - verificar introspection", "firmas": ["__schema", "__types", "data", "errors"]},
        {"path": "/admin", "categoria": "admin", "severidad": "MEDIUM", "descripcion": "Panel de administracion accesible", "firmas": ["admin", "login", "dashboard", "panel", "username", "password"]},
        {"path": "/phpmyadmin", "categoria": "admin", "severidad": "HIGH", "descripcion": "phpMyAdmin expuesto", "firmas": ["phpMyAdmin", "MySQL", "pma_", "Welcome to"]},
        {"path": "/temporal", "categoria": "dashboard", "severidad": "HIGH", "descripcion": "Temporal workflow UI expuesto", "firmas": ["Temporal", "workflow", "namespace", "taskQueue"]},
        {"path": "/grafana", "categoria": "dashboard", "severidad": "HIGH", "descripcion": "Grafana dashboard expuesto", "firmas": ["Grafana", "dashboard", "panel", "datasource"]},
        {"path": "/kibana", "categoria": "dashboard", "severidad": "HIGH", "descripcion": "Kibana expuesto", "firmas": ["kibana", "elasticsearch", "index pattern", "Discover"]},
    ]
    found = []
    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (security-research)"})
    for entry in PATHS:
        url = f"https://{domain}{entry['path']}"
        try:
            response = session.get(url, timeout=5, allow_redirects=False)
            if response.status_code != 200:
                continue
            body = response.text
            firmas_encontradas = [f for f in entry["firmas"] if f.lower() in body.lower()]
            if not firmas_encontradas:
                print(f"  SKIP  {entry['path']} (200 sin firma valida)")
                continue
            resultado = {
                "path": entry["path"],
                "url_completa": url,
                "categoria": entry["categoria"],
                "severidad": entry["severidad"],
                "descripcion": entry["descripcion"],
                "firmas_encontradas": firmas_encontradas,
                "content_length": len(body),
                "content_type": response.headers.get("Content-Type", ""),
                "evidencia": body[:300].strip()
            }
            found.append(resultado)
            print(f"  EXPUESTO [{entry['severidad']}]  {entry['path']} - {entry['descripcion']}")
            print(f"    Firmas: {', '.join(firmas_encontradas)}")
        except requests.RequestException:
            pass
    if not found:
        print("  No se encontraron paths sensibles expuestos")
    return found