import requests


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