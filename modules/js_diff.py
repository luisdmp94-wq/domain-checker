import requests
import hashlib
import sqlite3
import re
import os
from datetime import datetime

DB_PATH = "js_diff.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS js_snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT,
            url TEXT,
            hash TEXT,
            endpoints TEXT,
            first_seen TEXT,
            last_seen TEXT,
            last_changed TEXT
        )
    """)
    conn.commit()
    conn.close()

def get_js_hash(url):
    try:
        r = requests.get(url, timeout=10)
        return hashlib.sha256(r.content).hexdigest(), r.text
    except:
        return None, None

def extract_endpoints_from_js(content):
    pattern = r'["\'][/](?:api|graphql|rest|v[0-9]+)[/][a-zA-Z0-9/_\-]{4,}["\']'
    matches = re.findall(pattern, content, re.IGNORECASE)
    cleaned = []
    for m in matches:
        m = m.strip('"\'')
        if not re.search(r'[(){}\[\]<>+*=;,]', m) and len(m) > 5:
            cleaned.append(m)
    return list(set(cleaned))[:20]

def check_js_diff(domain, js_urls):
    init_db()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    results = []

    print(f"\nJS Diffing para {domain} ({len(js_urls)} archivos):")

    for url in js_urls:
        current_hash, content = get_js_hash(url)
        if not current_hash:
            continue

        filename = url.split('/')[-1][:60]
        c.execute("SELECT hash, endpoints, first_seen FROM js_snapshots WHERE domain=? AND url=?", (domain, url))
        row = c.fetchone()

        if not row:
            # Primera vez que vemos este archivo
            endpoints = extract_endpoints_from_js(content) if content else []
            c.execute("""
                INSERT INTO js_snapshots (domain, url, hash, endpoints, first_seen, last_seen, last_changed)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (domain, url, current_hash, str(endpoints), now, now, now))
            conn.commit()
            print(f"  NUEVO  {filename}")
            results.append({
                "url": url,
                "status": "nuevo",
                "endpoints_encontrados": endpoints
            })
        elif row[0] != current_hash:
            # El hash cambio - archivo modificado
            old_endpoints = eval(row[1]) if row[1] else []
            new_endpoints = extract_endpoints_from_js(content) if content else []
            endpoints_nuevos = [e for e in new_endpoints if e not in old_endpoints]
            endpoints_eliminados = [e for e in old_endpoints if e not in new_endpoints]

            c.execute("""
                UPDATE js_snapshots SET hash=?, endpoints=?, last_seen=?, last_changed=?
                WHERE domain=? AND url=?
            """, (current_hash, str(new_endpoints), now, now, domain, url))
            conn.commit()

            print(f"  CAMBIO  {filename}")
            if endpoints_nuevos:
                print(f"    + Endpoints nuevos: {endpoints_nuevos}")
            if endpoints_eliminados:
                print(f"    - Endpoints eliminados: {endpoints_eliminados}")

            results.append({
                "url": url,
                "status": "modificado",
                "endpoints_nuevos": endpoints_nuevos,
                "endpoints_eliminados": endpoints_eliminados,
                "primera_vez_visto": row[2],
                "ultimo_cambio": now
            })
        else:
            # Sin cambios
            c.execute("UPDATE js_snapshots SET last_seen=? WHERE domain=? AND url=?", (now, domain, url))
            conn.commit()
            print(f"  OK  {filename} (sin cambios)")
            results.append({
                "url": url,
                "status": "sin_cambios"
            })

    conn.close()

    if not results:
        print("  No se encontraron archivos JS para comparar")

    return results
