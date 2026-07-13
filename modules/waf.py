import subprocess

WAFW00F_PATH = r'C:\Users\Luisd\AppData\Local\Python\pythoncore-3.14-64\Scripts\wafw00f.exe'

import subprocess


def detect_waf(domain):
    print(f"\nDetectando WAF de {domain}:")
    try:
        result = subprocess.run(
            [WAFW00F_PATH, f"https://{domain}"],
            capture_output=True, text=True, timeout=30
        )
        output = result.stdout
        if "is behind" in output:
            lines = [l for l in output.split('\n') if "is behind" in l]
            waf_name = lines[0].strip() if lines else "WAF detectado"
            print(f"  WAF detectado: {waf_name}")
            return {"detectado": True, "nombre": waf_name}
        elif "No WAF" in output or "not behind" in output:
            print(f"  No se detecto WAF")
            return {"detectado": False, "nombre": None}
        else:
            print(f"  No se pudo determinar")
            return {"detectado": None, "nombre": None}
    except Exception as e:
        print(f"  Error: {e}")
        return {"error": str(e)}
