import requests
import re


def check_csrf(domain):
    print(f"\nBuscando formularios sin proteccion CSRF en {domain}:")
    findings = []
    
    try:
        r = requests.get(f"https://{domain}/login", timeout=5, allow_redirects=True)
        html = r.text
        
        import re
        forms = re.findall(r'<form[^>]*>(.*?)</form>', html, re.DOTALL | re.IGNORECASE)
        
        for i, form in enumerate(forms):
            has_csrf = any(token in html.lower() for token in [
                'csrf', '_token', 'authenticity_token', 'nonce', 'csrf-token', 'csrf-param', 
                '__requestverificationtoken', 'x-csrf'
            ])
            
            has_input = '<input' in form.lower()
            
            if has_input and not has_csrf:
                print(f"  ALERTA  Formulario {i+1} sin token CSRF detectado")
                findings.append({"formulario": i+1, "csrf": False})
            elif has_input:
                print(f"  OK  Formulario {i+1} tiene proteccion CSRF")
        
        if not forms:
            print(f"  No se encontraron formularios en la pagina principal")
        elif not findings:
            print(f"  OK: Todos los formularios tienen proteccion CSRF")
            
    except Exception as e:
        print(f"  Error: {e}")
    
    return findings