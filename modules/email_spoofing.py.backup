import dns.resolver


def check_email_spoofing(domain):
    print(f"\nAnalizando vulnerabilidad email spoofing de {domain}:")
    results = {"spf": None, "dmarc": None, "dkim": None, "vulnerable": False, "issues": []}
    try:
        txt_records = dns.resolver.resolve(domain, "TXT")
        spf_record = None
        for r in txt_records:
            txt = str(r)
            if "v=spf1" in txt:
                spf_record = txt
                break
        if not spf_record:
            results["spf"] = "FALTA"
            results["issues"].append("Sin SPF - vulnerable a spoofing")
            results["vulnerable"] = True
            print(f"  SPF: FALTA - vulnerable")
        elif "-all" in spf_record:
            results["spf"] = "ESTRICTO"
            print(f"  SPF: OK (estricto -all)")
        elif "~all" in spf_record:
            results["spf"] = "FLEXIBLE"
            print(f"  SPF: DEBIL (~all softfail)")
        else:
            results["spf"] = "DEBIL"
            results["vulnerable"] = True
            print(f"  SPF: Sin politica de rechazo")
    except:
        results["spf"] = "ERROR"
        results["vulnerable"] = True
        print(f"  SPF: No encontrado")
    try:
        dmarc_records = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        dmarc_record = str(list(dmarc_records)[0])
        if "p=reject" in dmarc_record:
            results["dmarc"] = "ESTRICTO"
            print(f"  DMARC: OK (p=reject)")
        elif "p=quarantine" in dmarc_record:
            results["dmarc"] = "MEDIO"
            print(f"  DMARC: MEDIO (p=quarantine)")
        elif "p=none" in dmarc_record:
            results["dmarc"] = "DEBIL"
            results["vulnerable"] = True
            results["issues"].append("DMARC usa p=none")
            print(f"  DMARC: DEBIL (p=none)")
        else:
            results["dmarc"] = "SIN_POLITICA"
            results["vulnerable"] = True
            print(f"  DMARC: Sin politica")
    except:
        results["dmarc"] = "FALTA"
        results["vulnerable"] = True
        print(f"  DMARC: FALTA")
    dkim_selectors = ["default", "google", "mail", "dkim", "k1", "selector1", "selector2"]
    dkim_found = False
    for selector in dkim_selectors:
        try:
            dns.resolver.resolve(f"{selector}._domainkey.{domain}", "TXT")
            dkim_found = True
            results["dkim"] = f"OK (selector: {selector})"
            print(f"  DKIM: OK (selector '{selector}')")
            break
        except:
            pass
    if not dkim_found:
        results["dkim"] = "No detectado"
        print(f"  DKIM: No detectado")
    if results["vulnerable"]:
        print(f"  RESULTADO: VULNERABLE a email spoofing")
    else:
        print(f"  RESULTADO: Bien protegido")
    return results