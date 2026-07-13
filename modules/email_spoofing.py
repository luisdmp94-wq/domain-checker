import dns.resolver
import dns.exception


def _txt_value(record):
    if hasattr(record, "strings"):
        return b"".join(record.strings).decode("utf-8", errors="ignore")
    return str(record).replace('" "', "").strip('"')


def check_email_spoofing(domain):
    print(f"\nAnalizando vulnerabilidad email spoofing de {domain}:")

    results = {
        "spf": None,
        "dmarc": None,
        "dkim": None,
        "vulnerable": False,
        "issues": [],
    }

    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ['1.1.1.1', '8.8.8.8']
    resolver.timeout = 5
    resolver.lifetime = 10

    # SPF
    try:
        txt_records = resolver.resolve(domain, "TXT")
        spf_record = next(
            (
                _txt_value(record)
                for record in txt_records
                if _txt_value(record).lower().startswith("v=spf1")
            ),
            None,
        )

        if not spf_record:
            results["spf"] = "FALTA"
            print("  SPF: FALTA")
        elif "-all" in spf_record.lower():
            results["spf"] = "ESTRICTO"
            print("  SPF: OK (estricto -all)")
        elif "~all" in spf_record.lower():
            results["spf"] = "FLEXIBLE"
            print("  SPF: MEDIO (~all softfail)")
        else:
            results["spf"] = "DEBIL"
            print("  SPF: Sin politica de rechazo")

    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        results["spf"] = "FALTA"
        print("  SPF: FALTA")
    except (dns.exception.Timeout, dns.resolver.NoNameservers) as exc:
        results["spf"] = "ERROR"
        print(f"  SPF: Error DNS - {exc}")

    # DMARC
    try:
        dmarc_records = resolver.resolve(f"_dmarc.{domain}", "TXT")
        dmarc_record = next(
            (
                _txt_value(record)
                for record in dmarc_records
                if _txt_value(record).lower().startswith("v=dmarc1")
            ),
            None,
        )

        if not dmarc_record:
            results["dmarc"] = "FALTA"
            print("  DMARC: FALTA")
        elif "p=reject" in dmarc_record.lower():
            results["dmarc"] = "ESTRICTO"
            print("  DMARC: OK (p=reject)")
        elif "p=quarantine" in dmarc_record.lower():
            results["dmarc"] = "MEDIO"
            print("  DMARC: MEDIO (p=quarantine)")
        elif "p=none" in dmarc_record.lower():
            results["dmarc"] = "DEBIL"
            print("  DMARC: DEBIL (p=none)")
        else:
            results["dmarc"] = "SIN_POLITICA"
            print("  DMARC: Sin politica")

    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        results["dmarc"] = "FALTA"
        print("  DMARC: FALTA")
    except (dns.exception.Timeout, dns.resolver.NoNameservers) as exc:
        results["dmarc"] = "ERROR"
        print(f"  DMARC: Error DNS - {exc}")

    # DKIM
    selectors = ["default", "google", "mail", "dkim", "k1", "selector1", "selector2"]
    results["dkim"] = "No detectado"

    for selector in selectors:
        try:
            resolver.resolve(f"{selector}._domainkey.{domain}", "TXT")
            results["dkim"] = f"OK (selector: {selector})"
            print(f"  DKIM: OK (selector '{selector}')")
            break
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            continue
        except (dns.exception.Timeout, dns.resolver.NoNameservers):
            continue

    if results["dkim"] == "No detectado":
        print("  DKIM: No detectado")

    # No marcar automáticamente como vulnerable solo por faltar políticas.
    results["vulnerable"] = False
    print("  RESULTADO: Revision informativa completada")

    return results

