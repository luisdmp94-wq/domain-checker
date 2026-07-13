import dns.resolver


def check_dns_records(domain):
    print(f"\nAnalizando registros DNS de {domain}:")
    records = {}
    spf_found = False
    dmarc_found = False
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        records['MX'] = [str(r.exchange) for r in mx_records]
        print(f"  MX: {', '.join(records['MX'])}")
    except:
        records['MX'] = []
        print(f"  MX: No encontrado")
    try:
        ns_records = dns.resolver.resolve(domain, 'NS')
        records['NS'] = [str(r) for r in ns_records]
        print(f"  NS: {', '.join(records['NS'])}")
    except:
        records['NS'] = []
        print(f"  NS: No encontrado")
    try:
        txt_records = dns.resolver.resolve(domain, 'TXT')
        records['TXT'] = [str(r) for r in txt_records]
        for txt in records['TXT']:
            if 'v=spf1' in txt:
                spf_found = True
                print(f"  SPF: OK - {txt[:60]}...")
            if 'v=DMARC1' in txt:
                dmarc_found = True
                print(f"  DMARC: OK")
        if not spf_found:
            print(f"  SPF: FALTA - riesgo de email spoofing")
        if not dmarc_found:
            print(f"  DMARC: verificando subdominio...")
    except:
        records['TXT'] = []
    try:
        dmarc_records = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
        dmarc_found = True
        records['DMARC'] = [str(r) for r in dmarc_records]
        print(f"  DMARC: OK")
    except:
        if not dmarc_found:
            records['DMARC'] = []
            print(f"  DMARC: FALTA - riesgo de email spoofing")
    records['spf_presente'] = spf_found
    records['dmarc_presente'] = dmarc_found
    return records