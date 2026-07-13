import requests


def check_cves(technologies):
    print(f"\nBuscando CVEs para tecnologias detectadas:")
    findings = []
    
    if not technologies:
        print(f"  No hay tecnologias detectadas para buscar CVEs")
        return findings
    
    for category, techs in technologies.items():
        for tech in techs:
            try:
                r = requests.get(f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={tech}&resultsPerPage=3", timeout=10)
                if r.status_code == 200:
                    data = r.json()
                    cves = data.get("vulnerabilities", [])[:3]
                    if cves:
                        for cve in cves:
                            cve_data = cve.get("cve", {}); cvss = cve_data.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseScore", "N/A")
                            cve_id = cve_data.get("id", "N/A")
                            summary = cve_data.get("descriptions", [{}])[0].get("value", "")[:100]
                            print(f"  CVE {cve_id} - CVSS {cvss} - {tech}: {summary}...")
                            findings.append({
                                "tecnologia": tech,
                                "cve_id": cve_id,
                                "cvss": cvss,
                                "resumen": summary
                            })
            except:
                pass
    
    if not findings:
        print(f"  No se encontraron CVEs para las tecnologias detectadas")
    
    return findings